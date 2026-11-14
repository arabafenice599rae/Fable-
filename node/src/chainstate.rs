//! Block tree, storage and fork choice.
//!
//! Every header that passes the parent-relative checks (time, ASERT bits, proof of work) gets an
//! entry in the index, even before its block arrives. Blocks are kept in an append-only file.
//! The active chain is the one with the most cumulative work among the blocks we can connect;
//! on a tie the one seen first stays. Switching chains disconnects blocks with their undo data and
//! connects the new ones with the full rules of `consensus::Chain`.

use std::collections::{BTreeMap, HashMap};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::Arc;

use num_bigint::BigUint;

use crate::consensus::*;

/// Far enough in the future that the clock rule never fires: used when a header's time was
/// already checked on arrival, and when replaying our own block file.
pub const NO_CLOCK: i64 = i64::MAX / 4;

#[derive(Clone, Debug)]
pub struct Entry {
    pub header: Header,
    pub hash: Hash,
    pub height: u32,
    /// Full 64-bit time.
    pub time: i64,
    /// Cumulative work up to and including this block.
    pub work: BigUint,
    /// Order of first sight, for ties.
    pub seq: u64,
    pub pos: Option<u64>,
    pub invalid: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Accepted {
    /// New block stored (it may or may not have become the tip).
    Stored,
    Duplicate,
    /// The parent is unknown: nothing is stored, the caller asks for headers.
    Orphan,
}

/// What a call changed in the active chain, oldest first, for the mempool and the miners.
#[derive(Default, Debug)]
pub struct Changes {
    pub disconnected: Vec<Block>,
    pub connected: Vec<Block>,
}

impl Changes {
    pub fn is_empty(&self) -> bool {
        self.connected.is_empty() && self.disconnected.is_empty()
    }

    fn extend(&mut self, o: Changes) {
        self.disconnected.extend(o.disconnected);
        self.connected.extend(o.connected);
    }
}

/// Append-only block storage: `length (4) ‖ block` records, in a file or in memory.
pub struct BlockStore {
    file: Option<File>,
    mem: Vec<u8>,
}

impl BlockStore {
    pub fn memory() -> Self {
        BlockStore { file: None, mem: Vec::new() }
    }

    pub fn open(path: &Path) -> std::io::Result<(Self, Vec<Vec<u8>>)> {
        let mut f = OpenOptions::new().read(true).append(true).create(true).open(path)?;
        let mut all = Vec::new();
        f.read_to_end(&mut all)?;
        let (mut blocks, mut o) = (Vec::new(), 0usize);
        while o + 4 <= all.len() {
            let n = u32::from_le_bytes(all[o..o + 4].try_into().unwrap()) as usize;
            if o + 4 + n > all.len() {
                break; // a torn write at the end: drop it
            }
            blocks.push(all[o + 4..o + 4 + n].to_vec());
            o += 4 + n;
        }
        if o != all.len() {
            f.set_len(o as u64)?;
        }
        Ok((BlockStore { file: Some(f), mem: Vec::new() }, blocks))
    }

    fn append(&mut self, raw: &[u8]) -> u64 {
        let mut rec = (raw.len() as u32).to_le_bytes().to_vec();
        rec.extend_from_slice(raw);
        match &mut self.file {
            Some(f) => {
                let pos = f.seek(SeekFrom::End(0)).expect("block file");
                f.write_all(&rec).expect("block file");
                pos
            }
            None => {
                let pos = self.mem.len() as u64;
                self.mem.extend(rec);
                pos
            }
        }
    }

    fn read(&mut self, pos: u64) -> Vec<u8> {
        match &mut self.file {
            Some(f) => {
                let mut len = [0u8; 4];
                f.seek(SeekFrom::Start(pos)).expect("block file");
                f.read_exact(&mut len).expect("block file");
                let mut raw = vec![0u8; u32::from_le_bytes(len) as usize];
                f.read_exact(&mut raw).expect("block file");
                raw
            }
            None => {
                let p = pos as usize;
                let n = u32::from_le_bytes(self.mem[p..p + 4].try_into().unwrap()) as usize;
                self.mem[p + 4..p + 4 + n].to_vec()
            }
        }
    }
}

/// The UTXO set a snapshot block commits to (the set after the block before it), sorted.
pub struct Snapshot {
    pub height: u32,
    pub root: Hash,
    pub entries: Vec<(OutPoint, UtxoEntry)>,
    pub leaves: Vec<Hash>,
}

pub struct ChainState {
    pub net: Net,
    pub index: HashMap<Hash, Entry>,
    children: HashMap<Hash, Vec<Hash>>,
    /// `active[h]` is the hash of the active block at height h; `active[0]` is genesis.
    pub active: Vec<Hash>,
    pub state: Chain,
    undo: HashMap<Hash, Undo>,
    store: BlockStore,
    seq: u64,
    pub best_header: Hash,
    pub snapshots: BTreeMap<u32, Arc<Snapshot>>,
    pub verify_sigs: bool,
    last_error: Option<Invalid>,
    /// Height the active chain starts from: 0, or the block before a snapshot. Blocks at or
    /// below it are not stored and the chain cannot be reorganised below it.
    pub base: u32,
    dir: Option<std::path::PathBuf>,
}

impl ChainState {
    pub fn new(net: Net, store: BlockStore) -> Self {
        let g = net.genesis_hash();
        let genesis = Entry {
            header: net.genesis,
            hash: g,
            height: 0,
            time: net.genesis_time,
            work: work(net.genesis.bits),
            seq: 0,
            pos: None,
            invalid: false,
        };
        ChainState {
            index: HashMap::from([(g, genesis)]),
            children: HashMap::new(),
            active: vec![g],
            state: Chain::new(net.clone()),
            undo: HashMap::new(),
            store,
            seq: 1,
            best_header: g,
            snapshots: BTreeMap::new(),
            verify_sigs: true,
            last_error: None,
            base: 0,
            dir: None,
            net,
        }
    }

    /// Open `<dir>/blocks.dat` and replay it.
    pub fn open(net: Net, dir: &Path) -> std::io::Result<Self> {
        std::fs::create_dir_all(dir)?;
        let (store, blocks) = BlockStore::open(&dir.join("blocks.dat"))?;
        let mut cs = ChainState::new(net, store);
        let snap = dir.join("snapshot.dat");
        if snap.exists() {
            let raw = std::fs::read(&snap)?;
            cs.load_snapshot_file(&raw).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("snapshot.dat: {e}")))?;
        }
        cs.dir = Some(dir.to_path_buf());
        cs.replay(blocks);
        Ok(cs)
    }

    /// Start the active chain from a UTXO set instead of from genesis. `base` is the block whose
    /// state `entries` is (the parent of a snapshot block); its headers must be in the index.
    pub fn start_from_snapshot(&mut self, base: Hash, entries: Vec<(OutPoint, UtxoEntry)>) -> std::result::Result<Changes, String> {
        if self.active.len() != 1 {
            return Err("the chain has already started".into());
        }
        let e = self.index.get(&base).ok_or("unknown base block")?;
        if e.invalid {
            return Err("base block is invalid".into());
        }
        let (height, time) = (e.height, e.time);
        if !Chain::is_snapshot_height(height + 1) {
            return Err("the base must be the block before a snapshot height".into());
        }
        let mut path = vec![base];
        while path.last() != Some(&self.active[0]) {
            let prev = self.index[path.last().unwrap()].header.prev;
            path.push(prev);
        }
        path.reverse();
        let utxo: UtxoSet = entries.iter().copied().collect();
        if utxo.len() != entries.len() {
            return Err("repeated outpoints".into());
        }
        if let Some(dir) = &self.dir {
            let mut f = Vec::new();
            f.extend(height.to_le_bytes());
            for h in &path[1..] {
                f.extend(self.index[h].header.serialize());
            }
            f.extend((entries.len() as u32).to_le_bytes());
            for (k, e) in &entries {
                f.extend(utxo_entry(k, e));
            }
            let tmp = dir.join("snapshot.dat.tmp");
            std::fs::write(&tmp, &f).map_err(|e| e.to_string())?;
            std::fs::rename(&tmp, dir.join("snapshot.dat")).map_err(|e| e.to_string())?;
        }
        self.active = path;
        self.state = Chain { net: self.net.clone(), height, tip: base, time, utxo };
        self.base = height;
        Ok(self.activate())
    }

    fn load_snapshot_file(&mut self, raw: &[u8]) -> std::result::Result<(), String> {
        let mut r = Reader::new(raw);
        let height = r.u32().map_err(|e| e.to_string())?;
        let mut base = self.active[0];
        for _ in 0..height {
            let hd = Header::parse(r.take(80).map_err(|e| e.to_string())?);
            base = self.accept_header(&hd, NO_CLOCK).map_err(|e| e.to_string())?;
        }
        let n = r.u32().map_err(|e| e.to_string())? as usize;
        let mut entries = Vec::with_capacity(n);
        for _ in 0..n {
            entries.push(r.take(UTXO_ENTRY_LEN).ok().and_then(parse_utxo_entry).ok_or("bad entry")?);
        }
        self.start_from_snapshot(base, entries).map(|_| ())
    }

    fn replay(&mut self, blocks: Vec<Vec<u8>>) {
        // The records go back in as they were first stored; nothing is appended again.
        let mut pos = 0u64;
        for raw in blocks {
            let p = pos;
            pos += 4 + raw.len() as u64;
            let Ok(blk) = read_block(&raw) else { continue };
            if self.accept_header(&blk.header, NO_CLOCK).is_err() {
                continue;
            }
            let hash = blk.hash();
            if self.index[&hash].pos.is_none() {
                self.index.get_mut(&hash).unwrap().pos = Some(p);
            }
        }
        self.activate();
    }

    pub fn tip(&self) -> &Entry {
        &self.index[self.active.last().unwrap()]
    }

    pub fn height(&self) -> u32 {
        self.state.height
    }

    pub fn entry(&self, h: &Hash) -> Option<&Entry> {
        self.index.get(h)
    }

    pub fn is_active(&self, h: &Hash) -> bool {
        self.index.get(h).is_some_and(|e| self.active.get(e.height as usize) == Some(h))
    }

    pub fn has_block(&self, h: &Hash) -> bool {
        self.index.get(h).is_some_and(|e| e.pos.is_some() || (e.height <= self.base && self.active.get(e.height as usize) == Some(h)))
    }

    pub fn block_raw(&mut self, h: &Hash) -> Option<Vec<u8>> {
        let pos = self.index.get(h)?.pos?;
        Some(self.store.read(pos))
    }

    pub fn block_at(&mut self, height: u32) -> Option<Vec<u8>> {
        let h = *self.active.get(height as usize)?;
        self.block_raw(&h)
    }

    /// Parent-relative checks of a header; on success it is in the index.
    pub fn accept_header(&mut self, hd: &Header, now: i64) -> Result<Hash> {
        let hash = hd.hash();
        if let Some(e) = self.index.get(&hash) {
            return if e.invalid { Err(Invalid("known invalid")) } else { Ok(hash) };
        }
        let Some(parent) = self.index.get(&hd.prev) else { return Err(Invalid("orphan")) };
        if parent.invalid {
            return Err(Invalid("prev invalid"));
        }
        let t = full_time(parent.time, hd.time32);
        if t > now.saturating_add(FUTURE_LIMIT) {
            return Err(Invalid("time"));
        }
        if hd.bits != asert_bits(&self.net, parent.height as u64, parent.time) {
            return Err(Invalid("bits"));
        }
        if !meets_target(&hash, &bits_to_target(hd.bits)?) {
            return Err(Invalid("pow"));
        }
        let e = Entry {
            header: *hd,
            hash,
            height: parent.height + 1,
            time: t,
            work: &parent.work + work(hd.bits),
            seq: self.seq,
            pos: None,
            invalid: false,
        };
        self.seq += 1;
        if e.work > self.index[&self.best_header].work {
            self.best_header = hash;
        }
        self.children.entry(hd.prev).or_default().push(hash);
        self.index.insert(hash, e);
        Ok(hash)
    }

    /// A block from the network or a miner. On `Err` the block is invalid (or, for "time", early).
    pub fn accept_block(&mut self, raw: &[u8], now: i64) -> (Result<Accepted>, Changes) {
        let mut changes = Changes::default();
        let r = self.accept_one(raw, now, &mut changes);
        (r, changes)
    }

    fn accept_one(&mut self, raw: &[u8], now: i64, changes: &mut Changes) -> Result<Accepted> {
        let blk = read_block(raw)?;
        let hash = blk.hash();
        if self.has_block(&hash) {
            return Ok(Accepted::Duplicate);
        }
        if !self.index.contains_key(&blk.header.prev) {
            return Ok(Accepted::Orphan);
        }
        self.accept_header(&blk.header, now)?;
        // Checks that need only the block itself. A merkle mismatch says nothing about the
        // header (the body may have been altered in transit), so the header stays usable.
        if blk.header.merkle != merkle_root(&blk.leaves()) {
            return Err(Invalid("merkle"));
        }
        let height = self.index[&hash].height;
        if blk.coinbase.height != height {
            self.mark_invalid(hash);
            return Err(Invalid("cbheight"));
        }
        if blk.txs.iter().map(|t| t.wits.len()).sum::<usize>() > max_sigs(height as u64) {
            self.mark_invalid(hash);
            return Err(Invalid("sigs"));
        }
        let pos = self.store.append(raw);
        self.index.get_mut(&hash).unwrap().pos = Some(pos);
        changes.extend(self.activate());
        if let Some(e) = self.index.get(&hash)
            && e.invalid
        {
            return Err(self.last_error.take().unwrap_or(Invalid("invalid")));
        }
        Ok(Accepted::Stored)
    }

    fn mark_invalid(&mut self, h: Hash) {
        let mut stack = vec![h];
        while let Some(x) = stack.pop() {
            if let Some(e) = self.index.get_mut(&x) {
                e.invalid = true;
            }
            if let Some(c) = self.children.get(&x) {
                stack.extend(c.iter().copied());
            }
        }
        if self.index[&self.best_header].invalid {
            self.best_header = self.pick_best_header();
        }
    }

    fn pick_best_header(&self) -> Hash {
        let mut best = &self.index[&self.active[0]];
        for e in self.index.values() {
            if !e.invalid && (e.work > best.work || (e.work == best.work && e.seq < best.seq)) {
                best = e;
            }
        }
        best.hash
    }

    /// Path from the active chain to `h`: (fork height, hashes above the fork, oldest first).
    fn path_from_active(&self, mut h: Hash) -> (u32, Vec<Hash>) {
        let mut path = Vec::new();
        while !self.is_active(&h) {
            path.push(h);
            h = self.index[&h].header.prev;
        }
        path.reverse();
        (self.index[&h].height, path)
    }

    /// The best block we could switch to: for every leaf of the tree, the highest block on its
    /// path whose ancestors back to the active chain are all stored and not invalid.
    fn best_candidate(&self) -> Option<Hash> {
        let tip = self.tip();
        let mut best: Option<&Entry> = None;
        for e in self.index.values() {
            if e.invalid || e.pos.is_none() || self.children.get(&e.hash).is_some_and(|c| c.iter().any(|x| self.index[x].pos.is_some())) {
                continue; // only leaves of the stored part of the tree
            }
            let (fork, path) = self.path_from_active(e.hash);
            if fork < self.base {
                continue; // below a snapshot there is nothing to reorganise with
            }
            let mut reach = None;
            for x in &path {
                let xe = &self.index[x];
                if xe.invalid || xe.pos.is_none() {
                    break;
                }
                reach = Some(xe);
            }
            let Some(r) = reach else { continue };
            let better_than_tip = r.work > tip.work;
            let better_than_best = best.is_none_or(|b| r.work > b.work || (r.work == b.work && r.seq < b.seq));
            if better_than_tip && better_than_best {
                best = Some(r);
            }
        }
        best.map(|e| e.hash)
    }

    /// Move the active chain to the best candidate, until no candidate beats the tip.
    pub fn activate(&mut self) -> Changes {
        let mut changes = Changes::default();
        while let Some(target) = self.best_candidate() {
            let (fork, path) = self.path_from_active(target);
            while self.state.height > fork {
                changes.disconnected.push(self.disconnect_tip());
            }
            for h in path {
                match self.connect(h) {
                    Ok(b) => changes.connected.push(b),
                    Err(e) => {
                        self.last_error = Some(e);
                        self.mark_invalid(h);
                        break;
                    }
                }
            }
        }
        changes
    }

    fn connect(&mut self, h: Hash) -> Result<Block> {
        let raw = self.block_raw(&h).expect("stored block");
        let blk = read_block(&raw)?;
        let height = self.state.height + 1;
        let snapshot = if Chain::is_snapshot_height(height) { Some(self.make_snapshot(height)) } else { None };
        let root = snapshot.as_ref().map_or(ZERO32, |s| s.root);
        let c = self.state.check_block(blk, NO_CLOCK, self.verify_sigs, Some(root))?;
        let undo = self.state.apply_checked(&c);
        self.undo.insert(h, undo);
        self.active.push(h);
        if let Some(s) = snapshot {
            self.snapshots.insert(height, Arc::new(s));
            while self.snapshots.len() > 2 {
                let k = *self.snapshots.keys().next().unwrap();
                self.snapshots.remove(&k);
            }
        }
        Ok(c.block)
    }

    fn make_snapshot(&self, height: u32) -> Snapshot {
        let entries: Vec<(OutPoint, UtxoEntry)> = self.state.utxo.iter().map(|(k, e)| (*k, *e)).collect();
        let leaves: Vec<Hash> = entries.iter().map(|(k, e)| utxo_leaf(k, e)).collect();
        Snapshot { height, root: merkle_root(&leaves), entries, leaves }
    }

    fn disconnect_tip(&mut self) -> Block {
        let h = self.active.pop().unwrap();
        let raw = self.block_raw(&h).unwrap();
        let undo = self.undo.remove(&h).expect("undo data for an active block");
        let parent = *self.active.last().unwrap();
        self.snapshots.remove(&self.state.height);
        self.state.undo(&undo, parent);
        read_block(&raw).unwrap()
    }

    // ------------------------------------------------------------ sync helpers
    /// Hashes of the active chain going back: the last 10 one by one, then doubling the step.
    pub fn locator(&self) -> Vec<Hash> {
        let mut out = Vec::new();
        let mut h = self.active.len() as i64 - 1;
        let mut step = 1;
        while h > 0 {
            out.push(self.active[h as usize]);
            if out.len() >= 10 {
                step *= 2;
            }
            h -= step;
        }
        out.push(self.active[0]);
        out
    }

    /// Up to `max` active headers after the first locator hash that is on our active chain.
    pub fn headers_after(&self, locator: &[Hash], max: usize) -> Vec<Header> {
        let start = locator.iter().find(|h| self.is_active(h)).map_or(0, |h| self.index[h].height);
        self.active.iter().skip(start as usize + 1).take(max).map(|h| self.index[h].header).collect()
    }

    /// Blocks to fetch: the path to the best header, while it has more work than our tip.
    pub fn wanted_blocks(&self, max: usize) -> Vec<Hash> {
        let best = &self.index[&self.best_header];
        if best.invalid || best.work <= self.tip().work {
            return vec![];
        }
        let mut out = Vec::new();
        let mut h = best.hash;
        while !self.has_block(&h) {
            out.push(h);
            h = self.index[&h].header.prev;
        }
        out.reverse();
        out.truncate(max);
        out
    }
}
