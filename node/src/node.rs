//! The running node: chain state and mempool behind one lock, one thread per peer, a manager
//! thread for outbound connections and block requests.

use std::collections::{HashMap, HashSet};
use std::io::BufWriter;
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::mpsc::{Sender, channel};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use num_bigint::BigUint;

use crate::chainstate::{Accepted, ChainState};
use crate::consensus::*;
use crate::mempool::{Mempool, Policy};
use crate::p2p::*;

pub fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64)
}

pub struct Config {
    pub net: Net,
    pub datadir: Option<std::path::PathBuf>,
    pub listen: Option<SocketAddr>,
    /// Peers to keep connected to, whatever their network group.
    pub connect: Vec<String>,
    /// Peers to start from (in the binary for a launched network; none yet).
    pub seeds: Vec<String>,
    pub max_outbound: usize,
    pub max_inbound: usize,
    /// Blocks are downloaded only once the best header chain has at least this much work.
    pub min_chain_work: BigUint,
    pub policy: Policy,
    pub verbose: bool,
    /// Start from the newest UTXO snapshot the peers offer instead of downloading every block.
    pub snapshot_sync: bool,
}

impl Config {
    pub fn new(net: Net) -> Config {
        Config {
            net,
            datadir: None,
            listen: None,
            connect: vec![],
            seeds: vec![],
            max_outbound: 8,
            max_inbound: 64,
            min_chain_work: BigUint::default(),
            policy: Policy::default(),
            verbose: false,
            snapshot_sync: false,
        }
    }
}

pub struct Peer {
    pub addr: SocketAddr,
    pub outbound: bool,
    pub manual: bool,
    tx: Sender<Msg>,
    pub version: Option<(u32, u32, Hash)>, // protocol version, height, tip at hello
    listen_port: u16,
    in_flight: HashMap<Hash, Instant>,
    last_headers_request: Option<Instant>,
    /// The most-work block we know the peer has (from its hello, inv and headers).
    best_known: Option<Hash>,
}

pub struct Node {
    pub cs: ChainState,
    pub pool: Mempool,
    pub peers: HashMap<u64, Peer>,
    pub addrs: HashSet<SocketAddr>,
    pub manual: Vec<String>,
    pub tip_generation: u64,
    pub listen_port: u16,
    pub min_chain_work: BigUint,
    pub verbose: bool,
    next_peer: u64,
    nonce: u64,
    pub max_outbound: usize,
    pub max_inbound: usize,
    pub stopping: bool,
    /// Waiting to start from a snapshot; `snap` is the one being collected.
    pub snap_mode: bool,
    pub snap: Option<crate::snapsync::SnapSync>,
}

#[derive(Clone)]
pub struct Handle(pub Arc<(Mutex<Node>, Condvar)>);

impl Handle {
    pub fn lock(&self) -> MutexGuard<'_, Node> {
        self.0.0.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Wait until the tip changes from `generation`, or the timeout passes. Returns the new generation.
    pub fn wait_tip(&self, generation: u64, timeout: Duration) -> u64 {
        let g = self.lock();
        let (g, _) =
            self.0.1.wait_timeout_while(g, timeout, |n| n.tip_generation == generation && !n.stopping).unwrap_or_else(|e| e.into_inner());
        g.tip_generation
    }

    fn notify(&self) {
        self.0.1.notify_all();
    }

    pub fn submit_block(&self, raw: &[u8], from: Option<u64>) -> std::result::Result<Accepted, Invalid> {
        let r = self.lock().submit_block(raw, from);
        self.notify();
        r
    }

    pub fn submit_tx(&self, raw: &[u8], from: Option<u64>) -> std::result::Result<Hash, String> {
        self.lock().submit_tx(raw, from)
    }
}

fn log(verbose: bool, s: impl AsRef<str>) {
    if verbose {
        eprintln!("[{}] {}", now(), s.as_ref());
    }
}

impl Node {
    fn send(&self, peer: u64, m: Msg) {
        if let Some(p) = self.peers.get(&peer) {
            let _ = p.tx.send(m);
        }
    }

    fn broadcast(&self, m: &Msg, except: Option<u64>) {
        for (id, p) in &self.peers {
            if Some(*id) != except && p.version.is_some() {
                let _ = p.tx.send(m.clone());
            }
        }
    }

    pub fn submit_block(&mut self, raw: &[u8], from: Option<u64>) -> std::result::Result<Accepted, Invalid> {
        if let Some(p) = from.and_then(|f| self.peers.get_mut(&f))
            && let Ok(b) = read_block(raw)
        {
            p.in_flight.remove(&b.hash());
        }
        let (r, ch) = self.cs.accept_block(raw, now());
        if !ch.is_empty() {
            self.pool.apply_changes(&ch, &self.cs.state);
            self.tip_generation += 1;
            let tip = self.cs.state.tip;
            log(
                self.verbose,
                format!(
                    "tip {} height {} ({} disconnected, {} connected)",
                    display_hash(&tip),
                    self.cs.height(),
                    ch.disconnected.len(),
                    ch.connected.len()
                ),
            );
            self.broadcast(&Msg::Inv { kind: INV_BLOCK, hashes: vec![tip] }, from);
        }
        match (&r, from) {
            (Ok(Accepted::Orphan), Some(f)) => self.request_headers(f),
            (Err(e), Some(f)) => log(self.verbose, format!("peer {f}: block refused: {e}")),
            _ => {}
        }
        self.request_blocks();
        r
    }

    pub fn submit_tx(&mut self, raw: &[u8], from: Option<u64>) -> std::result::Result<Hash, String> {
        let tx = Tx::parse(raw).map_err(|e| e.to_string())?;
        let id = self.pool.accept(tx, &self.cs.state)?;
        self.broadcast(&Msg::Inv { kind: INV_TX, hashes: vec![id] }, from);
        Ok(id)
    }

    fn hello(&self) -> Msg {
        Msg::Hello {
            version: PROTOCOL_VERSION,
            chain_id: self.cs.net.chain_id,
            height: self.cs.height(),
            tip: self.cs.state.tip,
            port: self.listen_port,
            nonce: self.nonce,
        }
    }

    fn request_headers(&mut self, peer: u64) {
        let loc = self.cs.locator();
        if let Some(p) = self.peers.get_mut(&peer) {
            p.last_headers_request = Some(Instant::now());
        }
        self.send(peer, Msg::Get { kind: GET_HEADERS, hashes: loc });
    }

    /// Ask for the blocks on the way to the best header, spread over the peers.
    pub fn request_blocks(&mut self) {
        if self.snap_mode {
            return;
        }
        let best = self.cs.entry(&self.cs.best_header).map(|e| e.work.clone()).unwrap_or_default();
        if best < self.min_chain_work {
            return;
        }
        let wanted = self.cs.wanted_blocks(64);
        if wanted.is_empty() {
            return;
        }
        let busy: HashSet<Hash> = self.peers.values().flat_map(|p| p.in_flight.keys().copied()).collect();
        let low = wanted.iter().filter_map(|h| self.cs.entry(h)).map(|e| e.height).min().unwrap_or(0);
        let mut ids: Vec<u64> = self.peers.iter().filter(|(_, p)| p.version.is_some() && p.best_known.is_some()).map(|(i, _)| *i).collect();
        ids.sort_by_key(|i| self.peers[i].in_flight.len());
        let mut todo: Vec<Hash> = wanted.into_iter().filter(|h| !busy.contains(h)).collect();
        for id in ids {
            // what this peer has, down to the lowest block we want
            let mut has = HashSet::new();
            let mut cur = self.peers[&id].best_known;
            while let Some(e) = cur.and_then(|h| self.cs.entry(&h)) {
                if e.height < low {
                    break;
                }
                has.insert(e.hash);
                cur = Some(e.header.prev);
            }
            let room = 16usize.saturating_sub(self.peers[&id].in_flight.len());
            let batch: Vec<Hash> = todo.iter().filter(|h| has.contains(*h)).take(room).copied().collect();
            if batch.is_empty() {
                continue;
            }
            todo.retain(|h| !batch.contains(h));
            let p = self.peers.get_mut(&id).unwrap();
            for h in &batch {
                p.in_flight.insert(*h, Instant::now());
            }
            self.send(id, Msg::Get { kind: INV_BLOCK, hashes: batch });
        }
    }

    /// Starting from a snapshot: pick the newest snapshot height below the best header, get that
    /// block for its `utxo_root`, collect the chunks, then switch to normal operation.
    /// Gives up (and downloads every block) when the chain is too short or no peer serves it.
    pub fn drive_snapshot(&mut self) {
        use crate::snapsync::SnapSync;
        if !self.snap_mode {
            return;
        }
        if self.cs.height() > 0 || self.cs.base > 0 {
            self.snap_mode = false;
            return;
        }
        let best = self.cs.entry(&self.cs.best_header).cloned().unwrap();
        let ready: Vec<u64> = self.peers.iter().filter(|(_, p)| p.version.is_some()).map(|(i, _)| *i).collect();
        if self.snap.is_none() {
            if ready.is_empty() {
                return;
            }
            let h = best.height / SNAPSHOT_EVERY * SNAPSHOT_EVERY;
            if h == 0 {
                // nothing to start from yet: peers that are this short are better followed block by block
                if best.height > 0 {
                    log(self.verbose, "snapshot: chain shorter than 1440 blocks, downloading blocks");
                    self.snap_mode = false;
                    self.request_blocks();
                }
                return;
            }
            let mut cur = best.hash;
            while self.cs.entry(&cur).unwrap().height > h {
                cur = self.cs.entry(&cur).unwrap().header.prev;
            }
            log(self.verbose, format!("snapshot: starting from height {h}"));
            self.snap = Some(SnapSync::new(h, cur));
        }
        let sn = self.snap.as_mut().unwrap();
        if sn.started.elapsed() > Duration::from_secs(180) {
            log(self.verbose, "snapshot: no peer served it, downloading blocks");
            self.snap = None;
            self.snap_mode = false;
            self.request_blocks();
            return;
        }
        if sn.root.is_none() {
            let block = sn.block;
            if let Some(raw) = self.cs.block_raw(&block) {
                let b = read_block(&raw).unwrap();
                self.snap.as_mut().unwrap().root = Some(b.coinbase.utxo_root);
            } else {
                if sn.block_requested.is_none_or(|t| t.elapsed() > Duration::from_secs(10)) {
                    sn.block_requested = Some(Instant::now());
                    let holders: Vec<u64> = ready.iter().copied().filter(|i| self.peers[i].best_known.is_some()).collect();
                    for id in holders.iter().take(2) {
                        self.send(*id, Msg::Get { kind: INV_BLOCK, hashes: vec![block] });
                    }
                }
                return;
            }
        }
        let sn = self.snap.as_mut().unwrap();
        if let Some(entries) = sn.complete() {
            let base = self.cs.entry(&sn.block).unwrap().header.prev;
            let (height, n) = (sn.height, entries.len());
            self.snap = None;
            self.snap_mode = false;
            match self.cs.start_from_snapshot(base, entries) {
                Ok(ch) => {
                    log(self.verbose, format!("snapshot: {n} outputs at height {height}, tip now {}", self.cs.height()));
                    self.pool.apply_changes(&ch, &self.cs.state);
                    self.tip_generation += 1;
                }
                Err(e) => log(self.verbose, format!("snapshot: cannot start from it: {e}")),
            }
            self.request_blocks();
            return;
        }
        // ask for missing chunks, a few per peer, again after 20 seconds
        let height = sn.height;
        sn.requested.retain(|_, (_, t)| t.elapsed() < Duration::from_secs(20));
        let mut load: HashMap<u64, usize> = HashMap::new();
        for (p, _) in sn.requested.values() {
            *load.entry(*p).or_default() += 1;
        }
        let todo: Vec<u32> = sn.missing().into_iter().filter(|k| !sn.requested.contains_key(k)).collect();
        let mut sends = Vec::new();
        for k in todo {
            let Some(&id) =
                ready.iter().filter(|i| load.get(i).copied().unwrap_or(0) < 4).min_by_key(|i| load.get(i).copied().unwrap_or(0))
            else {
                break;
            };
            *load.entry(id).or_default() += 1;
            sn.requested.insert(k, (id, Instant::now()));
            sends.push((id, k));
            if sn.total.is_none() {
                break; // the first reply says how many there are
            }
        }
        for (id, k) in sends {
            self.send(id, Msg::SnapRequest { height, chunk: k });
        }
    }

    /// Remember that a peer has `h`, if it beats what we knew.
    fn peer_has(&mut self, id: u64, h: Hash) {
        let Some(e) = self.cs.entry(&h) else { return };
        let w = e.work.clone();
        let Some(p) = self.peers.get_mut(&id) else { return };
        let better = match p.best_known.and_then(|b| self.cs.entry(&b)) {
            Some(b) => w > b.work,
            None => true,
        };
        if better {
            p.best_known = Some(h);
        }
    }

    /// Handle one message. Returns false to drop the peer.
    fn handle(&mut self, id: u64, m: Msg, handle: &Handle) -> bool {
        let Some(p) = self.peers.get(&id) else { return false };
        if p.version.is_none() && !matches!(m, Msg::Hello { .. }) {
            return false;
        }
        match m {
            Msg::Hello { version, chain_id, height, tip, port, nonce } => {
                if chain_id != self.cs.net.chain_id || nonce == self.nonce || p.version.is_some() {
                    return false;
                }
                let outbound = p.outbound;
                let addr = p.addr;
                let p = self.peers.get_mut(&id).unwrap();
                p.version = Some((version, height, tip));
                p.listen_port = port;
                if !outbound {
                    let h = self.hello();
                    self.send(id, h);
                    if port != 0 {
                        self.addrs.insert(SocketAddr::new(addr.ip(), port));
                    }
                }
                log(self.verbose, format!("peer {id} {addr}: hello, height {height}"));
                self.peer_has(id, tip);
                self.request_headers(id);
                self.send(id, Msg::Peers(vec![]));
                // our mempool, so a new peer can mine what we know
                let txids: Vec<Hash> = self.pool.txs.keys().copied().take(MAX_INV).collect();
                if !txids.is_empty() {
                    self.send(id, Msg::Inv { kind: INV_TX, hashes: txids });
                }
            }
            Msg::Peers(list) => {
                if list.is_empty() {
                    let mut out: Vec<SocketAddr> = self.addrs.iter().copied().take(MAX_PEERS_MSG).collect();
                    out.truncate(MAX_PEERS_MSG);
                    if !out.is_empty() {
                        self.send(id, Msg::Peers(out));
                    }
                } else if self.addrs.len() < 10_000 {
                    self.addrs.extend(list.into_iter().filter(|a| a.port() != 0));
                }
            }
            Msg::Inv { kind: INV_BLOCK, hashes } => {
                for h in &hashes {
                    self.peer_has(id, *h);
                }
                if hashes.iter().any(|h| self.cs.entry(h).is_none()) {
                    self.request_headers(id);
                } else {
                    self.request_blocks();
                }
            }
            Msg::Inv { kind: INV_TX, hashes } => {
                let want: Vec<Hash> = hashes.into_iter().filter(|h| !self.pool.contains(h)).collect();
                if !want.is_empty() {
                    self.send(id, Msg::Get { kind: INV_TX, hashes: want });
                }
            }
            Msg::Get { kind: INV_TX, hashes } => {
                for h in hashes {
                    if let Some(e) = self.pool.txs.get(&h) {
                        self.send(id, Msg::Tx(e.tx.serialize()));
                    }
                }
            }
            Msg::Get { kind: INV_BLOCK, hashes } => {
                for h in hashes.iter().take(64) {
                    if let Some(raw) = self.cs.block_raw(h) {
                        self.send(id, Msg::Block(raw));
                    }
                }
            }
            Msg::Get { kind: GET_HEADERS, hashes } => {
                let hs = self.cs.headers_after(&hashes, MAX_HEADERS);
                self.send(id, Msg::Headers(hs));
            }
            Msg::Headers(hs) => {
                let n = hs.len();
                let t = now();
                for h in &hs {
                    match self.cs.accept_header(h, t) {
                        Ok(_) => {}
                        Err(Invalid("orphan")) => {
                            self.request_headers(id);
                            break;
                        }
                        Err(Invalid("time")) => break,
                        Err(e) => {
                            log(self.verbose, format!("peer {id}: bad header: {e}"));
                            return false;
                        }
                    }
                }
                if let Some(last) = hs.last() {
                    self.peer_has(id, last.hash());
                }
                if n < MAX_HEADERS {
                    self.drive_snapshot(); // the header chain is complete as far as this peer knows
                }
                if n == MAX_HEADERS {
                    let mut loc = vec![hs[n - 1].hash()];
                    loc.extend(self.cs.locator());
                    self.send(id, Msg::Get { kind: GET_HEADERS, hashes: loc });
                }
                self.request_blocks();
            }
            Msg::Block(raw) => {
                let r = self.submit_block(&raw, Some(id));
                if r.is_ok()
                    && let Ok(b) = read_block(&raw)
                {
                    self.peer_has(id, b.hash());
                }
                self.drive_snapshot();
                handle.notify();
            }
            Msg::Tx(raw) => {
                if let Err(e) = self.submit_tx(&raw, Some(id)) {
                    log(self.verbose, format!("peer {id}: tx refused: {e}"));
                }
            }
            Msg::SnapRequest { height, chunk } => {
                let reply = match self.cs.snapshots.get(&height) {
                    Some(s) if (chunk as usize) * SNAPSHOT_CHUNK < s.entries.len().max(1) => {
                        let a = chunk as usize * SNAPSHOT_CHUNK;
                        let b = (a + SNAPSHOT_CHUNK).min(s.entries.len());
                        Msg::SnapChunk {
                            height,
                            chunk,
                            total: s.entries.len() as u32,
                            entries: s.entries[a..b].to_vec(),
                            proof: chunk_proof(&s.leaves, chunk as usize),
                        }
                    }
                    _ => Msg::SnapMissing { height, chunk },
                };
                self.send(id, reply);
            }
            Msg::SnapChunk { height, chunk, total, entries, proof } => {
                if let Some(sn) = self.snap.as_mut().filter(|sn| sn.height == height) {
                    if let Err(e) = sn.add_chunk(chunk, total, entries, &proof) {
                        log(self.verbose, format!("peer {id}: bad snapshot chunk {chunk}: {e}"));
                        return false;
                    }
                    log(self.verbose, format!("snapshot {height}: chunk {chunk} of {}", sn.chunk_count().unwrap_or(0)));
                    self.drive_snapshot();
                    handle.notify();
                }
            }
            Msg::SnapMissing { height, chunk } => {
                if let Some(sn) = self.snap.as_mut().filter(|sn| sn.height == height) {
                    sn.requested.remove(&chunk);
                }
            }
            Msg::Inv { .. } | Msg::Get { .. } => {}
        }
        true
    }
}

impl Handle {
    pub fn start(cfg: Config) -> std::io::Result<Handle> {
        let mut cs = match &cfg.datadir {
            Some(d) => ChainState::open(cfg.net.clone(), d)?,
            None => ChainState::new(cfg.net.clone(), crate::chainstate::BlockStore::memory()),
        };
        cs.best_header = cs.state.tip;
        let mut nonce = [0u8; 8];
        getrandom::fill(&mut nonce).expect("randomness");
        let node = Node {
            cs,
            pool: Mempool::new(cfg.policy.clone()),
            peers: HashMap::new(),
            addrs: HashSet::new(),
            manual: cfg.connect.clone(),
            tip_generation: 0,
            listen_port: cfg.listen.map_or(0, |a| a.port()),
            min_chain_work: cfg.min_chain_work.clone(),
            verbose: cfg.verbose,
            next_peer: 0,
            nonce: u64::from_le_bytes(nonce),
            max_outbound: cfg.max_outbound,
            max_inbound: cfg.max_inbound,
            stopping: false,
            snap_mode: cfg.snapshot_sync,
            snap: None,
        };
        let h = Handle(Arc::new((Mutex::new(node), Condvar::new())));
        {
            let mut n = h.lock();
            for s in &cfg.seeds {
                if let Ok(it) = s.to_socket_addrs() {
                    n.addrs.extend(it);
                }
            }
        }
        if let Some(addr) = cfg.listen {
            let l = TcpListener::bind(addr)?;
            h.lock().listen_port = l.local_addr()?.port();
            let hh = h.clone();
            std::thread::spawn(move || {
                for s in l.incoming().flatten() {
                    let inbound = hh.lock().peers.values().filter(|p| !p.outbound).count();
                    if inbound >= hh.lock().max_inbound {
                        continue;
                    }
                    let hh2 = hh.clone();
                    std::thread::spawn(move || hh2.run_peer(s, false, false));
                }
            });
        }
        let hh = h.clone();
        std::thread::spawn(move || hh.manager());
        Ok(h)
    }

    pub fn listen_port(&self) -> u16 {
        self.lock().listen_port
    }

    pub fn connect(&self, addr: SocketAddr, manual: bool) {
        let h = self.clone();
        std::thread::spawn(move || {
            if let Ok(s) = TcpStream::connect_timeout(&addr, Duration::from_secs(5)) {
                h.run_peer(s, true, manual);
            }
        });
    }

    fn run_peer(&self, stream: TcpStream, outbound: bool, manual: bool) {
        let Ok(addr) = stream.peer_addr() else { return };
        let _ = stream.set_nodelay(true);
        let Ok(wstream) = stream.try_clone() else { return };
        let (tx, rx) = channel::<Msg>();
        let id = {
            let mut n = self.lock();
            n.next_peer += 1;
            let id = n.next_peer;
            n.peers.insert(
                id,
                Peer {
                    addr,
                    outbound,
                    manual,
                    tx: tx.clone(),
                    version: None,
                    listen_port: 0,
                    in_flight: HashMap::new(),
                    last_headers_request: None,
                    best_known: None,
                },
            );
            if outbound {
                let hello = n.hello();
                let _ = tx.send(hello);
            }
            id
        };
        std::thread::spawn(move || {
            let mut w = BufWriter::new(wstream);
            while let Ok(m) = rx.recv() {
                if write_msg(&mut w, &m).is_err() {
                    break;
                }
                // flush when nothing else is queued
                if std::io::Write::flush(&mut w).is_err() {
                    break;
                }
            }
            let _ = w.get_ref().shutdown(std::net::Shutdown::Both);
        });
        let mut r = std::io::BufReader::new(stream);
        let _ = r.get_ref().set_read_timeout(Some(Duration::from_secs(600)));
        while let Ok(Some(m)) = read_msg(&mut r) {
            let mut n = self.lock();
            if n.stopping || !n.handle(id, m, self) {
                break;
            }
        }
        let mut n = self.lock();
        n.peers.remove(&id);
        let _ = r.get_ref().shutdown(std::net::Shutdown::Both);
        log(n.verbose, format!("peer {id} {addr}: gone"));
        drop(tx);
    }

    fn manager(&self) {
        let mut last_headers = Instant::now();
        loop {
            {
                let mut n = self.lock();
                if n.stopping {
                    return;
                }
                // requests that did not arrive go back in the pool
                for p in n.peers.values_mut() {
                    p.in_flight.retain(|_, t| t.elapsed() < Duration::from_secs(30));
                }
                n.request_blocks();
                if n.snap.is_some() {
                    n.drive_snapshot();
                }
                if last_headers.elapsed() > Duration::from_secs(60) {
                    last_headers = Instant::now();
                    let ids: Vec<u64> = n.peers.keys().copied().collect();
                    for id in ids {
                        n.request_headers(id);
                    }
                }
                // manual peers: always try to keep them
                let connected: HashSet<SocketAddr> = n.peers.values().map(|p| p.addr).collect();
                let manual = n.manual.clone();
                let mut to_connect: Vec<(SocketAddr, bool)> = Vec::new();
                for m in manual {
                    if let Some(a) = m.to_socket_addrs().ok().and_then(|mut it| it.next())
                        && !connected.contains(&a)
                    {
                        to_connect.push((a, true));
                    }
                }
                // others: one per network group
                let outbound = n.peers.values().filter(|p| p.outbound && !p.manual).count();
                if outbound < n.max_outbound {
                    let groups: HashSet<Vec<u8>> = n.peers.values().filter(|p| p.outbound).map(|p| netgroup(&p.addr)).collect();
                    if let Some(a) = n.addrs.iter().find(|a| {
                        !connected.contains(a) && !groups.contains(&netgroup(a)) && **a != SocketAddr::from(([127, 0, 0, 1], n.listen_port))
                    }) {
                        to_connect.push((*a, false));
                    }
                }
                drop(n);
                for (a, manual) in to_connect {
                    self.connect(a, manual);
                }
            }
            std::thread::sleep(Duration::from_secs(3));
        }
    }

    pub fn stop(&self) {
        let mut n = self.lock();
        n.stopping = true;
        for p in n.peers.values() {
            let _ = p.tx.send(Msg::Peers(vec![]));
        }
        n.peers.clear();
        drop(n);
        self.notify();
    }
}
