//! Mempool and block template (spec 8, outside consensus; the defaults can be changed).
//!
//! - minimum relay fee 0.001 coin per signature, minimum output 0.001 coin;
//! - at most 5,000 signatures in total; when full, the lowest fee per signature leaves first;
//! - a transaction that spends what another one spends replaces it (with its descendants) only if
//!   it pays more in total and more per signature than every transaction it conflicts with;
//! - at most 64 unconfirmed transactions linked to each other (a "cluster").

use std::collections::{HashMap, HashSet};

use crate::consensus::*;

#[derive(Clone, Debug)]
pub struct Policy {
    pub min_fee_per_sig: u64,
    pub min_output: u64,
    pub max_sigs: usize,
    pub max_cluster: usize,
}

impl Default for Policy {
    fn default() -> Self {
        Policy { min_fee_per_sig: COIN / 1000, min_output: COIN / 1000, max_sigs: 5_000, max_cluster: 64 }
    }
}

#[derive(Clone, Debug)]
pub struct Entry {
    pub tx: Tx,
    pub txid: Hash,
    pub fee: u64,
    pub sigs: usize,
    pub size: usize,
    pub seq: u64,
    /// Unconfirmed transactions whose outputs this one spends.
    pub parents: HashSet<Hash>,
}

/// `a` pays strictly more per signature than `b`.
fn better(a: (u64, usize), b: (u64, usize)) -> bool {
    a.0 as u128 * b.1 as u128 > b.0 as u128 * a.1 as u128
}

#[derive(Default)]
pub struct Mempool {
    pub policy: Policy,
    pub txs: HashMap<Hash, Entry>,
    spends: HashMap<OutPoint, Hash>,
    children: HashMap<Hash, HashSet<Hash>>,
    pub sigs: usize,
    seq: u64,
    /// Leaves (txid and witnesses) whose signatures were already verified for this chain.
    verified: HashSet<Hash>,
}

impl Mempool {
    pub fn new(policy: Policy) -> Self {
        Mempool { policy, ..Default::default() }
    }

    pub fn len(&self) -> usize {
        self.txs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.txs.is_empty()
    }

    pub fn contains(&self, txid: &Hash) -> bool {
        self.txs.contains_key(txid)
    }

    /// An unspent output, confirmed or in the mempool: (entry, created by an unconfirmed tx).
    pub fn lookup(&self, chain: &Chain, op: &OutPoint) -> Option<(UtxoEntry, bool)> {
        if let Some(e) = self.txs.get(&op.txid) {
            let o = e.tx.outs.get(op.index as usize)?;
            return Some((UtxoEntry { amount: o.amount, addr: o.addr, height: chain.height + 1, coinbase: false }, true));
        }
        chain.utxo.get(op).map(|e| (*e, false))
    }

    pub fn spender(&self, op: &OutPoint) -> Option<Hash> {
        self.spends.get(op).copied()
    }

    fn descendants(&self, roots: impl IntoIterator<Item = Hash>) -> HashSet<Hash> {
        let mut out = HashSet::new();
        let mut stack: Vec<Hash> = roots.into_iter().collect();
        while let Some(x) = stack.pop() {
            if out.insert(x)
                && let Some(c) = self.children.get(&x)
            {
                stack.extend(c.iter().copied());
            }
        }
        out
    }

    fn cluster(&self, start: impl IntoIterator<Item = Hash>, skip: &HashSet<Hash>) -> HashSet<Hash> {
        let mut out = HashSet::new();
        let mut stack: Vec<Hash> = start.into_iter().collect();
        while let Some(x) = stack.pop() {
            if skip.contains(&x) || !out.insert(x) {
                continue;
            }
            let e = &self.txs[&x];
            stack.extend(e.parents.iter().copied());
            if let Some(c) = self.children.get(&x) {
                stack.extend(c.iter().copied());
            }
        }
        out
    }

    /// Validate a transaction against the tip and the mempool, then add it.
    pub fn accept(&mut self, tx: Tx, chain: &Chain) -> std::result::Result<Hash, String> {
        let txid = tx.txid();
        if self.txs.contains_key(&txid) {
            return Err("already in mempool".into());
        }
        if tx.outs.iter().any(|o| o.amount < self.policy.min_output) {
            return Err("output below the relay minimum".into());
        }
        let h = chain.height + 1;
        let (mut total_in, mut addrs, mut parents, mut conflicts) = (0u128, Vec::new(), HashSet::new(), HashSet::new());
        for op in &tx.ins {
            let Some((e, unconfirmed)) = self.lookup(chain, op) else { return Err("missing input".into()) };
            if e.coinbase && (h as u64) < e.height as u64 + MATURITY as u64 {
                return Err("immature coinbase".into());
            }
            if unconfirmed {
                parents.insert(op.txid);
            }
            if let Some(s) = self.spends.get(op) {
                conflicts.insert(*s);
            }
            total_in += e.amount as u128;
            addrs.push(e.addr);
        }
        let mut want: Vec<Hash> = Vec::new();
        for a in addrs {
            if !want.contains(&a) {
                want.push(a);
            }
        }
        if tx.wits.iter().map(|w| address(&w.pk)).collect::<Vec<_>>() != want {
            return Err("witnesses do not match the input addresses".into());
        }
        let total_out: u128 = tx.outs.iter().map(|o| o.amount as u128).sum();
        if total_out > total_in {
            return Err("outputs exceed inputs".into());
        }
        let fee = (total_in - total_out) as u64;
        let sigs = tx.wits.len();
        if (fee as u128) < self.policy.min_fee_per_sig as u128 * sigs as u128 {
            return Err("fee below the relay minimum".into());
        }
        let replaced = self.descendants(conflicts.iter().copied());
        if !replaced.is_empty() {
            if parents.iter().any(|p| replaced.contains(p)) {
                return Err("spends a transaction it replaces".into());
            }
            let old_fee: u128 = replaced.iter().map(|x| self.txs[x].fee as u128).sum();
            if fee as u128 <= old_fee {
                return Err("replacement must pay more than what it replaces".into());
            }
            if conflicts.iter().any(|c| !better((fee, sigs), (self.txs[c].fee, self.txs[c].sigs))) {
                return Err("replacement must pay more per signature".into());
            }
        }
        if self.cluster(parents.iter().copied(), &replaced).len() + 1 > self.policy.max_cluster {
            return Err("too many linked unconfirmed transactions".into());
        }
        let freed: usize = replaced.iter().map(|x| self.txs[x].sigs).sum();
        if self.sigs - freed + sigs > self.policy.max_sigs {
            let worst = self.txs.values().filter(|e| !replaced.contains(&e.txid)).min_by(|a, b| {
                if better((a.fee, a.sigs), (b.fee, b.sigs)) { std::cmp::Ordering::Greater } else { std::cmp::Ordering::Less }
            });
            if worst.is_some_and(|w| !better((fee, sigs), (w.fee, w.sigs))) {
                return Err("mempool full".into());
            }
        }
        let leaf = tx.leaf();
        if !self.verified.contains(&leaf) {
            let msg = tx.sighash(&chain.net.chain_id);
            let jobs: Vec<(&[u8], Hash, &[u8])> = tx.wits.iter().map(|w| (&w.pk[..], msg, &w.sig[..])).collect();
            if first_bad_sig(&jobs).is_some() {
                return Err("bad signature".into());
            }
            if self.verified.len() > 50_000 {
                self.verified.clear();
            }
            self.verified.insert(leaf);
        }
        for x in replaced {
            self.remove_one(&x);
        }
        self.insert(tx, txid, fee, parents);
        while self.sigs > self.policy.max_sigs {
            let worst = self.txs.values().min_by(|a, b| {
                if better((a.fee, a.sigs), (b.fee, b.sigs)) { std::cmp::Ordering::Greater } else { std::cmp::Ordering::Less }
            });
            let w = worst.unwrap().txid;
            self.remove_with_descendants(&w);
        }
        if !self.txs.contains_key(&txid) {
            return Err("mempool full".into());
        }
        Ok(txid)
    }

    fn insert(&mut self, tx: Tx, txid: Hash, fee: u64, parents: HashSet<Hash>) {
        for op in &tx.ins {
            self.spends.insert(*op, txid);
        }
        for p in &parents {
            self.children.entry(*p).or_default().insert(txid);
        }
        self.sigs += tx.wits.len();
        self.seq += 1;
        let size = tx.serialize().len();
        let sigs = tx.wits.len();
        self.txs.insert(txid, Entry { tx, txid, fee, sigs, size, seq: self.seq, parents });
    }

    fn remove_one(&mut self, txid: &Hash) -> Option<Entry> {
        let e = self.txs.remove(txid)?;
        for op in &e.tx.ins {
            if self.spends.get(op) == Some(txid) {
                self.spends.remove(op);
            }
        }
        for p in &e.parents {
            if let Some(c) = self.children.get_mut(p) {
                c.remove(txid);
            }
        }
        self.children.remove(txid);
        self.sigs -= e.sigs;
        Some(e)
    }

    pub fn remove_with_descendants(&mut self, txid: &Hash) {
        for x in self.descendants([*txid]) {
            self.remove_one(&x);
        }
    }

    /// A block was connected: drop what it confirmed and whatever now conflicts with it.
    pub fn block_connected(&mut self, blk: &Block) {
        for tx in &blk.txs {
            let id = tx.txid();
            if let Some(e) = self.remove_one(&id) {
                // its children now spend a confirmed output
                for c in self.txs.values_mut() {
                    c.parents.remove(&e.txid);
                }
            }
            for op in &tx.ins {
                if let Some(other) = self.spends.get(op).copied() {
                    self.remove_with_descendants(&other);
                }
            }
        }
    }

    /// After a reorganisation: everything is checked again against the new tip, the transactions
    /// of the disconnected blocks first.
    pub fn rebuild(&mut self, disconnected: &[Block], chain: &Chain) {
        let mut old: Vec<Entry> = self.txs.drain().map(|(_, e)| e).collect();
        old.sort_by_key(|e| e.seq);
        self.spends.clear();
        self.children.clear();
        self.sigs = 0;
        for tx in disconnected.iter().flat_map(|b| b.txs.iter()).cloned().chain(old.into_iter().map(|e| e.tx)) {
            let _ = self.accept(tx, chain);
        }
    }

    pub fn apply_changes(&mut self, ch: &crate::chainstate::Changes, chain: &Chain) {
        if ch.disconnected.is_empty() {
            for b in &ch.connected {
                self.block_connected(b);
            }
        } else {
            self.rebuild(&ch.disconnected, chain);
        }
    }

    /// Transactions for the next block: highest fee per signature first, parents before
    /// children, at most `max_sigs` witnesses. Returns the transactions and their total fee.
    pub fn select(&self, max_sigs: usize) -> (Vec<Tx>, u64) {
        let mut chosen: Vec<Hash> = Vec::new();
        let mut in_block: HashSet<Hash> = HashSet::new();
        let (mut used, mut fees) = (0usize, 0u64);
        loop {
            let pick = self
                .txs
                .values()
                .filter(|e| !in_block.contains(&e.txid) && used + e.sigs <= max_sigs && e.parents.iter().all(|p| in_block.contains(p)))
                .max_by(|a, b| {
                    if better((a.fee, a.sigs), (b.fee, b.sigs)) {
                        std::cmp::Ordering::Greater
                    } else if better((b.fee, b.sigs), (a.fee, a.sigs)) {
                        std::cmp::Ordering::Less
                    } else {
                        b.seq.cmp(&a.seq)
                    }
                });
            let Some(e) = pick else { break };
            in_block.insert(e.txid);
            chosen.push(e.txid);
            used += e.sigs;
            fees += e.fee;
        }
        (chosen.iter().map(|h| self.txs[h].tx.clone()).collect(), fees)
    }
}
