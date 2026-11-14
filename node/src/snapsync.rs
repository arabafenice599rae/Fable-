//! Collecting a UTXO snapshot (spec 6): chunks of 4,096 entries, each checked against the
//! `utxo_root` of the snapshot block before it is kept.

use std::collections::{BTreeMap, HashMap};
use std::time::Instant;

use crate::consensus::*;
use std::result::Result;

pub struct SnapSync {
    /// The snapshot height (a multiple of 1,440) and the hash of the block there.
    pub height: u32,
    pub block: Hash,
    /// From that block's coinbase, once we have it.
    pub root: Option<Hash>,
    pub total: Option<u32>,
    chunks: BTreeMap<u32, Vec<(OutPoint, UtxoEntry)>>,
    pub requested: HashMap<u32, (u64, Instant)>,
    pub started: Instant,
    pub block_requested: Option<Instant>,
}

impl SnapSync {
    pub fn new(height: u32, block: Hash) -> Self {
        SnapSync {
            height,
            block,
            root: None,
            total: None,
            chunks: BTreeMap::new(),
            requested: HashMap::new(),
            started: Instant::now(),
            block_requested: None,
        }
    }

    pub fn chunk_count(&self) -> Option<u32> {
        self.total.map(|t| (t as usize).div_ceil(SNAPSHOT_CHUNK) as u32)
    }

    /// Chunks still to fetch. Before the first reply the total is unknown: chunk 0 tells it.
    pub fn missing(&self) -> Vec<u32> {
        match self.chunk_count() {
            None => vec![0],
            Some(n) => (0..n).filter(|k| !self.chunks.contains_key(k)).collect(),
        }
    }

    pub fn have(&self) -> usize {
        self.chunks.len()
    }

    /// Check one chunk and keep it.
    pub fn add_chunk(&mut self, chunk: u32, total: u32, entries: Vec<(OutPoint, UtxoEntry)>, proof: &[Hash]) -> Result<(), &'static str> {
        let root = self.root.ok_or("no root yet")?;
        if self.total.is_some_and(|t| t != total) {
            return Err("total changed");
        }
        if entries.windows(2).any(|w| w[0].0 >= w[1].0) {
            return Err("entries out of order");
        }
        let leaves: Vec<Hash> = entries.iter().map(|(k, e)| utxo_leaf(k, e)).collect();
        if chunk_root(&leaves, chunk as usize, total as usize, proof) != Some(root) {
            return Err("chunk does not match the utxo root");
        }
        self.total = Some(total);
        self.requested.remove(&chunk);
        self.chunks.insert(chunk, entries);
        Ok(())
    }

    /// The whole set, if every chunk is here.
    pub fn complete(&self) -> Option<Vec<(OutPoint, UtxoEntry)>> {
        if !self.missing().is_empty() {
            return None;
        }
        let all: Vec<(OutPoint, UtxoEntry)> = self.chunks.values().flatten().copied().collect();
        // each chunk is proven at its position, so the order across chunks holds too; check anyway
        if all.windows(2).any(|w| w[0].0 >= w[1].0) {
            return None;
        }
        Some(all)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assembles_several_chunks_and_refuses_bad_ones() {
        let set: UtxoSet = (0..10_000u32)
            .map(|i| {
                (
                    OutPoint { txid: sha256(&i.to_le_bytes()), index: (i % 4) as u8 },
                    UtxoEntry { amount: i as u64 + 1, addr: [i as u8; 32], height: i, coinbase: i % 3 == 0 },
                )
            })
            .collect();
        let entries: Vec<_> = set.iter().map(|(k, e)| (*k, *e)).collect();
        let leaves: Vec<Hash> = entries.iter().map(|(k, e)| utxo_leaf(k, e)).collect();
        let mut s = SnapSync::new(1440, [0; 32]);
        s.root = Some(utxo_root(&set));
        let total = entries.len() as u32;
        let chunk = |k: usize| entries[k * SNAPSHOT_CHUNK..((k + 1) * SNAPSHOT_CHUNK).min(entries.len())].to_vec();
        assert_eq!(s.missing(), vec![0]);
        // a chunk with one amount changed, or offered at another position, is refused
        let mut bad = chunk(1);
        bad[5].1.amount += 1;
        s.add_chunk(1, total, chunk(0), &chunk_proof(&leaves, 1)).unwrap_err();
        s.add_chunk(1, total, bad, &chunk_proof(&leaves, 1)).unwrap_err();
        for k in [2usize, 0, 1] {
            s.add_chunk(k as u32, total, chunk(k), &chunk_proof(&leaves, k)).unwrap();
        }
        assert_eq!(s.complete().unwrap(), entries);
    }
}
