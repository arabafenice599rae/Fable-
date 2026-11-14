//! Block templates and a CPU miner (for the test network and for tests).

use crate::chainstate::ChainState;
use crate::consensus::*;
use crate::mempool::Mempool;

#[derive(Clone, Debug)]
pub struct Template {
    pub height: u32,
    pub prev: Hash,
    pub bits: u32,
    pub time: i64,
    pub utxo_root: Hash,
    pub outs: Vec<Output>,
    pub txs: Vec<Tx>,
    pub fees: u64,
}

impl Template {
    /// Leaves after the coinbase, which is what the Stratum merkle branch is built from.
    pub fn tx_leaves(&self) -> Vec<Hash> {
        self.txs.iter().map(Tx::leaf).collect()
    }

    pub fn coinbase(&self, extra: [u8; 8]) -> Coinbase {
        Coinbase { height: self.height, extra, utxo_root: self.utxo_root, outs: self.outs.clone() }
    }

    /// Coinbase bytes before and after the 8-byte `extra`: Stratum's coinb1 and coinb2.
    pub fn coinb1(&self) -> Vec<u8> {
        self.height.to_le_bytes().to_vec()
    }

    pub fn coinb2(&self) -> Vec<u8> {
        let mut b = self.utxo_root.to_vec();
        ser_outputs(&self.outs, &mut b);
        b
    }

    pub fn block(&self, version: u32, extra: [u8; 8], time32: u32, nonce: u32) -> Block {
        let coinbase = self.coinbase(extra);
        let mut leaves = vec![coinbase.txid()];
        leaves.extend(self.tx_leaves());
        let header = Header { version, prev: self.prev, merkle: merkle_root(&leaves), time32, bits: self.bits, nonce };
        Block { header, coinbase, txs: self.txs.clone() }
    }
}

/// Template on top of the active tip, paying subsidy and fees to `payout`.
pub fn template(cs: &ChainState, pool: &Mempool, payout: Hash, now: i64) -> Template {
    let st = &cs.state;
    let height = st.height + 1;
    let (txs, fees) = pool.select(MAX_SIGS);
    let utxo_root = st.next_utxo_root();
    Template {
        height,
        prev: st.tip,
        bits: st.next_bits(),
        time: now.max(st.time + 1),
        utxo_root,
        outs: vec![Output { amount: subsidy(height as u64) + fees, addr: payout }],
        txs,
        fees,
    }
}

/// Try nonces (and then `extra`) until the header meets the target.
pub fn mine(t: &Template, max_tries: u64) -> Option<Block> {
    let target = bits_to_target(t.bits).ok()?;
    let mut tries = 0u64;
    for extra in 0u64.. {
        let mut blk = t.block(0x2000_0000, extra.to_le_bytes(), t.time as u32, 0);
        for nonce in 0..=u32::MAX {
            blk.header.nonce = nonce;
            if meets_target(&blk.header.hash(), &target) {
                return Some(blk);
            }
            tries += 1;
            if tries >= max_tries {
                return None;
            }
        }
    }
    None
}
