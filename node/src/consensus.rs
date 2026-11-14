//! Consensus rules, spec v0.13. A line-by-line port of `fable.py`.
//!
//! Every check happens in the same order as in the reference and fails with the same short
//! code, so `verdict()` gives exactly the strings `fable.py` gives.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;

use num_bigint::BigUint;
use num_traits::{One, Zero};
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------- constants
pub const TX: u8 = 1;
pub const SIG: u8 = 2;
pub const LEAF: u8 = 3;
pub const WIT: u8 = 4;
pub const ADDR: u8 = 5;
pub const UTXO: u8 = 6;
pub const COIN: u64 = 100_000_000;
pub const MAX_AMOUNT: u64 = 1 << 62;
pub const BLOCK_TIME: i64 = 60;
pub const HALFLIFE: i64 = 3600;
pub const FUTURE_LIMIT: i64 = 600;
pub const QUARTER: u64 = 131_400;
pub const SLOW_START: u64 = 43_200;
pub const MATURITY: u32 = 100;
pub const SNAPSHOT_EVERY: u32 = 1_440;
pub const SNAPSHOT_CHUNK: usize = 4_096;
/// Witnesses per block, coinbase excluded: 80 at first, +40% every 2,102,400 blocks, up to 2,048.
pub const SIGS_START: usize = 80;
pub const SIGS_STEP: u64 = 2_102_400;
pub const SIGS_CAP: usize = 2_048;
pub const MAX_IN: usize = 32;
pub const MAX_OUT: usize = 16;
pub const MAX_WIT: usize = 4;
pub const MAX_CB_OUT: usize = 2;
pub const PK_LEN: usize = 32;
pub const SIG_LEN: usize = 7_856;
pub const ZERO32: Hash = [0; 32];

pub type Hash = [u8; 32];

/// A consensus rule was broken. The code is the same short string `fable.py` uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Invalid(pub &'static str);

impl fmt::Display for Invalid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for Invalid {}

pub type Result<T> = std::result::Result<T, Invalid>;

fn bad<T>(code: &'static str) -> Result<T> {
    Err(Invalid(code))
}

pub fn sha256(b: &[u8]) -> Hash {
    Sha256::digest(b).into()
}

pub fn sha256d(b: &[u8]) -> Hash {
    sha256(&sha256(b))
}

/// `H(tag, x) = SHA-256(byte(tag) ‖ x)`, with x given in parts.
pub fn tagged(tag: u8, parts: &[&[u8]]) -> Hash {
    let mut h = Sha256::new();
    h.update([tag]);
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

pub fn h(tag: u8, b: &[u8]) -> Hash {
    tagged(tag, &[b])
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok()).collect()
}

pub fn unhex32(s: &str) -> Option<Hash> {
    unhex(s)?.try_into().ok()
}

/// Block hashes are shown the way Bitcoin shows them: byte-reversed.
pub fn display_hash(h: &Hash) -> String {
    let mut r = *h;
    r.reverse();
    hex(&r)
}

// ---------------------------------------------------------------- headers and networks
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub version: u32,
    pub prev: Hash,
    pub merkle: Hash,
    pub time32: u32,
    pub bits: u32,
    pub nonce: u32,
}

impl Header {
    pub fn serialize(&self) -> [u8; 80] {
        let mut b = [0u8; 80];
        b[0..4].copy_from_slice(&self.version.to_le_bytes());
        b[4..36].copy_from_slice(&self.prev);
        b[36..68].copy_from_slice(&self.merkle);
        b[68..72].copy_from_slice(&self.time32.to_le_bytes());
        b[72..76].copy_from_slice(&self.bits.to_le_bytes());
        b[76..80].copy_from_slice(&self.nonce.to_le_bytes());
        b
    }

    pub fn parse(b: &[u8]) -> Header {
        let u = |o: usize| u32::from_le_bytes(b[o..o + 4].try_into().unwrap());
        Header {
            version: u(0),
            prev: b[4..36].try_into().unwrap(),
            merkle: b[36..68].try_into().unwrap(),
            time32: u(68),
            bits: u(72),
            nonce: u(76),
        }
    }

    pub fn hash(&self) -> Hash {
        sha256d(&self.serialize())
    }
}

#[derive(Clone, Debug)]
pub struct Net {
    pub name: String,
    pub genesis: Header,
    pub genesis_time: i64,
    pub genesis_bits: u32,
    pub max_bits: u32,
    pub chain_id: Hash,
}

impl Net {
    pub fn new(name: &str, genesis_time: i64, genesis_bits: u32, max_bits: u32, genesis_prev: Hash) -> Net {
        let genesis = Header { version: 1, prev: genesis_prev, merkle: ZERO32, time32: genesis_time as u32, bits: genesis_bits, nonce: 0 };
        let chain_id = genesis.hash();
        Net { name: name.into(), genesis, genesis_time, genesis_bits, max_bits, chain_id }
    }

    /// MAIN: `genesis_prev` is a placeholder. On launch day it becomes the hash of a recent Bitcoin block.
    pub fn main() -> Net {
        Net::new("main", 1_794_441_600, 0x1B04_0000, 0x1D00_FFFF, ZERO32)
    }

    /// TEST: same rules, trivial difficulty, so a chain can be mined on a laptop.
    pub fn test() -> Net {
        Net::new("test", 1_794_441_600, 0x207F_FFFF, 0x207F_FFFF, ZERO32)
    }

    /// LAB (as in `stratum.py`): mainnet difficulty, throwaway genesis stamped at first start.
    pub fn lab(genesis_time: i64) -> Net {
        Net::new("lab", genesis_time, 0x1B04_0000, 0x1D00_FFFF, ZERO32)
    }

    pub fn genesis_hash(&self) -> Hash {
        self.genesis.hash()
    }
}

// ---------------------------------------------------------------- compact targets
pub fn bits_to_target(bits: u32) -> Result<BigUint> {
    let exp = bits >> 24;
    let mant = BigUint::from(bits & 0x007F_FFFF);
    if bits & 0x0080_0000 != 0 {
        return bad("bits");
    }
    Ok(if exp <= 3 { mant >> (8 * (3 - exp)) } else { mant << (8 * (exp - 3)) })
}

pub fn target_to_bits(target: &BigUint) -> u32 {
    let mut size = target.bits().div_ceil(8);
    let mut c: u64 =
        if size <= 3 { (target << (8 * (3 - size))).try_into().unwrap() } else { (target >> (8 * (size - 3))).try_into().unwrap() };
    if c & 0x0080_0000 != 0 {
        c >>= 8;
        size += 1;
    }
    (c | (size << 24)) as u32
}

/// Work of one block: `2^256 / (target + 1)`.
pub fn work(bits: u32) -> BigUint {
    let target = bits_to_target(bits).unwrap_or_default();
    (BigUint::one() << 256u32) / (target + 1u32)
}

/// Block hash read as a little-endian integer, compared with the target.
pub fn meets_target(hash: &Hash, target: &BigUint) -> bool {
    BigUint::from_bytes_le(hash) <= *target
}

// ---------------------------------------------------------------- difficulty (aserti3-2d, anchored at genesis)
/// Compact target required of the block that follows the given parent.
pub fn asert_bits(net: &Net, parent_height: u64, parent_time: i64) -> u32 {
    let anchor = bits_to_target(net.genesis_bits).unwrap();
    let max_target = bits_to_target(net.max_bits).unwrap();
    let time_delta = parent_time as i128 - (net.genesis_time as i128 - BLOCK_TIME as i128);
    let num = (time_delta - BLOCK_TIME as i128 * (parent_height as i128 + 1)) * 65536;
    let mut exponent = num / HALFLIFE as i128; // truncates toward zero
    let shifts = exponent >> 16; // arithmetic shift
    exponent -= shifts * 65536;
    if shifts > 300 {
        return net.max_bits;
    }
    if shifts < -300 {
        return target_to_bits(&BigUint::one());
    }
    let e = exponent as u128; // 0..=65535
    let factor = ((195_766_423_245_049u128 * e + 971_821_376u128 * e * e + 5127u128 * e * e * e + (1u128 << 47)) >> 48) + 65536;
    let mut nt = anchor * BigUint::from(factor);
    nt = if shifts >= 0 { nt << (shifts as u32) } else { nt >> ((-shifts) as u32) };
    nt >>= 16u32;
    if nt.is_zero() {
        return target_to_bits(&BigUint::one());
    }
    if nt > max_target {
        return net.max_bits;
    }
    target_to_bits(&nt)
}

// ---------------------------------------------------------------- emission
pub fn subsidy(height: u64) -> u64 {
    let mut r = 50 * COIN;
    for _ in 0..height / QUARTER {
        r -= r >> 4;
        if r < COIN {
            r = COIN;
            break;
        }
    }
    if height < SLOW_START {
        r = r * height / SLOW_START;
    }
    r
}

/// Witnesses allowed in the block at this height, coinbase excluded.
pub fn max_sigs(height: u64) -> usize {
    let mut s = SIGS_START;
    for _ in 0..height / SIGS_STEP {
        s += s * 2 / 5;
        if s >= SIGS_CAP {
            return SIGS_CAP;
        }
    }
    s
}

/// Largest transaction bytes one witness can carry: 32 inputs, 16 outputs, one witness.
pub const MAX_TX_BYTES_PER_SIG: usize = 3 + 33 * MAX_IN + 40 * MAX_OUT + PK_LEN + SIG_LEN;
/// Header, the largest coinbase (two outputs) and the 2-byte transaction counter.
pub const BLOCK_OVERHEAD: usize = 80 + 4 + 8 + 32 + 1 + 40 * MAX_CB_OUT + 2;

/// Largest valid block at this height. A transaction with w witnesses is at most
/// w × MAX_TX_BYTES_PER_SIG bytes, so the witness limit bounds the block.
pub fn max_block_size(height: u64) -> usize {
    BLOCK_OVERHEAD + max_sigs(height) * MAX_TX_BYTES_PER_SIG
}

// ---------------------------------------------------------------- time
/// The header carries the low 32 bits. The full value is the smallest one after the parent.
pub fn full_time(prev_time: i64, time32: u32) -> i64 {
    let mut t = (prev_time & !0xFFFF_FFFF) | time32 as i64;
    if t <= prev_time {
        t += 1 << 32;
    }
    t
}

// ---------------------------------------------------------------- merkle
fn merkle_level(level: &[Hash]) -> Vec<Hash> {
    let mut next: Vec<Hash> = level
        .chunks_exact(2)
        .map(|p| {
            let mut b = [0u8; 64];
            b[..32].copy_from_slice(&p[0]);
            b[32..].copy_from_slice(&p[1]);
            sha256d(&b)
        })
        .collect();
    if level.len() % 2 == 1 {
        next.push(level[level.len() - 1]); // an unpaired node moves up unchanged
    }
    next
}

pub fn merkle_root(leaves: &[Hash]) -> Hash {
    if leaves.is_empty() {
        return ZERO32;
    }
    let mut level = leaves.to_vec();
    while level.len() > 1 {
        level = merkle_level(&level);
    }
    level[0]
}

/// Siblings on the path from leaf 0 to the root: what a Stratum miner folds in.
pub fn coinbase_branch(leaves: &[Hash]) -> Vec<Hash> {
    let mut out = Vec::new();
    let mut level = leaves.to_vec();
    while level.len() > 1 {
        out.push(level[1]);
        level = merkle_level(&level);
    }
    out
}

pub fn fold(a: &Hash, b: &Hash) -> Hash {
    let mut x = [0u8; 64];
    x[..32].copy_from_slice(a);
    x[32..].copy_from_slice(b);
    sha256d(&x)
}

// ---------------------------------------------------------------- parsing
pub struct Reader<'a> {
    pub b: &'a [u8],
    pub o: usize,
}

impl<'a> Reader<'a> {
    pub fn new(b: &'a [u8]) -> Self {
        Reader { b, o: 0 }
    }

    pub fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.o + n > self.b.len() {
            return bad("parse");
        }
        let v = &self.b[self.o..self.o + n];
        self.o += n;
        Ok(v)
    }

    pub fn arr<const N: usize>(&mut self) -> Result<[u8; N]> {
        Ok(self.take(N)?.try_into().unwrap())
    }

    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    pub fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.arr()?))
    }

    pub fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.arr()?))
    }

    pub fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.arr()?))
    }

    pub fn done(&self) -> bool {
        self.o == self.b.len()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct OutPoint {
    pub txid: Hash,
    pub index: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Output {
    pub amount: u64,
    pub addr: Hash,
}

fn read_outputs(r: &mut Reader, limit: usize) -> Result<Vec<Output>> {
    let n = r.u8()? as usize;
    if !(1..=limit).contains(&n) {
        return bad("parse");
    }
    let mut outs = Vec::with_capacity(n);
    for _ in 0..n {
        let amount = r.u64()?;
        let addr = r.arr()?;
        if !(1..=MAX_AMOUNT).contains(&amount) {
            return bad("parse");
        }
        outs.push(Output { amount, addr });
    }
    Ok(outs)
}

pub fn ser_outputs(outs: &[Output], b: &mut Vec<u8>) {
    b.push(outs.len() as u8);
    for o in outs {
        b.extend_from_slice(&o.amount.to_le_bytes());
        b.extend_from_slice(&o.addr);
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Witness {
    pub pk: [u8; PK_LEN],
    pub sig: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tx {
    pub ins: Vec<OutPoint>,
    pub outs: Vec<Output>,
    pub wits: Vec<Witness>,
}

impl Tx {
    pub fn body(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(2 + 33 * self.ins.len() + 40 * self.outs.len());
        b.push(self.ins.len() as u8);
        for i in &self.ins {
            b.extend_from_slice(&i.txid);
            b.push(i.index);
        }
        ser_outputs(&self.outs, &mut b);
        b
    }

    pub fn witness(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(1 + (PK_LEN + SIG_LEN) * self.wits.len());
        b.push(self.wits.len() as u8);
        for w in &self.wits {
            b.extend_from_slice(&w.pk);
            b.extend_from_slice(&w.sig);
        }
        b
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut b = self.body();
        b.extend(self.witness());
        b
    }

    pub fn txid(&self) -> Hash {
        h(TX, &self.body())
    }

    pub fn sighash(&self, chain_id: &Hash) -> Hash {
        tagged(SIG, &[chain_id, &self.body()])
    }

    pub fn leaf(&self) -> Hash {
        let wid = h(WIT, &self.witness());
        tagged(LEAF, &[&self.txid(), &wid])
    }

    /// Parse one transaction that must fill `raw` exactly.
    pub fn parse(raw: &[u8]) -> Result<Tx> {
        let mut r = Reader::new(raw);
        let tx = read_tx(&mut r)?;
        if !r.done() {
            return bad("parse");
        }
        Ok(tx)
    }
}

pub fn read_tx(r: &mut Reader) -> Result<Tx> {
    let n_in = r.u8()? as usize;
    if !(1..=MAX_IN).contains(&n_in) {
        return bad("parse");
    }
    let mut ins = Vec::with_capacity(n_in);
    for _ in 0..n_in {
        let txid = r.arr()?;
        let index = r.u8()?;
        if index as usize >= MAX_OUT {
            return bad("parse");
        }
        ins.push(OutPoint { txid, index });
    }
    if ins.iter().collect::<HashSet<_>>().len() != n_in {
        return bad("parse");
    }
    let outs = read_outputs(r, MAX_OUT)?;
    let n_wit = r.u8()? as usize;
    if !(1..=MAX_WIT.min(n_in)).contains(&n_wit) {
        return bad("parse");
    }
    let mut wits = Vec::with_capacity(n_wit);
    for _ in 0..n_wit {
        let pk = r.arr()?;
        let sig = r.take(SIG_LEN)?.to_vec();
        wits.push(Witness { pk, sig });
    }
    Ok(Tx { ins, outs, wits })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Coinbase {
    pub height: u32,
    pub extra: [u8; 8],
    pub utxo_root: Hash,
    pub outs: Vec<Output>,
}

impl Coinbase {
    pub fn serialize(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(45 + 40 * self.outs.len());
        b.extend_from_slice(&self.height.to_le_bytes());
        b.extend_from_slice(&self.extra);
        b.extend_from_slice(&self.utxo_root);
        ser_outputs(&self.outs, &mut b);
        b
    }

    pub fn txid(&self) -> Hash {
        sha256d(&self.serialize())
    }
}

fn read_coinbase(r: &mut Reader) -> Result<Coinbase> {
    Ok(Coinbase { height: r.u32()?, extra: r.arr()?, utxo_root: r.arr()?, outs: read_outputs(r, MAX_CB_OUT)? })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Block {
    pub header: Header,
    pub coinbase: Coinbase,
    pub txs: Vec<Tx>,
}

impl Block {
    pub fn serialize(&self) -> Vec<u8> {
        let mut b = self.header.serialize().to_vec();
        b.extend(self.coinbase.serialize());
        b.extend_from_slice(&(self.txs.len() as u16).to_le_bytes());
        for t in &self.txs {
            b.extend(t.serialize());
        }
        b
    }

    pub fn leaves(&self) -> Vec<Hash> {
        let mut v = vec![self.coinbase.txid()];
        v.extend(self.txs.iter().map(Tx::leaf));
        v
    }

    pub fn hash(&self) -> Hash {
        self.header.hash()
    }
}

pub fn read_block(buf: &[u8]) -> Result<Block> {
    let mut r = Reader::new(buf);
    let header = Header::parse(r.take(80)?);
    let coinbase = read_coinbase(&mut r)?;
    let n = r.u16()? as usize;
    if n > SIGS_CAP {
        return bad("parse");
    }
    let mut txs = Vec::with_capacity(n);
    for _ in 0..n {
        txs.push(read_tx(&mut r)?);
    }
    if !r.done() {
        return bad("parse");
    }
    Ok(Block { header, coinbase, txs })
}

// ---------------------------------------------------------------- signatures and addresses
pub fn address(pk: &[u8]) -> Hash {
    h(ADDR, pk)
}

/// SLH-DSA-SHA2-128s, pure interface, empty context. Anything malformed is simply invalid.
pub fn verify_sig(pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    use slh_dsa::signature::Verifier;
    use slh_dsa::{Sha2_128s, Signature, VerifyingKey};
    let Ok(vk) = VerifyingKey::<Sha2_128s>::try_from(pk) else { return false };
    let Ok(s) = Signature::<Sha2_128s>::try_from(sig) else { return false };
    vk.verify(msg, &s).is_ok()
}

/// Verifies every (pk, msg, sig) and returns the index of the first failure, if any.
/// Work is spread over the available cores; the answer does not depend on how.
pub fn first_bad_sig(jobs: &[(&[u8], Hash, &[u8])]) -> Option<usize> {
    let threads = std::thread::available_parallelism().map_or(1, |n| n.get()).min(jobs.len().max(1));
    if threads <= 1 || jobs.len() < 2 {
        return jobs.iter().position(|(pk, m, s)| !verify_sig(pk, m, s));
    }
    let next = std::sync::atomic::AtomicUsize::new(0);
    let results: Vec<std::sync::atomic::AtomicBool> = (0..jobs.len()).map(|_| std::sync::atomic::AtomicBool::new(true)).collect();
    std::thread::scope(|s| {
        for _ in 0..threads {
            s.spawn(|| {
                loop {
                    let i = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    if i >= jobs.len() {
                        break;
                    }
                    let (pk, m, sig) = jobs[i];
                    results[i].store(verify_sig(pk, &m, sig), std::sync::atomic::Ordering::Relaxed);
                }
            });
        }
    });
    results.iter().position(|r| !r.load(std::sync::atomic::Ordering::Relaxed))
}

// ---------------------------------------------------------------- state
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UtxoEntry {
    pub amount: u64,
    pub addr: Hash,
    pub height: u32,
    pub coinbase: bool,
}

pub const UTXO_ENTRY_LEN: usize = 78;

pub fn utxo_entry(op: &OutPoint, e: &UtxoEntry) -> [u8; UTXO_ENTRY_LEN] {
    let mut b = [0u8; UTXO_ENTRY_LEN];
    b[0..32].copy_from_slice(&op.txid);
    b[32] = op.index;
    b[33..41].copy_from_slice(&e.amount.to_le_bytes());
    b[41..73].copy_from_slice(&e.addr);
    b[73..77].copy_from_slice(&e.height.to_le_bytes());
    b[77] = e.coinbase as u8;
    b
}

pub fn parse_utxo_entry(b: &[u8]) -> Option<(OutPoint, UtxoEntry)> {
    if b.len() != UTXO_ENTRY_LEN || b[77] > 1 {
        return None;
    }
    Some((
        OutPoint { txid: b[0..32].try_into().unwrap(), index: b[32] },
        UtxoEntry {
            amount: u64::from_le_bytes(b[33..41].try_into().unwrap()),
            addr: b[41..73].try_into().unwrap(),
            height: u32::from_le_bytes(b[73..77].try_into().unwrap()),
            coinbase: b[77] == 1,
        },
    ))
}

pub fn utxo_leaf(op: &OutPoint, e: &UtxoEntry) -> Hash {
    h(UTXO, &utxo_entry(op, e))
}

pub type UtxoSet = BTreeMap<OutPoint, UtxoEntry>;

/// The BTreeMap is ordered by (txid, index) in bytes, which is the order the root needs.
pub fn utxo_root(utxo: &UtxoSet) -> Hash {
    let leaves: Vec<Hash> = utxo.iter().map(|(k, e)| utxo_leaf(k, e)).collect();
    merkle_root(&leaves)
}

/// What a valid block does to the state: built by `Chain::check`, used by `Chain::apply`.
#[derive(Clone, Debug)]
pub struct Checked {
    pub block: Block,
    pub hash: Hash,
    pub time: i64,
    pub height: u32,
    pub fees: u64,
    /// Outputs the block creates, in order, including those it also spends.
    pub created: Vec<(OutPoint, UtxoEntry)>,
    /// Outpoints the block spends, in order.
    pub spent: Vec<OutPoint>,
}

/// What it takes to disconnect a block again.
#[derive(Clone, Debug, Default)]
pub struct Undo {
    /// Entries the block removed from the state before it.
    pub removed: Vec<(OutPoint, UtxoEntry)>,
    /// Outpoints the block added to the state.
    pub added: Vec<OutPoint>,
    pub prev_time: i64,
}

/// The tip of one chain and its unspent outputs. Blocks are applied in order.
#[derive(Clone)]
pub struct Chain {
    pub net: Net,
    pub height: u32,
    pub tip: Hash,
    pub time: i64,
    pub utxo: UtxoSet,
}

impl Chain {
    pub fn new(net: Net) -> Chain {
        Chain { height: 0, tip: net.genesis_hash(), time: net.genesis_time, utxo: UtxoSet::new(), net }
    }

    pub fn next_bits(&self) -> u32 {
        asert_bits(&self.net, self.height as u64, self.time)
    }

    pub fn is_snapshot_height(h: u32) -> bool {
        h.is_multiple_of(SNAPSHOT_EVERY)
    }

    pub fn next_utxo_root(&self) -> Hash {
        if Self::is_snapshot_height(self.height + 1) { utxo_root(&self.utxo) } else { ZERO32 }
    }

    /// Validate a block against the tip. Returns what `apply()` needs.
    pub fn check(&self, raw: &[u8], now: i64) -> Result<Checked> {
        self.check_with(raw, now, true)
    }

    /// As `check`, optionally skipping signature verification (for blocks this node already validated).
    pub fn check_with(&self, raw: &[u8], now: i64, verify_sigs: bool) -> Result<Checked> {
        let blk = read_block(raw)?;
        let utxo_root = if Self::is_snapshot_height(self.height + 1) { None } else { Some(ZERO32) };
        self.check_block(blk, now, verify_sigs, utxo_root)
    }

    /// `expected_root`: None means compute it from the current set, as the reference does.
    pub fn check_block(&self, blk: Block, now: i64, verify_sigs: bool, expected_root: Option<Hash>) -> Result<Checked> {
        let h = self.height + 1;
        let hd = &blk.header;
        if hd.prev != self.tip {
            return bad("prev");
        }
        let t = full_time(self.time, hd.time32);
        if t > now.saturating_add(FUTURE_LIMIT) {
            return bad("time");
        }
        if hd.bits != self.next_bits() {
            return bad("bits");
        }
        let block_hash = hd.hash();
        if !meets_target(&block_hash, &bits_to_target(hd.bits)?) {
            return bad("pow");
        }
        if hd.merkle != merkle_root(&blk.leaves()) {
            return bad("merkle");
        }
        if blk.coinbase.height != h {
            return bad("cbheight");
        }
        let want_root = match expected_root {
            Some(r) => r,
            None => utxo_root(&self.utxo),
        };
        if blk.coinbase.utxo_root != want_root {
            return bad("utxoroot");
        }
        if blk.txs.iter().map(|t| t.wits.len()).sum::<usize>() > max_sigs(h as u64) {
            return bad("sigs");
        }

        // Signatures are collected and checked together at the end, in parallel. To keep the
        // reference's error codes, a failure found later in the loop is reported only if every
        // signature the reference would have checked before reaching it is valid.
        let msgs: Vec<Hash> = blk.txs.iter().map(|tx| tx.sighash(&self.net.chain_id)).collect();
        let mut jobs: Vec<(&[u8], Hash, &[u8])> = Vec::new();
        let mut failure: Option<Invalid> = None;

        let mut view: HashMap<OutPoint, UtxoEntry> = HashMap::new(); // created inside this block
        let mut created: Vec<(OutPoint, UtxoEntry)> = Vec::new();
        let mut spent_set: HashSet<OutPoint> = HashSet::new();
        let mut spent: Vec<OutPoint> = Vec::new();
        let mut fees: u128 = 0;
        'txs: for (ti, tx) in blk.txs.iter().enumerate() {
            let mut total_in: u128 = 0;
            let mut addrs: Vec<Hash> = Vec::new();
            for op in &tx.ins {
                if spent_set.contains(op) {
                    failure = Some(Invalid("missing"));
                    break 'txs;
                }
                let Some(e) = view.get(op).or_else(|| self.utxo.get(op)) else {
                    failure = Some(Invalid("missing"));
                    break 'txs;
                };
                if e.coinbase && (h as u64) < e.height as u64 + MATURITY as u64 {
                    failure = Some(Invalid("immature"));
                    break 'txs;
                }
                total_in += e.amount as u128;
                addrs.push(e.addr);
            }
            // one witness per distinct input address, in the order the addresses first appear
            let mut want: Vec<Hash> = Vec::new();
            for a in addrs {
                if !want.contains(&a) {
                    want.push(a);
                }
            }
            let got: Vec<Hash> = tx.wits.iter().map(|w| address(&w.pk)).collect();
            if got != want {
                failure = Some(Invalid("witness"));
                break;
            }
            if verify_sigs {
                for w in &tx.wits {
                    jobs.push((&w.pk, msgs[ti], &w.sig));
                }
            }
            let total_out: u128 = tx.outs.iter().map(|o| o.amount as u128).sum();
            if total_out > total_in {
                failure = Some(Invalid("value"));
                break;
            }
            fees += total_in - total_out;
            let txid = tx.txid();
            for op in &tx.ins {
                spent_set.insert(*op);
                spent.push(*op);
            }
            for (i, o) in tx.outs.iter().enumerate() {
                let k = OutPoint { txid, index: i as u8 };
                if view.contains_key(&k) || self.utxo.contains_key(&k) {
                    failure = Some(Invalid("dup"));
                    break 'txs;
                }
                let e = UtxoEntry { amount: o.amount, addr: o.addr, height: h, coinbase: false };
                view.insert(k, e);
                created.push((k, e));
            }
        }
        if failure.is_none() {
            let cb_total: u128 = blk.coinbase.outs.iter().map(|o| o.amount as u128).sum();
            if cb_total > subsidy(h as u64) as u128 + fees {
                failure = Some(Invalid("cbvalue"));
            } else {
                let cbid = blk.coinbase.txid();
                for (i, o) in blk.coinbase.outs.iter().enumerate() {
                    let k = OutPoint { txid: cbid, index: i as u8 };
                    if view.contains_key(&k) || self.utxo.contains_key(&k) {
                        failure = Some(Invalid("dup"));
                        break;
                    }
                    let e = UtxoEntry { amount: o.amount, addr: o.addr, height: h, coinbase: true };
                    view.insert(k, e);
                    created.push((k, e));
                }
            }
        }
        if first_bad_sig(&jobs).is_some() {
            return bad("sig");
        }
        if let Some(f) = failure {
            return Err(f);
        }
        drop(jobs);
        Ok(Checked { hash: block_hash, time: t, height: h, fees: fees.min(u64::MAX as u128) as u64, created, spent, block: blk })
    }

    /// Apply a block that `check` accepted. Returns what is needed to undo it.
    pub fn apply_checked(&mut self, c: &Checked) -> Undo {
        let mut undo = Undo { prev_time: self.time, ..Default::default() };
        let mut created: HashMap<OutPoint, UtxoEntry> = c.created.iter().copied().collect();
        for op in &c.spent {
            if created.remove(op).is_none() {
                let e = self.utxo.remove(op).expect("checked block spends a known output");
                undo.removed.push((*op, e));
            }
        }
        for (k, e) in &c.created {
            if created.contains_key(k) {
                self.utxo.insert(*k, *e);
                undo.added.push(*k);
            }
        }
        self.height += 1;
        self.tip = c.hash;
        self.time = c.time;
        undo
    }

    pub fn apply(&mut self, raw: &[u8], now: i64) -> Result<Hash> {
        let c = self.check(raw, now)?;
        self.apply_checked(&c);
        Ok(c.hash)
    }

    /// Disconnect the tip block, given its undo data and the hash of its parent.
    pub fn undo(&mut self, undo: &Undo, parent: Hash) {
        for k in &undo.added {
            self.utxo.remove(k);
        }
        for (k, e) in &undo.removed {
            self.utxo.insert(*k, *e);
        }
        self.height -= 1;
        self.tip = parent;
        self.time = undo.prev_time;
    }

    pub fn verdict(&self, raw: &[u8], now: i64) -> &'static str {
        match self.check(raw, now) {
            Ok(_) => "ok",
            Err(Invalid(code)) => code,
        }
    }
}

// ---------------------------------------------------------------- snapshot chunks (spec 6)
/// Sizes of every level of the Merkle tree over `n` leaves, bottom first.
fn level_sizes(n: usize) -> Vec<usize> {
    let mut v = vec![n];
    let mut m = n;
    while m > 1 {
        m = m.div_ceil(2);
        v.push(m);
    }
    v
}

/// Proof that the chunk `k` of `leaves` (4,096 consecutive leaves) belongs to `merkle_root(leaves)`.
/// Chunk k is the subtree at level 12, index k; the proof lists the siblings above it, skipping
/// the levels where the node is unpaired and moves up unchanged.
pub fn chunk_proof(leaves: &[Hash], k: usize) -> Vec<Hash> {
    let mut level = leaves.to_vec();
    let mut idx = 0usize;
    let mut depth = 0;
    let mut proof = Vec::new();
    while level.len() > 1 {
        if depth >= 12 {
            let sib = idx ^ 1;
            if sib < level.len() {
                proof.push(level[sib]);
            }
        }
        if depth == 11 {
            idx = k;
        }
        level = merkle_level(&level);
        depth += 1;
        if depth > 12 {
            idx /= 2;
        }
    }
    proof
}

/// Recompute the root from a chunk of leaves, its position and its proof.
pub fn chunk_root(chunk: &[Hash], k: usize, total: usize, proof: &[Hash]) -> Option<Hash> {
    let start = k.checked_mul(SNAPSHOT_CHUNK)?;
    if chunk.is_empty() || start >= total || chunk.len() != (total - start).min(SNAPSHOT_CHUNK) {
        return None;
    }
    let mut node = merkle_root(chunk);
    let sizes = level_sizes(total);
    let mut idx = k;
    let mut proof = proof.iter();
    for &size in sizes.iter().skip(12) {
        if size <= 1 {
            break;
        }
        let sib = idx ^ 1;
        if sib < size {
            let s = proof.next()?;
            node = if idx.is_multiple_of(2) { fold(&node, s) } else { fold(s, &node) };
        }
        idx /= 2;
    }
    if proof.next().is_some() {
        return None;
    }
    Some(node)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunk_proofs_fold_to_the_root() {
        for n in [1usize, 2, 4095, 4096, 4097, 8192, 8193, 12289, 20000] {
            let leaves: Vec<Hash> = (0..n as u32).map(|i| sha256(&i.to_le_bytes())).collect();
            let root = merkle_root(&leaves);
            for k in 0..n.div_ceil(SNAPSHOT_CHUNK) {
                let chunk = &leaves[k * SNAPSHOT_CHUNK..((k + 1) * SNAPSHOT_CHUNK).min(n)];
                let proof = chunk_proof(&leaves, k);
                assert_eq!(chunk_root(chunk, k, n, &proof), Some(root), "n={n} k={k}");
                if !proof.is_empty() {
                    let mut p = proof.clone();
                    p[0][0] ^= 1;
                    assert_ne!(chunk_root(chunk, k, n, &p), Some(root));
                }
            }
        }
    }
}
