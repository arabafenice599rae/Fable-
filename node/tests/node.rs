//! Block tree, reorganisations, mempool and storage.
use fable::chainstate::{Accepted, BlockStore, ChainState, NO_CLOCK};
use fable::consensus::*;
use fable::mempool::Mempool;
use fable::miner;
use fable::wallet::{self, Key};

fn keys() -> Vec<Key> {
    let seed = wallet::seed_from_mnemonic(&("abandon ".repeat(23) + "art"), "");
    (0..3).map(|i| Key::derive(&seed, 0, i)).collect()
}

/// Fill in the witnesses: one per distinct input address, in order of first appearance.
/// `input_addrs[i]` is the address that owns `tx.ins[i]`.
fn sign_tx(tx: &mut Tx, input_addrs: &[Hash], keys: &[&Key], chain_id: &Hash) -> std::result::Result<(), String> {
    let mut want: Vec<Hash> = Vec::new();
    for a in input_addrs {
        if !want.contains(a) {
            want.push(*a);
        }
    }
    let msg = tx.sighash(chain_id);
    tx.wits = want
        .iter()
        .map(|a| {
            let k = keys.iter().find(|k| &k.addr == a).ok_or_else(|| format!("no key for address {}", wallet::encode_address(a)))?;
            Ok(Witness { pk: k.pk, sig: k.sign(&msg) })
        })
        .collect::<std::result::Result<_, String>>()?;
    Ok(())
}

fn mem(net: Net) -> ChainState {
    ChainState::new(net, BlockStore::memory())
}

/// Mine one block on `cs` (with what `pool` offers) and add it. Returns the raw block.
fn step(cs: &mut ChainState, pool: &mut Mempool, payout: Hash, extra: u64) -> Vec<u8> {
    let t = cs.state.time + 60;
    let mut tpl = miner::template(cs, pool, payout, t);
    tpl.time = t;
    let mut blk = miner::mine(&tpl, 1 << 24).unwrap();
    blk.coinbase.extra = extra.to_le_bytes(); // makes the two sides of a fork differ
    let mut leaves = vec![blk.coinbase.txid()];
    leaves.extend(blk.txs.iter().map(Tx::leaf));
    blk.header.merkle = merkle_root(&leaves);
    let target = bits_to_target(blk.header.bits).unwrap();
    while !meets_target(&blk.header.hash(), &target) {
        blk.header.nonce += 1;
    }
    let raw = blk.serialize();
    let (r, ch) = cs.accept_block(&raw, NO_CLOCK);
    assert_eq!(r, Ok(Accepted::Stored));
    pool.apply_changes(&ch, &cs.state);
    raw
}

#[test]
fn vector_chain_through_the_block_tree() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../vectors.json");
    let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let mut cs = mem(Net::test());
    for e in v["chain"]["events"].as_array().unwrap() {
        let raw = unhex(e["block"].as_str().unwrap()).unwrap();
        let now = e["now"].as_i64().unwrap();
        let (r, _) = cs.accept_block(&raw, now);
        if e["op"] == "apply" {
            assert_eq!(r, Ok(Accepted::Stored), "height {}", e["height"]);
            assert_eq!(hex(&cs.state.tip), e["hash"].as_str().unwrap());
        } else {
            let before = cs.state.tip;
            // an unknown parent makes an orphan; everything else is an error
            assert!(r.is_err() || r == Ok(Accepted::Orphan), "{} was accepted", e["name"]);
            assert_eq!(cs.state.tip, before);
        }
    }
    assert_eq!(hex(&cs.state.tip), v["chain"]["tip"].as_str().unwrap());
    assert_eq!(hex(&utxo_root(&cs.state.utxo)), v["chain"]["utxo_root"].as_str().unwrap());
    assert_eq!(cs.snapshots.keys().copied().collect::<Vec<_>>(), vec![1440]);
}

#[test]
fn most_work_wins_and_ties_keep_the_first() {
    let k = keys();
    let (mut a, mut b) = (mem(Net::test()), mem(Net::test()));
    let (mut pa, mut pb) = (Mempool::default(), Mempool::default());
    for i in 0..5 {
        let raw = step(&mut a, &mut pa, k[0].addr, i);
        let _ = b.accept_block(&raw, NO_CLOCK);
    }
    let fork_a: Vec<_> = (0..3).map(|i| step(&mut a, &mut pa, k[0].addr, 100 + i)).collect();
    let fork_b: Vec<_> = (0..4).map(|i| step(&mut b, &mut pb, k[1].addr, 200 + i)).collect();
    let tip_a = a.state.tip;
    // three blocks of b: equal work, a keeps what it saw first
    for raw in &fork_b[..3] {
        let _ = a.accept_block(raw, NO_CLOCK);
    }
    assert_eq!(a.state.tip, tip_a);
    // the fourth gives b's chain more work: a reorganises
    let (_, ch) = a.accept_block(&fork_b[3], NO_CLOCK);
    assert_eq!((ch.disconnected.len(), ch.connected.len()), (3, 4));
    assert_eq!(a.state.tip, b.state.tip);
    assert_eq!(a.state.utxo, b.state.utxo);
    // and b, given a's shorter fork, does not move
    for raw in &fork_a {
        let (_, ch) = b.accept_block(raw, NO_CLOCK);
        assert!(ch.is_empty());
    }
    assert_eq!(b.height(), 9);
}

#[test]
fn a_block_with_an_unknown_parent_is_not_kept() {
    let k = keys();
    let (mut a, mut b) = (mem(Net::test()), mem(Net::test()));
    let mut pa = Mempool::default();
    let raws: Vec<_> = (0..3).map(|i| step(&mut a, &mut pa, k[0].addr, i)).collect();
    // out of order: the child is refused as an orphan and not stored, so it has to come again
    assert_eq!(b.accept_block(&raws[1], NO_CLOCK).0, Ok(Accepted::Orphan));
    assert_eq!(b.accept_block(&raws[0], NO_CLOCK).0, Ok(Accepted::Stored));
    assert_eq!(b.height(), 1);
    for raw in &raws[1..] {
        assert_eq!(b.accept_block(raw, NO_CLOCK).0, Ok(Accepted::Stored));
    }
    assert_eq!(b.state.tip, a.state.tip);
}

#[test]
fn invalid_block_on_a_heavier_branch_falls_back() {
    let k = keys();
    let (mut a, mut b) = (mem(Net::test()), mem(Net::test()));
    let (mut pa, mut pb) = (Mempool::default(), Mempool::default());
    let raw = step(&mut a, &mut pa, k[0].addr, 0);
    let _ = b.accept_block(&raw, NO_CLOCK);
    step(&mut a, &mut pa, k[0].addr, 1);
    let tip_a = a.state.tip;
    // b's branch: a block paying one unit too much, then a valid-looking child on it
    let t = b.state.time + 60;
    let mut tpl = miner::template(&b, &pb, k[1].addr, t);
    tpl.outs[0].amount += 1;
    let bad = miner::mine(&tpl, 1 << 24).unwrap();
    assert_eq!(b.state.check_block(bad.clone(), NO_CLOCK, false, Some(ZERO32)).unwrap_err(), Invalid("cbvalue"));
    let hb = bad.hash();
    let child_tpl = miner::Template {
        height: 3,
        prev: hb,
        bits: asert_bits(&Net::test(), 2, full_time(b.state.time, bad.header.time32)),
        time: full_time(b.state.time, bad.header.time32) + 60,
        utxo_root: ZERO32,
        outs: vec![Output { amount: subsidy(3), addr: k[1].addr }],
        txs: vec![],
        fees: 0,
    };
    let child = miner::mine(&child_tpl, 1 << 24).unwrap();
    // equal work: stored, not validated yet, tip unchanged
    assert_eq!(a.accept_block(&bad.serialize(), NO_CLOCK).0, Ok(Accepted::Stored));
    assert_eq!(a.state.tip, tip_a);
    // more work: a tries the branch, finds the bad block, and stays where it was
    assert_eq!(a.accept_block(&child.serialize(), NO_CLOCK).0, Err(Invalid("cbvalue")));
    assert_eq!(a.state.tip, tip_a);
    assert!(a.entry(&hb).unwrap().invalid && a.entry(&child.hash()).unwrap().invalid);
    step(&mut a, &mut pa, k[0].addr, 2);
    assert_eq!(a.height(), 3);
    let _ = &mut pb;
}

#[test]
fn mempool_spend_replace_mine_and_reorg_back() {
    let k = keys();
    let net = Net::test();
    let chain_id = net.chain_id;
    let mut cs = mem(net.clone());
    let mut pool = Mempool::default();
    for i in 0..110 {
        step(&mut cs, &mut pool, k[0].addr, i);
    }
    // the coinbases of blocks 1 to 10 are mature at 110; early ones are small (slow start)
    let ins: Vec<OutPoint> =
        (1..=10).map(|h| OutPoint { txid: read_block(&cs.block_at(h).unwrap()).unwrap().coinbase.txid(), index: 0 }).collect();
    let value: u64 = ins.iter().map(|o| cs.state.utxo[o].amount).sum();
    let owners = vec![k[0].addr; ins.len()];
    let fee = COIN / 1000;
    let mk = |fee: u64, to: Hash| {
        let mut tx = Tx { ins: ins.clone(), outs: vec![Output { amount: value - fee, addr: to }], wits: vec![] };
        sign_tx(&mut tx, &owners, &[&k[0]], &chain_id).unwrap();
        tx
    };
    let tx1 = mk(fee, k[1].addr);
    assert_eq!(pool.accept(mk(fee - 1, k[1].addr), &cs.state), Err("fee below the relay minimum".into()));
    let id1 = pool.accept(tx1.clone(), &cs.state).unwrap();
    // a child of tx1, spent by k1
    let mut child =
        Tx { ins: vec![OutPoint { txid: id1, index: 0 }], outs: vec![Output { amount: value - 3 * fee, addr: k[2].addr }], wits: vec![] };
    sign_tx(&mut child, &[k[1].addr], &[&k[1]], &chain_id).unwrap();
    pool.accept(child.clone(), &cs.state).unwrap();
    assert_eq!(pool.len(), 2);
    // replacing tx1 needs more than tx1 + child together
    assert!(pool.accept(mk(3 * fee, k[2].addr), &cs.state).is_err());
    let tx1b = mk(4 * fee, k[2].addr);
    let id1b = pool.accept(tx1b.clone(), &cs.state).unwrap();
    assert_eq!(pool.len(), 1);
    assert!(pool.contains(&id1b));
    // mined: the block pays subsidy + fee and the mempool empties
    let before = cs.state.clone();
    let raw = step(&mut cs, &mut pool, k[0].addr, 1000);
    let blk = read_block(&raw).unwrap();
    assert_eq!(blk.txs, vec![tx1b.clone()]);
    assert_eq!(blk.coinbase.outs[0].amount, subsidy(111) + 4 * fee);
    assert!(pool.is_empty());
    // a heavier fork without it: the transaction comes back
    let mut other = mem(net);
    for h in 1..=110 {
        let _ = other.accept_block(&cs.block_at(h).unwrap(), NO_CLOCK);
    }
    assert_eq!(other.state.utxo, before.utxo);
    let mut op = Mempool::default();
    let f1 = step(&mut other, &mut op, k[2].addr, 5000);
    let f2 = step(&mut other, &mut op, k[2].addr, 5001);
    let _ = cs.accept_block(&f1, NO_CLOCK);
    let (_, ch) = cs.accept_block(&f2, NO_CLOCK);
    pool.apply_changes(&ch, &cs.state);
    assert_eq!(cs.state.tip, other.state.tip);
    assert!(pool.contains(&id1b));
}

#[test]
fn block_file_survives_a_restart() {
    let k = keys();
    let dir = std::env::temp_dir().join(format!("fable-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let tip;
    {
        let mut cs = ChainState::open(Net::test(), &dir).unwrap();
        let mut pool = Mempool::default();
        for i in 0..30 {
            step(&mut cs, &mut pool, k[0].addr, i);
        }
        tip = cs.state.tip;
    }
    let cs = ChainState::open(Net::test(), &dir).unwrap();
    assert_eq!(cs.state.tip, tip);
    assert_eq!(cs.height(), 30);
    std::fs::remove_dir_all(&dir).unwrap();
}
