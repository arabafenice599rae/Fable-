//! Local control interface: one JSON object per line, `{"method": ..., "params": [...]}` in,
//! `{"result": ..., "error": ...}` out. Bind it to localhost only: there is no authentication.

use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};

use serde_json::{Value, json};

use crate::chainstate::Accepted;
use crate::consensus::*;
use crate::miner;
use crate::node::{Handle, now};
use crate::wallet::parse_address;
use std::result::Result;

pub fn serve(h: Handle, addr: SocketAddr) -> std::io::Result<SocketAddr> {
    let l = TcpListener::bind(addr)?;
    let local = l.local_addr()?;
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            let h = h.clone();
            std::thread::spawn(move || client(h, s));
        }
    });
    Ok(local)
}

fn client(h: Handle, s: TcpStream) {
    let Ok(w) = s.try_clone() else { return };
    let mut w = std::io::BufWriter::new(w);
    for line in BufReader::new(s).lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() {
            continue;
        }
        let reply = match serde_json::from_str::<Value>(&line) {
            Ok(req) => {
                let params = req["params"].as_array().cloned().unwrap_or_default();
                match call(&h, req["method"].as_str().unwrap_or(""), &params) {
                    Ok(r) => json!({"id": req["id"], "result": r, "error": null}),
                    Err(e) => json!({"id": req["id"], "result": null, "error": e}),
                }
            }
            Err(e) => json!({"id": null, "result": null, "error": format!("bad request: {e}")}),
        };
        if writeln!(w, "{reply}").and_then(|_| w.flush()).is_err() {
            break;
        }
    }
}

fn p_str(p: &[Value], i: usize) -> Result<String, String> {
    match p.get(i) {
        Some(Value::String(s)) => Ok(s.clone()),
        Some(Value::Number(n)) => Ok(n.to_string()),
        _ => Err(format!("parameter {i} missing")),
    }
}

fn p_u64(p: &[Value], i: usize) -> Result<u64, String> {
    p_str(p, i)?.parse().map_err(|_| format!("parameter {i} is not a number"))
}

fn coins(units: u64) -> String {
    format!("{}.{:08}", units / COIN, units % COIN)
}

/// A block hash as shown (reversed) or as raw bytes is accepted, or a height.
fn find_block(n: &mut crate::node::Node, s: &str) -> Option<(Hash, u32)> {
    if let Ok(h) = s.parse::<u32>() {
        return n.cs.active.get(h as usize).map(|x| (*x, h));
    }
    let raw = unhex32(s)?;
    let mut rev = raw;
    rev.reverse();
    for c in [rev, raw] {
        if let Some(e) = n.cs.entry(&c) {
            return Some((c, e.height));
        }
    }
    None
}

pub fn call(h: &Handle, method: &str, p: &[Value]) -> Result<Value, String> {
    match method {
        "getinfo" => {
            let n = h.lock();
            let st = &n.cs.state;
            let best = n.cs.entry(&n.cs.best_header).unwrap();
            Ok(json!({
                "net": n.cs.net.name,
                "chain_id": hex(&n.cs.net.chain_id),
                "height": st.height,
                "tip": display_hash(&st.tip),
                "time": st.time,
                "next_bits": format!("{:08x}", st.next_bits()),
                "work": n.cs.tip().work.to_str_radix(16),
                "best_header_height": best.height,
                "utxos": st.utxo.len(),
                "supply": coins(st.utxo.values().map(|e| e.amount).sum()),
                "mempool_txs": n.pool.len(),
                "mempool_sigs": n.pool.sigs,
                "peers": n.peers.values().filter(|p| p.version.is_some()).count(),
                "snapshots": n.cs.snapshots.keys().collect::<Vec<_>>(),
                "base": n.cs.base,
                "snapshot_sync": n.snap.as_ref().map(|s| json!({"height": s.height, "chunks": s.have(), "of": s.chunk_count()})),
            }))
        }
        "getblockhash" => {
            let n = h.lock();
            let height = p_u64(p, 0)? as usize;
            n.cs.active.get(height).map(|x| json!(display_hash(x))).ok_or_else(|| "no block at that height".into())
        }
        "getblock" => {
            let mut n = h.lock();
            let (hash, height) = find_block(&mut n, &p_str(p, 0)?).ok_or("unknown block")?;
            let raw = n.cs.block_raw(&hash).ok_or("block not stored")?;
            let txs: Vec<String> = read_block(&raw).unwrap().txs.iter().map(|t| hex(&t.txid())).collect();
            Ok(json!({"hash": display_hash(&hash), "height": height, "active": n.cs.is_active(&hash), "txs": txs, "hex": hex(&raw)}))
        }
        "submitblock" => {
            let raw = unhex(&p_str(p, 0)?).ok_or("not hex")?;
            match h.submit_block(&raw, None) {
                Ok(Accepted::Stored) => Ok(json!("stored")),
                Ok(Accepted::Duplicate) => Ok(json!("duplicate")),
                Ok(Accepted::Orphan) => Ok(json!("orphan")),
                Err(e) => Err(e.to_string()),
            }
        }
        "sendrawtransaction" => {
            let raw = unhex(&p_str(p, 0)?).ok_or("not hex")?;
            h.submit_tx(&raw, None).map(|id| json!(hex(&id)))
        }
        "getutxos" => {
            // Confirmed outputs of an address, with the ones the mempool already spends marked,
            // plus unconfirmed outputs paying it.
            let addr = parse_address(&p_str(p, 0)?).ok_or("not an address")?;
            let n = h.lock();
            let height = n.cs.height();
            let mut out = Vec::new();
            for (k, e) in n.cs.state.utxo.iter().filter(|(_, e)| e.addr == addr) {
                let mature = !e.coinbase || height + 1 >= e.height + MATURITY;
                out.push(json!({"txid": hex(&k.txid), "index": k.index, "amount": e.amount, "height": e.height,
                    "coinbase": e.coinbase, "mature": mature, "spent_in_mempool": n.pool.spender(k).is_some()}));
            }
            for e in n.pool.txs.values() {
                for (i, o) in e.tx.outs.iter().enumerate() {
                    let k = OutPoint { txid: e.txid, index: i as u8 };
                    if o.addr == addr {
                        out.push(json!({"txid": hex(&k.txid), "index": i, "amount": o.amount, "height": null,
                            "coinbase": false, "mature": true, "spent_in_mempool": n.pool.spender(&k).is_some()}));
                    }
                }
            }
            Ok(json!(out))
        }
        "gettemplate" => {
            let addr = parse_address(&p_str(p, 0)?).ok_or("not an address")?;
            let n = h.lock();
            let t = miner::template(&n.cs, &n.pool, addr, now());
            Ok(json!({"height": t.height, "prev": hex(&t.prev), "bits": format!("{:08x}", t.bits), "time": t.time,
                "coinb1": hex(&t.coinb1()), "coinb2": hex(&t.coinb2()), "txs": t.txs.iter().map(|x| hex(&x.serialize())).collect::<Vec<_>>(),
                "fees": t.fees}))
        }
        "generate" => {
            // CPU mining, for the test network.
            let count = p_u64(p, 0)?;
            let addr = parse_address(&p_str(p, 1)?).ok_or("not an address")?;
            let mut hashes = Vec::new();
            for i in 0..count {
                let t = {
                    let n = h.lock();
                    let mut t = miner::template(&n.cs, &n.pool, addr, now());
                    // one second apart, ending now: never ahead of the clock rule however many blocks
                    t.time = (now() - (count - 1 - i) as i64).max(n.cs.state.time + 1);
                    t
                };
                let blk = miner::mine(&t, 1 << 32).ok_or("no block found")?;
                let raw = blk.serialize();
                h.submit_block(&raw, None).map_err(|e| e.to_string())?;
                hashes.push(json!(display_hash(&blk.hash())));
            }
            Ok(json!(hashes))
        }
        "addpeer" => {
            let a = p_str(p, 0)?;
            h.lock().manual.push(a.clone());
            Ok(json!(a))
        }
        "stop" => {
            h.stop();
            Ok(json!("stopping"))
        }
        _ => Err(format!("unknown method {method:?}")),
    }
}

/// Client side, for the command line.
pub fn request(addr: &str, method: &str, params: Value) -> Result<Value, String> {
    let s = TcpStream::connect(addr).map_err(|e| format!("cannot reach the node at {addr}: {e}"))?;
    let mut w = s.try_clone().map_err(|e| e.to_string())?;
    writeln!(w, "{}", json!({"id": 1, "method": method, "params": params})).map_err(|e| e.to_string())?;
    let mut line = String::new();
    BufReader::new(s).read_line(&mut line).map_err(|e| e.to_string())?;
    let v: Value = serde_json::from_str(&line).map_err(|e| e.to_string())?;
    if v["error"].is_null() { Ok(v["result"].clone()) } else { Err(v["error"].as_str().unwrap_or("error").to_string()) }
}
