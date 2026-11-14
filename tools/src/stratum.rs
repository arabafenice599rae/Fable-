//! Stratum v1 server (spec 9), ported from `stratum.py`, fed by a node over its control interface:
//! jobs come from `gettemplate`, so they carry the node's mempool transactions and the merkle
//! branch is not empty; blocks go back with `submitblock`.
//! coinb1 = height, extranonce1 + extranonce2 = 4 + 4 bytes = extra, coinb2 = utxo_root ‖ outputs,
//! version rolling with mask 0x1fffe000.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use num_bigint::BigUint;
use num_traits::{FromPrimitive, ToPrimitive};
use serde_json::{Value, json};

use fable::consensus::*;
use fable::rpc;
use std::result::Result;

pub const MASK: u32 = 0x1FFF_E000;
pub const JOB_VERSION: u32 = 0x2000_0000;

fn diff1() -> BigUint {
    BigUint::from(0xFFFFu32) << 208u32
}

/// Stratum sends the previous hash with the bytes of every 4-byte word reversed.
fn swap_words(b: &Hash) -> Hash {
    let mut o = [0u8; 32];
    for i in 0..32 {
        o[i] = b[i / 4 * 4 + 3 - i % 4];
    }
    o
}

/// A block template as `gettemplate` returns it.
struct Template {
    height: u32,
    prev: Hash,
    bits: u32,
    time: i64,
    coinb1: Vec<u8>,
    coinb2: Vec<u8>,
    txs: Vec<Vec<u8>>,
    leaves: Vec<Hash>,
}

fn fetch(rpc_addr: &str, payout: &str) -> Result<Template, String> {
    let v = rpc::request(rpc_addr, "gettemplate", json!([payout]))?;
    let bytes = |k: &str| unhex(v[k].as_str().unwrap_or("")).ok_or(format!("gettemplate: bad {k}"));
    let txs: Vec<Vec<u8>> = v["txs"].as_array().into_iter().flatten().filter_map(|t| unhex(t.as_str()?)).collect();
    let leaves = txs.iter().map(|t| Tx::parse(t).map(|t| t.leaf()).map_err(|e| e.to_string())).collect::<Result<_, _>>()?;
    Ok(Template {
        height: v["height"].as_u64().ok_or("gettemplate: no height")? as u32,
        prev: bytes("prev")?.try_into().map_err(|_| "gettemplate: bad prev")?,
        bits: u32::from_str_radix(v["bits"].as_str().unwrap_or(""), 16).map_err(|_| "gettemplate: bad bits")?,
        time: v["time"].as_i64().ok_or("gettemplate: no time")?,
        coinb1: bytes("coinb1")?,
        coinb2: bytes("coinb2")?,
        txs,
        leaves,
    })
}

struct Job {
    id: String,
    tpl: Template,
    branch: Vec<Hash>,
}

struct Pool {
    jobs: HashMap<String, Arc<Job>>,
    current: Arc<Job>,
    job_n: u64,
    clients: Vec<(u32, Arc<Mutex<TcpStream>>)>,
    sid: u32,
}

pub struct Server {
    rpc: String,
    payout: String,
    share_target: BigUint,
    pub share_diff: f64,
    pool: Mutex<Pool>,
}

impl Server {
    pub fn start(rpc: String, payout: String, addr: SocketAddr, share_diff: Option<f64>) -> Result<(Arc<Server>, SocketAddr), String> {
        let tpl = fetch(&rpc, &payout)?;
        let target = bits_to_target(tpl.bits).map_err(|e| e.to_string())?;
        let net_diff = diff1().to_f64().unwrap() / target.to_f64().unwrap();
        let share_diff = share_diff.unwrap_or(256f64.min(net_diff));
        let share_target = BigUint::from_f64(diff1().to_f64().unwrap() / share_diff).unwrap_or_default();
        let first = Arc::new(Job { id: "1".into(), branch: branch(&tpl), tpl });
        let pool = Pool { jobs: HashMap::from([(first.id.clone(), first.clone())]), current: first, job_n: 1, clients: vec![], sid: 0 };
        let srv = Arc::new(Server { rpc, payout, share_target, share_diff, pool: Mutex::new(pool) });
        let l = TcpListener::bind(addr).map_err(|e| format!("stratum on {addr}: {e}"))?;
        let local = l.local_addr().map_err(|e| e.to_string())?;
        let s2 = srv.clone();
        std::thread::spawn(move || {
            for c in l.incoming().flatten() {
                let s3 = s2.clone();
                std::thread::spawn(move || s3.client(c));
            }
        });
        // poll the node: a clean job on a new tip, a fresh one (time, transactions) every 30 seconds
        let s2 = srv.clone();
        std::thread::spawn(move || {
            let mut last = Instant::now();
            loop {
                std::thread::sleep(Duration::from_millis(500));
                let tip = s2.pool.lock().unwrap().current.tpl.prev;
                match fetch(&s2.rpc, &s2.payout) {
                    Ok(t) if t.prev != tip || last.elapsed() > Duration::from_secs(30) => {
                        last = Instant::now();
                        s2.publish(t, true);
                    }
                    Ok(_) => {}
                    Err(e) => eprintln!("stratum: {e}"),
                }
            }
        });
        Ok((srv, local))
    }

    /// Make `tpl` the current job and send it to every miner. Old jobs stay valid on the same tip.
    fn publish(&self, tpl: Template, send: bool) -> Arc<Job> {
        let mut p = self.pool.lock().unwrap();
        p.job_n += 1;
        let job = Arc::new(Job { id: format!("{:x}", p.job_n), branch: branch(&tpl), tpl });
        let clean = job.tpl.prev != p.current.tpl.prev;
        if clean {
            p.jobs.clear();
        }
        p.jobs.insert(job.id.clone(), job.clone());
        let oldest = p.job_n.saturating_sub(8);
        p.jobs.retain(|k, _| u64::from_str_radix(k, 16).unwrap_or(0) > oldest);
        p.current = job.clone();
        if send {
            let line = format!("{}\n", notify(&job, clean));
            p.clients.retain(|(_, c)| c.lock().unwrap().write_all(line.as_bytes()).is_ok());
        }
        job
    }

    fn client(self: Arc<Self>, s: TcpStream) {
        let Ok(w) = s.try_clone() else { return };
        let _ = s.set_nodelay(true);
        let w = Arc::new(Mutex::new(w));
        let sid = {
            let mut p = self.pool.lock().unwrap();
            p.sid += 1;
            p.sid
        };
        let en1 = sid.to_be_bytes();
        let push = |m: Value| w.lock().unwrap().write_all(format!("{m}\n").as_bytes()).is_ok();
        for line in BufReader::new(s).lines() {
            let Ok(line) = line else { break };
            let Ok(m) = serde_json::from_str::<Value>(&line) else { continue };
            let (method, id) = (m["method"].as_str().unwrap_or(""), m["id"].clone());
            let params = m["params"].as_array().cloned().unwrap_or_default();
            let ok = match method {
                "mining.configure" => push(
                    json!({"id": id, "error": null, "result": {"version-rolling": true, "version-rolling.mask": format!("{MASK:08x}")}}),
                ),
                "mining.subscribe" => push(json!({"id": id, "error": null, "result": [[["mining.notify", hex(&en1)]], hex(&en1), 4]})),
                "mining.authorize" => {
                    // a fresh template for a new miner, with whatever the mempool holds now
                    let job = match fetch(&self.rpc, &self.payout) {
                        Ok(t) => self.publish(t, true),
                        Err(_) => self.pool.lock().unwrap().current.clone(),
                    };
                    self.pool.lock().unwrap().clients.push((sid, w.clone()));
                    push(json!({"id": id, "error": null, "result": true}))
                        && push(json!({"id": null, "method": "mining.set_difficulty", "params": [self.share_diff]}))
                        && push(notify(&job, true))
                }
                "mining.submit" => {
                    let (ok, msg) = self.submit(&en1, &params).unwrap_or((false, "malformed submit".into()));
                    let r = push(json!({"id": id, "error": if ok { Value::Null } else { json!([20, msg, null]) }, "result": ok}));
                    if msg.starts_with("block ") {
                        eprintln!("stratum: {msg}");
                        if let Ok(t) = fetch(&self.rpc, &self.payout) {
                            self.publish(t, true); // the miner sees the new job at once
                        }
                    }
                    r
                }
                _ => push(json!({"id": id, "error": null, "result": true})),
            };
            if !ok {
                break;
            }
        }
        self.pool.lock().unwrap().clients.retain(|(i, _)| *i != sid);
    }

    /// Returns (accepted, message). A share that is also a block goes to the node.
    fn submit(&self, en1: &[u8; 4], p: &[Value]) -> Option<(bool, String)> {
        let s = |i: usize| p.get(i).and_then(|v| v.as_str()).map(str::to_string);
        let (job_id, en2, ntime, nonce) = (s(1)?, s(2)?, s(3)?, s(4)?);
        let vbits = match s(5) {
            Some(v) => u32::from_str_radix(&v, 16).ok()?,
            None => 0,
        };
        let Some(job) = self.pool.lock().unwrap().jobs.get(&job_id).cloned() else { return Some((false, "stale job".into())) };
        if vbits & !MASK != 0 {
            return Some((false, "version bits outside the mask".into()));
        }
        let en2 = unhex(&en2)?;
        if en2.len() != 4 {
            return Some((false, "bad extranonce2 size".into()));
        }
        let t = &job.tpl;
        let coinbase = [&t.coinb1[..], en1, &en2, &t.coinb2].concat();
        let mut root = sha256d(&coinbase);
        for b in &job.branch {
            root = fold(&root, b);
        }
        let version = (JOB_VERSION & !MASK) | (vbits & MASK);
        let header = Header {
            version,
            prev: t.prev,
            merkle: root,
            time32: u32::from_str_radix(&ntime, 16).ok()?,
            bits: t.bits,
            nonce: u32::from_str_radix(&nonce, 16).ok()?,
        };
        let hash = header.hash();
        if BigUint::from_bytes_le(&hash) > self.share_target {
            return Some((false, "share above target".into()));
        }
        if !meets_target(&hash, &bits_to_target(t.bits).ok()?) {
            return Some((true, "share".into()));
        }
        let mut raw = header.serialize().to_vec();
        raw.extend(&coinbase);
        raw.extend((t.txs.len() as u16).to_le_bytes());
        t.txs.iter().for_each(|x| raw.extend(x));
        Some(match rpc::request(&self.rpc, "submitblock", json!([hex(&raw)])) {
            Ok(r) if r == "stored" || r == "duplicate" => (true, format!("block {} {}", t.height, display_hash(&hash))),
            Ok(r) => (false, format!("block refused: {}", r.as_str().unwrap_or("?"))),
            Err(e) => (false, format!("block refused: {e}")),
        })
    }
}

/// Siblings for the coinbase; leaf 0 is the coinbase itself, which the branch never depends on.
fn branch(t: &Template) -> Vec<Hash> {
    let mut leaves = vec![ZERO32];
    leaves.extend(&t.leaves);
    coinbase_branch(&leaves)
}

fn notify(job: &Job, clean: bool) -> Value {
    let t = &job.tpl;
    json!({"id": null, "method": "mining.notify", "params": [
        job.id, hex(&swap_words(&t.prev)), hex(&t.coinb1), hex(&t.coinb2),
        job.branch.iter().map(|b| hex(b)).collect::<Vec<_>>(),
        format!("{JOB_VERSION:08x}"), format!("{:08x}", t.bits), format!("{:08x}", t.time as u32), clean]})
}
