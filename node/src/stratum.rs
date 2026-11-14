//! Stratum v1 server (spec 9), ported from `stratum.py`, on top of the node's mempool:
//! coinb1 = height, extranonce1 + extranonce2 = 4 + 4 bytes = extra, coinb2 = utxo_root ‖ outputs,
//! version rolling with mask 0x1fffe000. Unlike `stratum.py`, jobs carry mempool transactions,
//! so the merkle branch is not empty.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use num_bigint::BigUint;
use num_traits::{FromPrimitive, ToPrimitive};
use serde_json::{Value, json};

use crate::chainstate::Accepted;
use crate::consensus::*;
use crate::miner::{self, Template};
use crate::node::{Handle, now};

pub const MASK: u32 = 0x1FFF_E000;
pub const JOB_VERSION: u32 = 0x2000_0000;

pub fn diff1() -> BigUint {
    BigUint::from(0xFFFFu32) << 208u32
}

/// Stratum sends the previous hash with the bytes of every 4-byte word reversed.
pub fn swap_words(b: &Hash) -> Hash {
    let mut o = [0u8; 32];
    for i in (0..32).step_by(4) {
        for j in 0..4 {
            o[i + j] = b[i + 3 - j];
        }
    }
    o
}

struct Job {
    id: String,
    tpl: Template,
    ntime: u32,
    branch: Vec<Hash>,
}

struct Pool {
    jobs: HashMap<String, Arc<Job>>,
    current: Option<Arc<Job>>,
    job_n: u64,
    clients: Vec<(u64, Arc<Mutex<TcpStream>>)>,
    sid: u32,
    share_target: BigUint,
    share_diff: f64,
    log: Vec<String>,
}

pub struct Server {
    node: Handle,
    payout: Hash,
    pool: Mutex<Pool>,
    pub verbose: bool,
}

impl Server {
    pub fn start(
        node: Handle,
        payout: Hash,
        addr: SocketAddr,
        share_diff: Option<f64>,
        verbose: bool,
    ) -> std::io::Result<(Arc<Server>, SocketAddr)> {
        let net_diff = {
            let n = node.lock();
            let t = bits_to_target(n.cs.net.genesis_bits).unwrap();
            ratio(&diff1(), &t)
        };
        let share_diff = share_diff.unwrap_or(256f64.min(net_diff));
        let share_target = BigUint::from_f64(diff1().to_f64().unwrap() / share_diff).unwrap_or_default();
        let srv = Arc::new(Server {
            node,
            payout,
            verbose,
            pool: Mutex::new(Pool {
                jobs: HashMap::new(),
                current: None,
                job_n: 0,
                clients: vec![],
                sid: 0,
                share_target,
                share_diff,
                log: vec![],
            }),
        });
        srv.new_job(true);
        let l = TcpListener::bind(addr)?;
        let local = l.local_addr()?;
        let s2 = srv.clone();
        std::thread::spawn(move || {
            for c in l.incoming().flatten() {
                let s3 = s2.clone();
                std::thread::spawn(move || s3.client(c));
            }
        });
        // a new job on every new tip, and a fresh one (time, transactions) every 30 seconds
        let s2 = srv.clone();
        std::thread::spawn(move || {
            let mut generation = s2.node.lock().tip_generation;
            loop {
                let g = s2.node.wait_tip(generation, Duration::from_secs(30));
                if s2.node.lock().stopping {
                    return;
                }
                let clean = g != generation;
                generation = g;
                let job = s2.new_job(clean);
                s2.broadcast(&notify(&job, clean));
            }
        });
        Ok((srv, local))
    }

    pub fn share_diff(&self) -> f64 {
        self.pool.lock().unwrap().share_diff
    }

    pub fn found_blocks(&self) -> Vec<String> {
        self.pool.lock().unwrap().log.clone()
    }

    fn new_job(&self, clean: bool) -> Arc<Job> {
        let tpl = {
            let n = self.node.lock();
            miner::template(&n.cs, &n.pool, self.payout, now())
        };
        let mut leaves = vec![ZERO32]; // leaf 0 is the coinbase; the branch never depends on it
        leaves.extend(tpl.tx_leaves());
        let branch = coinbase_branch(&leaves);
        let mut p = self.pool.lock().unwrap();
        p.job_n += 1;
        let job = Arc::new(Job { id: format!("{:x}", p.job_n), ntime: tpl.time as u32, branch, tpl });
        if clean || p.current.as_ref().is_some_and(|c| c.tpl.prev != job.tpl.prev) {
            p.jobs.clear();
        }
        p.jobs.insert(job.id.clone(), job.clone());
        while p.jobs.len() > 8 {
            let oldest = p.jobs.keys().min_by_key(|k| u64::from_str_radix(k, 16).unwrap_or(0)).cloned().unwrap();
            p.jobs.remove(&oldest);
        }
        p.current = Some(job.clone());
        job
    }

    fn broadcast(&self, msg: &Value) {
        let clients: Vec<_> = self.pool.lock().unwrap().clients.clone();
        let line = format!("{msg}\n");
        let mut dead = vec![];
        for (id, c) in clients {
            if c.lock().unwrap().write_all(line.as_bytes()).is_err() {
                dead.push(id);
            }
        }
        self.pool.lock().unwrap().clients.retain(|(id, _)| !dead.contains(id));
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
                    let job = self.new_job(false);
                    let diff = {
                        let mut p = self.pool.lock().unwrap();
                        p.clients.push((sid as u64, w.clone()));
                        p.share_diff
                    };
                    push(json!({"id": id, "error": null, "result": true}))
                        && push(json!({"id": null, "method": "mining.set_difficulty", "params": [diff]}))
                        && push(notify(&job, true))
                }
                "mining.submit" => {
                    let (ok, msg) = self.submit(&en1, &params).unwrap_or((false, "malformed submit".into()));
                    let r = push(json!({"id": id, "error": if ok { Value::Null } else { json!([20, msg, null]) }, "result": ok}));
                    if msg.starts_with("block ") {
                        if self.verbose {
                            eprintln!("[{}] stratum: {msg}", now());
                        }
                        self.pool.lock().unwrap().log.push(msg);
                        // the tip watcher sends the new job; do it here too so the miner sees it at once
                        let job = self.new_job(true);
                        self.broadcast(&notify(&job, true));
                    }
                    r
                }
                _ => push(json!({"id": id, "error": null, "result": true})),
            };
            if !ok {
                break;
            }
        }
        self.pool.lock().unwrap().clients.retain(|(i, _)| *i != sid as u64);
    }

    /// Returns (accepted, message). A share that is also a block goes to the node.
    fn submit(&self, en1: &[u8; 4], p: &[Value]) -> Option<(bool, String)> {
        let s = |i: usize| p.get(i).and_then(|v| v.as_str()).map(str::to_string);
        let (job_id, en2, ntime, nonce) = (s(1)?, s(2)?, s(3)?, s(4)?);
        let vbits = match s(5) {
            Some(v) => u32::from_str_radix(&v, 16).ok()?,
            None => 0,
        };
        let (job, share_target) = {
            let pool = self.pool.lock().unwrap();
            (pool.jobs.get(&job_id).cloned(), pool.share_target.clone())
        };
        let Some(job) = job else { return Some((false, "stale job".into())) };
        if vbits & !MASK != 0 {
            return Some((false, "version bits outside the mask".into()));
        }
        let en2 = unhex(&en2)?;
        if en2.len() != 4 {
            return Some((false, "bad extranonce2 size".into()));
        }
        let mut extra = [0u8; 8];
        extra[..4].copy_from_slice(en1);
        extra[4..].copy_from_slice(&en2);
        let version = (JOB_VERSION & !MASK) | (vbits & MASK);
        let blk = job.tpl.block(version, extra, u32::from_str_radix(&ntime, 16).ok()?, u32::from_str_radix(&nonce, 16).ok()?);
        // the miner folded the branch the same way
        let mut root = blk.coinbase.txid();
        for b in &job.branch {
            root = fold(&root, b);
        }
        debug_assert_eq!(root, blk.header.merkle);
        let hash = blk.header.hash();
        let value = BigUint::from_bytes_le(&hash);
        if value > share_target {
            return Some((false, "share above target".into()));
        }
        if !meets_target(&hash, &bits_to_target(job.tpl.bits).ok()?) {
            return Some((true, "share".into()));
        }
        let raw = blk.serialize();
        Some(match self.node.submit_block(&raw, None) {
            Ok(Accepted::Stored) | Ok(Accepted::Duplicate) => {
                let height = self.node.lock().cs.entry(&hash).map_or(0, |e| e.height);
                (true, format!("block {height} {}", display_hash(&hash)))
            }
            Ok(Accepted::Orphan) => (false, "block refused: orphan".into()),
            Err(e) => (false, format!("block refused: {e}")),
        })
    }
}

fn ratio(a: &BigUint, b: &BigUint) -> f64 {
    a.to_f64().unwrap_or(f64::INFINITY) / b.to_f64().unwrap_or(f64::INFINITY)
}

fn notify(job: &Job, clean: bool) -> Value {
    json!({"id": null, "method": "mining.notify", "params": [
        job.id, hex(&swap_words(&job.tpl.prev)), hex(&job.tpl.coinb1()), hex(&job.tpl.coinb2()),
        job.branch.iter().map(|b| hex(b)).collect::<Vec<_>>(),
        format!("{JOB_VERSION:08x}"), format!("{:08x}", job.tpl.bits), format!("{:08x}", job.ntime), clean]})
}
