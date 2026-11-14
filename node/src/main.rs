//! `fable`: the reference node and its command-line tools.

use std::path::PathBuf;
use std::process::ExitCode;

use serde_json::{Value, json};

use fable::consensus::*;
use fable::node::{Config, Handle};
use fable::wallet::{self, Key};
use fable::{rpc, stratum};
use std::result::Result;

const USAGE: &str = "fable, reference node for spec v0.13

usage:
  fable node [options]                 run a node
    --net test|lab|main                  network (default test)
    --genesis-time T                     genesis time for --net lab (default: first start)
    --datadir DIR                        data directory (default ~/.fable/<net>; - keeps it in memory)
    --listen ADDR|none                   P2P address (default 0.0.0.0:17171, 7171 for main)
    --rpc ADDR                           control address (default 127.0.0.1:17172, 7172 for main)
    --connect HOST:PORT                  peer to keep connected to (repeatable)
    --stratum ADDR --payout fb1...       Stratum v1 server for miners
    --share-diff D                       Stratum share difficulty (default min(256, network))
    --min-chain-work HEX                 download blocks only above this much header work
    --snapshot-sync                      start from the newest UTXO snapshot the peers serve
    -v, --verbose
  fable rpc [--rpc ADDR] METHOD [PARAMS...]
  fable wallet new
  fable wallet address --words W [--account A] [--index I] [--count N] [--passphrase P]
  fable wallet balance --words W [--account A] [--count N] [--passphrase P] [--rpc ADDR]
  fable wallet send --words W --to fb1... --amount COINS [--fee COINS] [--account A] [--count N]
                    [--passphrase P] [--rpc ADDR] [--dry-run]
The phrase can also be given in FABLE_WORDS.";

/// Options without a value; every other `--name` takes the next argument (or `--name=value`).
const FLAGS: &[&str] = &["verbose", "no-sigs", "snapshot-sync", "dry-run", "help"];

struct Args {
    pos: Vec<String>,
    opts: Vec<(String, String)>,
}

impl Args {
    fn parse(it: impl Iterator<Item = String>) -> Result<Args, String> {
        let (mut pos, mut opts) = (vec![], vec![]);
        let mut it = it.peekable();
        while let Some(a) = it.next() {
            let name = match a.as_str() {
                "-v" => "verbose".to_string(),
                "-h" => "help".to_string(),
                _ => match a.strip_prefix("--") {
                    Some(n) => n.to_string(),
                    None => {
                        pos.push(a);
                        continue;
                    }
                },
            };
            if let Some((n, v)) = name.split_once('=') {
                opts.push((n.to_string(), v.to_string()));
            } else if FLAGS.contains(&name.as_str()) {
                opts.push((name, String::new()));
            } else {
                let v = it.next().ok_or_else(|| format!("--{name} needs a value"))?;
                opts.push((name, v));
            }
        }
        Ok(Args { pos, opts })
    }

    /// Refuse options the command does not know.
    fn allow(&self, known: &[&str]) -> Result<(), String> {
        match self.opts.iter().find(|(n, _)| !known.contains(&n.as_str()) && !FLAGS.contains(&n.as_str())) {
            Some((n, _)) => Err(format!("unknown option --{n}\n\n{USAGE}")),
            None => Ok(()),
        }
    }

    fn get(&self, name: &str) -> Option<String> {
        self.opts.iter().rev().find(|(n, _)| n == name).map(|(_, v)| v.clone())
    }

    fn all(&self, name: &str) -> Vec<String> {
        self.opts.iter().filter(|(n, _)| n == name).map(|(_, v)| v.clone()).collect()
    }

    fn flag(&self, name: &str) -> bool {
        self.opts.iter().any(|(n, _)| n == name)
    }

    fn num<T: std::str::FromStr>(&self, name: &str, default: T) -> Result<T, String> {
        self.get(name).map_or(Ok(default), |v| v.parse().map_err(|_| format!("--{name}: not a number: {v}")))
    }

    fn parsed<T: std::str::FromStr>(&self, name: &str) -> Result<Option<T>, String> {
        self.get(name).map(|v| v.parse().map_err(|_| format!("--{name}: cannot read {v}"))).transpose()
    }

    fn words(&self) -> Result<String, String> {
        self.get("words").or_else(|| std::env::var("FABLE_WORDS").ok()).ok_or_else(|| "--words (or FABLE_WORDS) is needed".into())
    }

    fn rpc(&self) -> String {
        self.get("rpc").unwrap_or_else(|| "127.0.0.1:17172".into())
    }
}

fn parse_coins(s: &str) -> Result<u64, String> {
    let (w, f) = s.split_once('.').unwrap_or((s, ""));
    if f.len() > 8 || (w.is_empty() && f.is_empty()) {
        return Err(format!("not an amount: {s}"));
    }
    let w: u64 = if w.is_empty() { 0 } else { w.parse().map_err(|_| format!("not an amount: {s}"))? };
    let f: u64 = if f.is_empty() { 0 } else { format!("{f:0<8}").parse().map_err(|_| format!("not an amount: {s}"))? };
    w.checked_mul(COIN).and_then(|x| x.checked_add(f)).ok_or_else(|| "amount too large".into())
}

fn coins(u: u64) -> String {
    format!("{}.{:08}", u / COIN, u % COIN)
}

fn keys(words: &str, passphrase: &str, account: u32, count: u32) -> Result<Vec<Key>, String> {
    wallet::check_mnemonic(words)?;
    let seed = wallet::seed_from_mnemonic(words, passphrase);
    Ok((0..count).map(|i| Key::derive(&seed, account, i)).collect())
}

fn utxos(rpc_addr: &str, key: &Key) -> Result<Vec<Value>, String> {
    let v = rpc::request(rpc_addr, "getutxos", json!([hex(&key.addr)]))?;
    Ok(v.as_array().cloned().unwrap_or_default())
}

fn run_node(a: &Args) -> Result<(), String> {
    a.allow(&["net", "genesis-time", "datadir", "listen", "rpc", "connect", "stratum", "payout", "share-diff", "min-chain-work"])?;
    let net_name = a.get("net").unwrap_or_else(|| "test".into());
    let default_dir = |name: &str| {
        std::env::var("HOME").map(|h| PathBuf::from(h).join(".fable").join(name)).unwrap_or_else(|_| PathBuf::from(".fable").join(name))
    };
    let datadir = match a.get("datadir").as_deref() {
        Some("-") => None,
        Some(d) => Some(PathBuf::from(d)),
        None => Some(default_dir(&net_name)),
    };
    let net = match net_name.as_str() {
        "test" => Net::test(),
        "main" => Net::main(),
        "lab" => {
            let t = match (a.parsed::<i64>("genesis-time")?, &datadir) {
                (Some(t), _) => t,
                (None, Some(d)) => {
                    std::fs::create_dir_all(d).map_err(|e| e.to_string())?;
                    let stamp = d.join("genesis_time");
                    if !stamp.exists() {
                        std::fs::write(&stamp, fable::node::now().to_string()).map_err(|e| e.to_string())?;
                    }
                    std::fs::read_to_string(&stamp).map_err(|e| e.to_string())?.trim().parse().map_err(|_| "bad genesis_time file")?
                }
                (None, None) => return Err("--net lab in memory needs --genesis-time".into()),
            };
            Net::lab(t)
        }
        other => return Err(format!("unknown network {other}")),
    };
    let main = net.name == "main";
    let mut cfg = Config::new(net);
    cfg.datadir = datadir;
    cfg.listen = match a.get("listen").as_deref() {
        Some("none") => None,
        Some(s) => Some(s.parse().map_err(|_| format!("bad --listen {s}"))?),
        None => Some(if main { "0.0.0.0:7171" } else { "0.0.0.0:17171" }.parse().unwrap()),
    };
    cfg.connect = a.all("connect");
    cfg.verbose = a.flag("verbose");
    cfg.snapshot_sync = a.flag("snapshot-sync");
    if let Some(w) = a.get("min-chain-work") {
        cfg.min_chain_work = num_bigint::BigUint::parse_bytes(w.trim_start_matches("0x").as_bytes(), 16).ok_or("bad --min-chain-work")?;
    }
    let payout = match &a.get("payout") {
        Some(p) => Some(wallet::parse_address(p).ok_or("--payout is not a Fable address")?),
        None => None,
    };
    let h = Handle::start(cfg).map_err(|e| format!("cannot start: {e}"))?;
    if a.flag("no-sigs") {
        h.lock().cs.verify_sigs = false;
    }
    let rpc_addr = a
        .parsed::<std::net::SocketAddr>("rpc")?
        .unwrap_or_else(|| if main { "127.0.0.1:7172" } else { "127.0.0.1:17172" }.parse().unwrap());
    let rpc_local = rpc::serve(h.clone(), rpc_addr).map_err(|e| format!("rpc on {rpc_addr}: {e}"))?;
    {
        let n = h.lock();
        eprintln!(
            "fable {} node: height {}, tip {}, p2p port {}, rpc {}",
            n.cs.net.name,
            n.cs.height(),
            display_hash(&n.cs.state.tip),
            n.listen_port,
            rpc_local
        );
    }
    if let Some(addr) = a.parsed::<std::net::SocketAddr>("stratum")? {
        let payout = payout.ok_or("--stratum needs --payout")?;
        let (srv, local) = stratum::Server::start(h.clone(), payout, addr, a.parsed("share-diff")?, true)
            .map_err(|e| format!("stratum on {addr}: {e}"))?;
        eprintln!("stratum on {local}, share difficulty {}, paying {}", srv.share_diff(), wallet::encode_address(&payout));
    }
    let mut g = 0;
    loop {
        g = h.wait_tip(g, std::time::Duration::from_secs(3600));
        if h.lock().stopping {
            std::thread::sleep(std::time::Duration::from_millis(200));
            return Ok(());
        }
    }
}

fn wallet_cmd(a: &Args) -> Result<(), String> {
    let (account, passphrase, rpc) = (a.num("account", 0u32)?, a.get("passphrase").unwrap_or_default(), a.rpc());
    match a.pos.get(1).map(String::as_str) {
        Some("new") => {
            let words = wallet::new_mnemonic();
            let k = keys(&words, "", 0, 1)?;
            println!("{}", json!({"words": words, "address": wallet::encode_address(&k[0].addr)}));
        }
        Some("address") => {
            a.allow(&["words", "account", "index", "count", "passphrase"])?;
            let (words, index, count) = (a.words()?, a.num("index", 0u32)?, a.num("count", 1u32)?);
            wallet::check_mnemonic(&words)?;
            let seed = wallet::seed_from_mnemonic(&words, &passphrase);
            for i in index..index + count {
                let k = Key::derive(&seed, account, i);
                println!(
                    "{}",
                    json!({"account": account, "index": i, "address": wallet::encode_address(&k.addr), "public_key": hex(&k.pk)})
                );
            }
        }
        Some("balance") => {
            a.allow(&["words", "account", "count", "passphrase", "rpc"])?;
            let (words, count) = (a.words()?, a.num("count", 5u32)?);
            let mut total = (0u64, 0u64);
            for (i, k) in keys(&words, &passphrase, account, count)?.iter().enumerate() {
                let (mut spendable, mut other) = (0u64, 0u64);
                for u in utxos(&rpc, k)? {
                    let amt = u["amount"].as_u64().unwrap_or(0);
                    if u["mature"] == true && u["spent_in_mempool"] == false && !u["height"].is_null() {
                        spendable += amt;
                    } else if u["spent_in_mempool"] == false {
                        other += amt;
                    }
                }
                total.0 += spendable;
                total.1 += other;
                println!(
                    "{}",
                    json!({"index": i, "address": wallet::encode_address(&k.addr), "spendable": coins(spendable), "pending_or_immature": coins(other)})
                );
            }
            println!("{}", json!({"spendable": coins(total.0), "pending_or_immature": coins(total.1)}));
        }
        Some("send") => {
            a.allow(&["words", "to", "amount", "fee", "account", "count", "passphrase", "rpc"])?;
            let (words, count, fee) = (a.words()?, a.num("count", 5u32)?, a.get("fee"));
            let to = a.get("to").ok_or("--to is needed")?;
            let amount = a.get("amount").ok_or("--amount is needed")?;
            let dest = wallet::parse_address(&to).ok_or("--to is not a Fable address")?;
            let amount = parse_coins(&amount)?;
            let ks = keys(&words, &passphrase, account, count)?;
            let info = rpc::request(&rpc, "getinfo", json!([]))?;
            let chain_id = unhex32(info["chain_id"].as_str().unwrap_or("")).ok_or("bad getinfo")?;
            // every spendable confirmed output, largest first
            let mut coins_avail: Vec<(OutPoint, u64, usize)> = Vec::new();
            for (i, k) in ks.iter().enumerate() {
                for u in utxos(&rpc, k)? {
                    if u["mature"] == true && u["spent_in_mempool"] == false && !u["height"].is_null() {
                        let op =
                            OutPoint { txid: unhex32(u["txid"].as_str().unwrap()).unwrap(), index: u["index"].as_u64().unwrap() as u8 };
                        coins_avail.push((op, u["amount"].as_u64().unwrap(), i));
                    }
                }
            }
            coins_avail.sort_by_key(|c| std::cmp::Reverse(c.1));
            let fee_for = |sigs: usize| match &fee {
                Some(f) => parse_coins(f),
                None => Ok(COIN / 1000 * sigs as u64),
            };
            let (mut picked, mut owners, mut total): (Vec<OutPoint>, Vec<usize>, u64) = (vec![], vec![], 0);
            let mut distinct: Vec<usize> = vec![];
            for (op, amt, who) in coins_avail {
                if picked.len() == MAX_IN {
                    break;
                }
                if !distinct.contains(&who) {
                    if distinct.len() == MAX_WIT {
                        continue;
                    }
                    distinct.push(who);
                }
                picked.push(op);
                owners.push(who);
                total += amt;
                if total >= amount + fee_for(distinct.len())? {
                    break;
                }
            }
            let fee = fee_for(distinct.len())?;
            if total < amount + fee {
                return Err(format!("not enough spendable coins: have {}, need {}", coins(total), coins(amount + fee)));
            }
            let mut outs = vec![Output { amount, addr: dest }];
            let change = total - amount - fee;
            let fee = if change >= COIN / 1000 {
                outs.push(Output { amount: change, addr: ks[0].addr });
                fee
            } else {
                fee + change
            };
            let mut tx = Tx { ins: picked, outs, wits: vec![] };
            let addrs: Vec<Hash> = owners.iter().map(|&i| ks[i].addr).collect();
            let refs: Vec<&Key> = ks.iter().collect();
            wallet::sign_tx(&mut tx, &addrs, &refs, &chain_id)?;
            let raw = tx.serialize();
            if a.flag("dry-run") {
                println!("{}", json!({"txid": hex(&tx.txid()), "fee": coins(fee), "size": raw.len(), "hex": hex(&raw)}));
            } else {
                let id = rpc::request(&rpc, "sendtx", json!([hex(&raw)]))?;
                println!("{}", json!({"txid": id, "fee": coins(fee), "size": raw.len()}));
            }
        }
        _ => return Err(USAGE.into()),
    }
    Ok(())
}

fn main() -> ExitCode {
    let r = Args::parse(std::env::args().skip(1)).and_then(|a| {
        if a.flag("help") {
            println!("{USAGE}");
            return Ok(());
        }
        match a.pos.first().map(String::as_str) {
            Some("node") => run_node(&a),
            Some("wallet") => wallet_cmd(&a),
            Some("rpc") => {
                a.allow(&["rpc"])?;
                let method = a.pos.get(1).ok_or("rpc needs a method, e.g. fable rpc getinfo")?;
                let params: Vec<Value> = a.pos[2..].iter().cloned().map(Value::String).collect();
                rpc::request(&a.rpc(), method, json!(params)).map(|v| println!("{}", serde_json::to_string_pretty(&v).unwrap()))
            }
            _ => Err(USAGE.into()),
        }
    });
    match r {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
