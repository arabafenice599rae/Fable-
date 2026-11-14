//! `fable`: the reference node, its control client and the key tools of the wallet standard.
//! Payments and Stratum mining are in `fable-tools`.

use std::path::PathBuf;
use std::process::ExitCode;

use serde_json::{Value, json};

use fable::cli::Args;
use fable::consensus::*;
use fable::node::{Config, Handle};
use fable::rpc;
use fable::wallet::{self, Key};
use std::result::Result;

const USAGE: &str = "fable, reference node for spec v0.13

usage:
  fable node [options]                 run a node
    --net test|main                      network (default test)
    --datadir DIR                        data directory (default ~/.fable/<net>; - keeps it in memory)
    --listen ADDR|none                   P2P address (default 0.0.0.0:17171, 7171 for main)
    --rpc ADDR                           control address (default 127.0.0.1:17172, 7172 for main)
    --connect HOST:PORT                  peer to keep connected to (repeatable)
    --min-chain-work HEX                 download blocks only above this much header work
    --snapshot-sync                      start from the newest UTXO snapshot the peers serve
    -v, --verbose
  fable rpc [--rpc ADDR] METHOD [PARAMS...]
  fable wallet new
  fable wallet address --words W [--account A] [--index I] [--count N] [--passphrase P]
The phrase can also be given in FABLE_WORDS. Payments and mining: fable-tools.";

fn run_node(a: &Args) -> Result<(), String> {
    a.allow(&["net", "datadir", "listen", "rpc", "connect", "min-chain-work"])?;
    let net_name = a.get("net").unwrap_or_else(|| "test".into());
    let datadir = match a.get("datadir").as_deref() {
        Some("-") => None,
        Some(d) => Some(PathBuf::from(d)),
        None => Some(PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".into())).join(".fable").join(&net_name)),
    };
    let net = match net_name.as_str() {
        "test" => Net::test(),
        "main" => Net::main(),
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
        let (name, height, tip, port) = (&n.cs.net.name, n.cs.height(), display_hash(&n.cs.state.tip), n.listen_port);
        eprintln!("fable {name} node: height {height}, tip {tip}, p2p port {port}, rpc {rpc_local}");
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
    match a.pos.get(1).map(String::as_str) {
        Some("new") => {
            let words = wallet::new_mnemonic();
            let k = Key::derive(&wallet::seed_from_mnemonic(&words, ""), 0, 0);
            println!("{}", json!({"words": words, "address": wallet::encode_address(&k.addr)}));
        }
        Some("address") => {
            a.allow(&["words", "account", "index", "count", "passphrase"])?;
            let (words, index, count, account) = (a.words()?, a.num("index", 0u32)?, a.num("count", 1u32)?, a.num("account", 0u32)?);
            wallet::check_mnemonic(&words)?;
            let seed = wallet::seed_from_mnemonic(&words, &a.get("passphrase").unwrap_or_default());
            for i in index..index + count {
                let k = Key::derive(&seed, account, i);
                let addr = wallet::encode_address(&k.addr);
                println!("{}", json!({"account": account, "index": i, "address": addr, "public_key": hex(&k.pk)}));
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
