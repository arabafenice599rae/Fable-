//! `fable`: the reference node and its command-line tools.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use serde_json::{Value, json};

use fable::consensus::*;
use fable::node::{Config, Handle};
use fable::wallet::{self, Key};
use fable::{rpc, stratum, vectors};
use std::result::Result;

#[derive(Parser)]
#[command(name = "fable", version, about = "Fable reference node (spec v0.11)")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run a node.
    Node(NodeArgs),
    /// Call a method of a running node, e.g. `fable rpc getinfo`.
    Rpc {
        #[arg(long, default_value = "127.0.0.1:17172")]
        rpc: String,
        method: String,
        params: Vec<String>,
    },
    /// Keys, addresses and payments.
    Wallet {
        #[command(subcommand)]
        cmd: WalletCmd,
    },
    /// Check every vector in vectors.json.
    Vectors {
        #[arg(default_value = "vectors.json")]
        path: PathBuf,
    },
    /// Compare with the cases crosscheck.py wrote (it leaves them in /tmp/fable_cross.json).
    Crosscheck {
        #[arg(default_value = "/tmp/fable_cross.json")]
        cases: PathBuf,
        #[arg(default_value = "vectors.json")]
        vectors: PathBuf,
    },
}

#[derive(Parser)]
struct NodeArgs {
    /// test (trivial difficulty), lab (mainnet difficulty, throwaway genesis) or main
    #[arg(long, default_value = "test")]
    net: String,
    /// Genesis time for --net lab; by default the time of the first start, kept in the data directory.
    #[arg(long)]
    genesis_time: Option<i64>,
    /// Data directory (default ~/.fable/<net>). `-` keeps everything in memory.
    #[arg(long)]
    datadir: Option<String>,
    /// P2P address to listen on (default 0.0.0.0:7171 main, 0.0.0.0:17171 otherwise). `none` to not listen.
    #[arg(long)]
    listen: Option<String>,
    /// Local control address (default 127.0.0.1:7172 main, 127.0.0.1:17172 otherwise).
    #[arg(long)]
    rpc: Option<SocketAddr>,
    /// Peer to keep connected to (repeatable).
    #[arg(long)]
    connect: Vec<String>,
    /// Stratum v1 address for miners, e.g. 0.0.0.0:3333. Needs --payout.
    #[arg(long)]
    stratum: Option<SocketAddr>,
    /// Address the Stratum server pays, fb1...
    #[arg(long)]
    payout: Option<String>,
    /// Share difficulty for Stratum (default: min(256, network difficulty)).
    #[arg(long)]
    share_diff: Option<f64>,
    /// Download blocks only once the header chain has this much work (hex).
    #[arg(long)]
    min_chain_work: Option<String>,
    /// Do not verify signatures (only for replaying chains you trust).
    #[arg(long, hide = true)]
    no_sigs: bool,
    /// Start from the newest UTXO snapshot the peers serve instead of from genesis.
    #[arg(long)]
    snapshot_sync: bool,
    #[arg(long, short)]
    verbose: bool,
}

#[derive(Subcommand)]
enum WalletCmd {
    /// A new 24-word phrase.
    New,
    /// Addresses of a phrase.
    Address {
        #[arg(long, env = "FABLE_WORDS")]
        words: String,
        #[arg(long, default_value_t = 0)]
        account: u32,
        #[arg(long, default_value_t = 0)]
        index: u32,
        #[arg(long, default_value_t = 1)]
        count: u32,
        #[arg(long, default_value = "")]
        passphrase: String,
    },
    /// Balance of the first `count` addresses, from a running node.
    Balance {
        #[arg(long, env = "FABLE_WORDS")]
        words: String,
        #[arg(long, default_value_t = 0)]
        account: u32,
        #[arg(long, default_value_t = 5)]
        count: u32,
        #[arg(long, default_value = "")]
        passphrase: String,
        #[arg(long, default_value = "127.0.0.1:17172")]
        rpc: String,
    },
    /// Pay an address, with change back to index 0.
    Send {
        #[arg(long, env = "FABLE_WORDS")]
        words: String,
        #[arg(long)]
        to: String,
        /// In coins, e.g. 1.5
        #[arg(long)]
        amount: String,
        /// In coins (default 0.001 per signature, the relay minimum)
        #[arg(long)]
        fee: Option<String>,
        #[arg(long, default_value_t = 0)]
        account: u32,
        #[arg(long, default_value_t = 5)]
        count: u32,
        #[arg(long, default_value = "")]
        passphrase: String,
        #[arg(long, default_value = "127.0.0.1:17172")]
        rpc: String,
        /// Build and sign, print the transaction, do not send it.
        #[arg(long)]
        dry_run: bool,
    },
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

fn run_node(a: NodeArgs) -> Result<(), String> {
    let default_dir = |name: &str| {
        std::env::var("HOME").map(|h| PathBuf::from(h).join(".fable").join(name)).unwrap_or_else(|_| PathBuf::from(".fable").join(name))
    };
    let datadir = match a.datadir.as_deref() {
        Some("-") => None,
        Some(d) => Some(PathBuf::from(d)),
        None => Some(default_dir(&a.net)),
    };
    let net = match a.net.as_str() {
        "test" => Net::test(),
        "main" => Net::main(),
        "lab" => {
            let t = match (a.genesis_time, &datadir) {
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
    cfg.listen = match a.listen.as_deref() {
        Some("none") => None,
        Some(s) => Some(s.parse().map_err(|_| format!("bad --listen {s}"))?),
        None => Some(if main { "0.0.0.0:7171" } else { "0.0.0.0:17171" }.parse().unwrap()),
    };
    cfg.connect = a.connect;
    cfg.verbose = a.verbose;
    cfg.snapshot_sync = a.snapshot_sync;
    if let Some(w) = a.min_chain_work {
        cfg.min_chain_work = num_bigint::BigUint::parse_bytes(w.trim_start_matches("0x").as_bytes(), 16).ok_or("bad --min-chain-work")?;
    }
    let payout = match &a.payout {
        Some(p) => Some(wallet::parse_address(p).ok_or("--payout is not a Fable address")?),
        None => None,
    };
    let h = Handle::start(cfg).map_err(|e| format!("cannot start: {e}"))?;
    if a.no_sigs {
        h.lock().cs.verify_sigs = false;
    }
    let rpc_addr = a.rpc.unwrap_or_else(|| if main { "127.0.0.1:7172" } else { "127.0.0.1:17172" }.parse().unwrap());
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
    if let Some(addr) = a.stratum {
        let payout = payout.ok_or("--stratum needs --payout")?;
        let (srv, local) =
            stratum::Server::start(h.clone(), payout, addr, a.share_diff, true).map_err(|e| format!("stratum on {addr}: {e}"))?;
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

fn wallet_cmd(cmd: WalletCmd) -> Result<(), String> {
    match cmd {
        WalletCmd::New => {
            let words = wallet::new_mnemonic();
            let k = keys(&words, "", 0, 1)?;
            println!("{}", json!({"words": words, "address": wallet::encode_address(&k[0].addr)}));
        }
        WalletCmd::Address { words, account, index, count, passphrase } => {
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
        WalletCmd::Balance { words, account, count, passphrase, rpc } => {
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
        WalletCmd::Send { words, to, amount, fee, account, count, passphrase, rpc, dry_run } => {
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
            if dry_run {
                println!("{}", json!({"txid": hex(&tx.txid()), "fee": coins(fee), "size": raw.len(), "hex": hex(&raw)}));
            } else {
                let id = rpc::request(&rpc, "sendtx", json!([hex(&raw)]))?;
                println!("{}", json!({"txid": id, "fee": coins(fee), "size": raw.len()}));
            }
        }
    }
    Ok(())
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let r: Result<(), String> = match cli.cmd {
        Cmd::Node(a) => run_node(a),
        Cmd::Rpc { rpc, method, params } => {
            let params: Vec<Value> = params.into_iter().map(Value::String).collect();
            rpc::request(&rpc, &method, json!(params)).map(|v| println!("{}", serde_json::to_string_pretty(&v).unwrap()))
        }
        Cmd::Wallet { cmd } => wallet_cmd(cmd),
        Cmd::Vectors { path } => (|| {
            let v: Value = serde_json::from_str(&std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?)
                .map_err(|e| e.to_string())?;
            let r = vectors::run(&v);
            println!(
                "spec {}: {} checks passed, {} failed ({} blocks applied, {} invalid blocks refused with the expected code)",
                v["spec"].as_str().unwrap_or("?"),
                r.pass,
                r.fails.len(),
                r.applied,
                r.rejected
            );
            for f in r.fails.iter().take(20) {
                println!("  FAIL {f}");
            }
            if r.fails.is_empty() { Ok(()) } else { Err("vectors failed".into()) }
        })(),
        Cmd::Crosscheck { cases, vectors: vp } => (|| {
            let d: Value = serde_json::from_str(&std::fs::read_to_string(&cases).map_err(|e| format!("{}: {e}", cases.display()))?)
                .map_err(|e| e.to_string())?;
            let v: Value = serde_json::from_str(&std::fs::read_to_string(&vp).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
            let r = vectors::crosscheck(&d, &v);
            println!("compared {} cases ({} mutated blocks): {} disagreements", r.pass + r.fails.len(), r.rejected, r.fails.len());
            for f in r.fails.iter().take(15) {
                println!("  {f}");
            }
            if r.fails.is_empty() { Ok(()) } else { Err("the implementations disagree".into()) }
        })(),
    };
    match r {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
