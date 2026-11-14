//! `fable-tools`: programs that work through a node's control interface.

mod stratum;
mod wallet;

use std::process::ExitCode;

use fable::cli::Args;
use std::result::Result;

const USAGE: &str = "fable-tools, for a running fable node

usage:
  fable-tools stratum --payout fb1... [--listen ADDR] [--share-diff D] [--rpc ADDR]
      Stratum v1 server for miners (default listen 0.0.0.0:3333). Jobs come from the node's
      gettemplate, with its mempool transactions; blocks go back with submitblock.
  fable-tools wallet balance --words W [--account A] [--count N] [--passphrase P] [--rpc ADDR]
  fable-tools wallet send --words W --to fb1... --amount COINS [--fee COINS] [--account A]
                          [--count N] [--passphrase P] [--rpc ADDR] [--dry-run]
The node's control address defaults to 127.0.0.1:17172. The phrase can also be given in FABLE_WORDS.";

fn run_stratum(a: &Args) -> Result<(), String> {
    a.allow(&["payout", "listen", "share-diff", "rpc"])?;
    let payout = a.get("payout").ok_or("--payout is needed")?;
    fable::wallet::parse_address(&payout).ok_or("--payout is not a Fable address")?;
    let listen = a.parsed("listen")?.unwrap_or_else(|| "0.0.0.0:3333".parse().unwrap());
    let (srv, local) = stratum::Server::start(a.rpc(), payout.clone(), listen, a.parsed("share-diff")?)?;
    eprintln!("stratum on {local}, share difficulty {}, paying {payout}, node at {}", srv.share_diff, a.rpc());
    loop {
        std::thread::park();
    }
}

fn main() -> ExitCode {
    let r = Args::parse(std::env::args().skip(1)).and_then(|a| {
        if a.flag("help") {
            println!("{USAGE}");
            return Ok(());
        }
        match (a.pos.first().map(String::as_str), a.pos.get(1).map(String::as_str)) {
            (Some("stratum"), _) => run_stratum(&a),
            (Some("wallet"), Some("balance")) => wallet::balance(&a),
            (Some("wallet"), Some("send")) => wallet::send(&a),
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
