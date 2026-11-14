//! Wallet payments over a node's control interface: balances from `getutxos`, transactions
//! built and signed here, sent with `sendrawtransaction`. Keys follow the wallet standard (spec 7).

use serde_json::{Value, json};

use fable::cli::Args;
use fable::consensus::*;
use fable::rpc;
use fable::wallet::{self, Key};
use std::result::Result;

/// Fill in the witnesses: one per distinct input address, in order of first appearance.
/// `input_addrs[i]` is the address that owns `tx.ins[i]`.
fn sign_tx(tx: &mut Tx, input_addrs: &[Hash], keys: &[&Key], chain_id: &Hash) -> Result<(), String> {
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
        .collect::<Result<_, String>>()?;
    Ok(())
}

fn parse_coins(s: &str) -> Result<u64, String> {
    let bad = || format!("not an amount: {s}");
    let (w, f) = s.split_once('.').unwrap_or((s, ""));
    if f.len() > 8 || (w.is_empty() && f.is_empty()) {
        return Err(bad());
    }
    let w: u64 = if w.is_empty() { 0 } else { w.parse().map_err(|_| bad())? };
    let f: u64 = if f.is_empty() { 0 } else { format!("{f:0<8}").parse().map_err(|_| bad())? };
    w.checked_mul(COIN).and_then(|x| x.checked_add(f)).ok_or_else(|| "amount too large".into())
}

fn coins(u: u64) -> String {
    format!("{}.{:08}", u / COIN, u % COIN)
}

fn keys(a: &Args) -> Result<Vec<Key>, String> {
    let words = a.words()?;
    wallet::check_mnemonic(&words)?;
    let seed = wallet::seed_from_mnemonic(&words, &a.get("passphrase").unwrap_or_default());
    let account = a.num("account", 0u32)?;
    Ok((0..a.num("count", 5u32)?).map(|i| Key::derive(&seed, account, i)).collect())
}

/// Confirmed, mature outputs the mempool does not already spend.
fn spendable(u: &Value) -> bool {
    u["mature"] == true && u["spent_in_mempool"] == false && !u["height"].is_null()
}

fn utxos(rpc_addr: &str, key: &Key) -> Result<Vec<Value>, String> {
    let v = rpc::request(rpc_addr, "getutxos", json!([hex(&key.addr)]))?;
    Ok(v.as_array().cloned().unwrap_or_default())
}

pub fn balance(a: &Args) -> Result<(), String> {
    a.allow(&["words", "account", "count", "passphrase", "rpc"])?;
    let mut total = (0u64, 0u64);
    for (i, k) in keys(a)?.iter().enumerate() {
        let (mut ready, mut other) = (0u64, 0u64);
        for u in utxos(&a.rpc(), k)? {
            let amt = u["amount"].as_u64().unwrap_or(0);
            if spendable(&u) {
                ready += amt;
            } else if u["spent_in_mempool"] == false {
                other += amt;
            }
        }
        total = (total.0 + ready, total.1 + other);
        let addr = wallet::encode_address(&k.addr);
        println!("{}", json!({"index": i, "address": addr, "spendable": coins(ready), "pending_or_immature": coins(other)}));
    }
    println!("{}", json!({"spendable": coins(total.0), "pending_or_immature": coins(total.1)}));
    Ok(())
}

/// Pay one address from the first `count` keys, largest outputs first, change back to index 0.
pub fn send(a: &Args) -> Result<(), String> {
    a.allow(&["words", "to", "amount", "fee", "account", "count", "passphrase", "rpc"])?;
    let rpc_addr = a.rpc();
    let dest = wallet::parse_address(&a.get("to").ok_or("--to is needed")?).ok_or("--to is not a Fable address")?;
    let amount = parse_coins(&a.get("amount").ok_or("--amount is needed")?)?;
    let fee_opt = a.get("fee");
    let ks = keys(a)?;
    let info = rpc::request(&rpc_addr, "getinfo", json!([]))?;
    let chain_id = unhex32(info["chain_id"].as_str().unwrap_or("")).ok_or("bad getinfo")?;
    let mut avail: Vec<(OutPoint, u64, usize)> = Vec::new();
    for (i, k) in ks.iter().enumerate() {
        for u in utxos(&rpc_addr, k)?.iter().filter(|u| spendable(u)) {
            let txid = unhex32(u["txid"].as_str().unwrap_or("")).ok_or("bad getutxos")?;
            avail.push((OutPoint { txid, index: u["index"].as_u64().unwrap_or(0) as u8 }, u["amount"].as_u64().unwrap_or(0), i));
        }
    }
    avail.sort_by_key(|c| std::cmp::Reverse(c.1));
    let fee_for = |sigs: usize| fee_opt.as_deref().map_or(Ok(COIN / 1000 * sigs as u64), parse_coins);
    let (mut picked, mut owners, mut distinct, mut total) = (vec![], vec![], vec![], 0u64);
    for (op, amt, who) in avail {
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
        owners.push(ks[who].addr);
        total += amt;
        if total >= amount + fee_for(distinct.len())? {
            break;
        }
    }
    let mut fee = fee_for(distinct.len())?;
    if total < amount + fee {
        return Err(format!("not enough spendable coins: have {}, need {}", coins(total), coins(amount + fee)));
    }
    let mut outs = vec![Output { amount, addr: dest }];
    let change = total - amount - fee;
    if change >= COIN / 1000 {
        outs.push(Output { amount: change, addr: ks[0].addr });
    } else {
        fee += change;
    }
    let mut tx = Tx { ins: picked, outs, wits: vec![] };
    sign_tx(&mut tx, &owners, &ks.iter().collect::<Vec<_>>(), &chain_id)?;
    let raw = tx.serialize();
    if a.flag("dry-run") {
        println!("{}", json!({"txid": hex(&tx.txid()), "fee": coins(fee), "size": raw.len(), "hex": hex(&raw)}));
    } else {
        let id = rpc::request(&rpc_addr, "sendrawtransaction", json!([hex(&raw)]))?;
        println!("{}", json!({"txid": id, "fee": coins(fee), "size": raw.len()}));
    }
    Ok(())
}
