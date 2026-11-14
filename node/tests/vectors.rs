//! Every vector in ../vectors.json (written by `gen_vectors.py`), the same file the Python and JS
//! implementations check, and the differential cases of `crosscheck.py`:
//!
//!     cargo test --release --test vectors                  # the vectors
//!     python3 crosscheck.py 1                              # from the repository root, then
//!     cargo test --release --test vectors -- --ignored     # compare with /tmp/fable_cross.json

use serde_json::Value;

use fable::consensus::*;
use fable::wallet::*;
struct Report {
    pass: usize,
    fails: Vec<String>,
    applied: usize,
    rejected: usize,
}

impl Report {
    fn eq(&mut self, group: &str, got: impl ToString, want: impl ToString, what: impl std::fmt::Display) {
        let (g, w) = (got.to_string(), want.to_string());
        if g == w {
            self.pass += 1;
        } else {
            self.fails.push(format!("{group} {what}: got {g}, want {w}"));
        }
    }
}

fn s(v: &Value) -> &str {
    v.as_str().unwrap_or_default()
}

fn b(v: &Value) -> Vec<u8> {
    unhex(s(v)).expect("hex")
}

fn n(v: &Value) -> i64 {
    v.as_i64().expect("number")
}

fn net_named(name: &str) -> Net {
    match name {
        "main" => Net::main(),
        _ => Net::test(),
    }
}

fn target_hex(t: &num_bigint::BigUint) -> String {
    format!("0x{}", t.to_str_radix(16))
}

fn run(v: &Value) -> Report {
    let mut r = Report { pass: 0, fails: vec![], applied: 0, rejected: 0 };
    let u = &v["unit"];
    for c in u["hash"].as_array().unwrap() {
        r.eq("hash", hex(&h(n(&c["tag"]) as u8, &b(&c["data"]))), s(&c["out"]), "");
    }
    for c in u["sha256d"].as_array().unwrap() {
        r.eq("sha256d", hex(&sha256d(&b(&c["data"]))), s(&c["out"]), "");
    }
    for c in u["bits"].as_array().unwrap() {
        let bits = n(&c["bits"]) as u32;
        let t = bits_to_target(bits).unwrap();
        r.eq("bits", target_hex(&t), s(&c["target"]), bits);
        r.eq("bits back", target_to_bits(&t), n(&c["back"]), bits);
    }
    for c in u["asert"].as_array().unwrap() {
        let net = net_named(s(&c["net"]));
        let (hh, t) = (n(&c["height"]), n(&c["time"]));
        r.eq("asert", asert_bits(&net, hh as u64, t), n(&c["bits"]), format!("{} h={hh} t={t}", net.name));
    }
    for c in u["subsidy"].as_array().unwrap() {
        r.eq("subsidy", subsidy(n(&c["height"]) as u64), s(&c["units"]), n(&c["height"]));
    }
    for c in u["max_sigs"].as_array().unwrap() {
        r.eq("max sigs", max_sigs(n(&c["height"]) as u64), n(&c["sigs"]), n(&c["height"]));
    }
    for c in u["time"].as_array().unwrap() {
        r.eq("time", full_time(n(&c["prev"]), n(&c["time32"]) as u32), n(&c["full"]), n(&c["prev"]));
    }
    for c in u["merkle"].as_array().unwrap() {
        let leaves: Vec<Hash> = c["leaves"].as_array().unwrap().iter().map(|x| unhex32(s(x)).unwrap()).collect();
        r.eq("merkle", hex(&merkle_root(&leaves)), s(&c["root"]), leaves.len());
        let branch: Vec<String> = coinbase_branch(&leaves).iter().map(|x| hex(x)).collect();
        let want: Vec<String> = c["coinbase_branch"].as_array().unwrap().iter().map(|x| s(x).to_string()).collect();
        r.eq("coinbase branch", branch.join(","), want.join(","), leaves.len());
        if let Some(first) = leaves.first() {
            let mut acc = *first; // fold the branch the way a Stratum miner does
            for x in coinbase_branch(&leaves) {
                acc = fold(&acc, &x);
            }
            r.eq("merkle branch", hex(&acc), s(&c["root"]), leaves.len());
        }
    }
    let main = Net::main();
    for c in u["tx"].as_array().unwrap() {
        let raw = b(&c["raw"]);
        let tx = Tx::parse(&raw).unwrap();
        r.eq("tx size", raw.len(), n(&c["size"]), "");
        r.eq("tx roundtrip", hex(&tx.serialize()), s(&c["raw"]), "");
        r.eq("txid", hex(&tx.txid()), s(&c["txid"]), "");
        r.eq("sighash", hex(&tx.sighash(&main.chain_id)), s(&c["sighash_main"]), "");
        r.eq("leaf", hex(&tx.leaf()), s(&c["leaf"]), "");
    }
    for c in u["genesis"].as_array().unwrap() {
        let net = net_named(s(&c["net"]));
        r.eq("genesis", hex(&net.genesis.serialize()), s(&c["header"]), &net.name);
        r.eq("chain id", hex(&net.chain_id), s(&c["chain_id"]), &net.name);
    }

    let w = &v["wallet"];
    let seed = seed_from_mnemonic(s(&w["mnemonic"]), "");
    r.eq("wallet seed", hex(&seed), s(&w["seed"]), "");
    r.eq("mnemonic checksum", check_mnemonic(s(&w["mnemonic"])).is_ok(), true, "");
    for k in w["keys"].as_array().unwrap() {
        let (acc, idx) = (n(&k["account"]) as u32, n(&k["index"]) as u32);
        let ks = key_seed(&seed, acc, idx);
        let key = Key::from_seed48(&ks);
        r.eq("key seed", hex(&ks), s(&k["key_seed"]), idx);
        r.eq("public key", hex(&key.pk), s(&k["public_key"]), idx);
        r.eq("address hash", hex(&key.addr), s(&k["address_hash"]), idx);
        r.eq("address", encode_address(&key.addr), s(&k["address"]), idx);
        r.eq("address decode", decode_address(s(&k["address"])).map(|a| hex(&a)).unwrap_or_default(), s(&k["address_hash"]), idx);
        r.eq(
            "address decode upper",
            decode_address(&s(&k["address"]).to_uppercase()).map(|a| hex(&a)).unwrap_or_default(),
            s(&k["address_hash"]),
            idx,
        );
    }
    for a in w["address_errors"].as_array().unwrap() {
        r.eq("address error", decode_address(s(a)).is_none(), true, s(a));
    }
    {
        let sv = &w["signature"];
        let (pk, msg, sig) = (b(&sv["public_key"]), b(&sv["message"]), b(&sv["signature"]));
        r.eq("signature verifies", verify_sig(&pk, &msg, &sig), true, "");
        let key = Key::derive(&seed, 0, 0);
        r.eq("signature is byte-identical", hex(&key.sign(&msg)), s(&sv["signature"]), "deterministic signing");
        let mut bad_sig = sig.clone();
        bad_sig[4000] ^= 1;
        r.eq("flipped signature fails", verify_sig(&pk, &msg, &bad_sig), false, "");
    }

    let cv = &v["chain"];
    let mut chain = Chain::new(net_named(s(&cv["net"])));
    for e in cv["events"].as_array().unwrap() {
        let raw = b(&e["block"]);
        let now = n(&e["now"]);
        if s(&e["op"]) == "apply" {
            match chain.apply(&raw, now) {
                Ok(hash) => r.eq("block hash", hex(&hash), s(&e["hash"]), n(&e["height"])),
                Err(code) => {
                    r.fails.push(format!("block {} refused: {code}", n(&e["height"])));
                    break;
                }
            }
            r.applied += 1;
        } else {
            r.eq("reject", chain.verdict(&raw, now), s(&e["code"]), s(&e["name"]));
            r.rejected += 1;
        }
    }
    r.eq("tip", hex(&chain.tip), s(&cv["tip"]), "");
    r.eq("height", chain.height, n(&cv["height"]), "");
    r.eq("utxo root", hex(&utxo_root(&chain.utxo)), s(&cv["utxo_root"]), "");
    r.eq("utxo count", chain.utxo.len(), n(&cv["utxo_count"]), "");
    r.eq("supply", chain.utxo.values().map(|e| e.amount as u128).sum::<u128>(), s(&cv["supply"]), "");
    r
}

/// The file `crosscheck.py` writes: numeric cases and mutated blocks with the reference verdicts.
fn crosscheck(d: &Value, v: &Value) -> Report {
    let mut r = Report { pass: 0, fails: vec![], applied: 0, rejected: 0 };
    let nm = &d["numeric"];
    for c in nm["asert"].as_array().unwrap() {
        let net = net_named(s(&c[0]));
        r.eq("asert", asert_bits(&net, n(&c[1]) as u64, n(&c[2])), n(&c[3]), format!("{} h={} t={}", s(&c[0]), c[1], c[2]));
    }
    for c in nm["bits"].as_array().unwrap() {
        let t = num_bigint::BigUint::parse_bytes(s(&c[0]).trim_start_matches("0x").as_bytes(), 16).unwrap();
        r.eq("bits", target_to_bits(&t), n(&c[1]), s(&c[0]));
        r.eq("bits", target_hex(&bits_to_target(n(&c[1]) as u32).unwrap()), s(&c[2]), &c[1]);
    }
    for c in nm["max_sigs"].as_array().unwrap() {
        r.eq("max sigs", max_sigs(n(&c[0]) as u64), n(&c[1]), &c[0]);
    }
    for c in nm["subsidy"].as_array().unwrap() {
        r.eq("subsidy", subsidy(n(&c[0]) as u64), s(&c[1]), &c[0]);
    }
    for c in nm["time"].as_array().unwrap() {
        r.eq("time", full_time(n(&c[0]), n(&c[1]) as u32), n(&c[2]), format!("{} {}", c[0], c[1]));
    }
    for c in nm["merkle"].as_array().unwrap() {
        let leaves: Vec<Hash> = c[0].as_array().unwrap().iter().map(|x| unhex32(s(x)).unwrap()).collect();
        r.eq("merkle", hex(&merkle_root(&leaves)), s(&c[1]), leaves.len());
    }
    for c in nm["address"].as_array().unwrap() {
        let got = decode_address(s(&c[0])).map(|a| hex(&a));
        r.eq("address", got.unwrap_or("null".into()), c[1].as_str().unwrap_or("null"), s(&c[0]));
    }
    let mut chain = Chain::new(Net::test());
    let sets: std::collections::HashMap<i64, &Value> = d["blocks"].as_array().unwrap().iter().map(|x| (n(&x["height"]), x)).collect();
    for e in v["chain"]["events"].as_array().unwrap() {
        if s(&e["op"]) != "apply" {
            continue;
        }
        if let Some(set) = sets.get(&(chain.height as i64)) {
            let now = n(&set["now"]);
            for c in set["cases"].as_array().unwrap() {
                r.eq("block", chain.verdict(&b(&c[0]), now), s(&c[1]), format!("at height {}", chain.height));
                r.rejected += 1;
            }
        }
        chain.apply(&b(&e["block"]), n(&e["now"])).expect("vector chain");
        r.applied += 1;
    }
    r
}

fn load(path: &str) -> Value {
    serde_json::from_str(&std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{path}: {e}"))).unwrap()
}

fn report(r: &Report) {
    for f in r.fails.iter().take(20) {
        eprintln!("FAIL {f}");
    }
    eprintln!("{} checks passed, {} failed ({} blocks applied, {} refused or compared)", r.pass, r.fails.len(), r.applied, r.rejected);
    assert!(r.fails.is_empty(), "{} failures", r.fails.len());
}

#[test]
fn all_vectors() {
    let v = load(concat!(env!("CARGO_MANIFEST_DIR"), "/../vectors.json"));
    let r = run(&v);
    report(&r);
    assert_eq!((r.applied, r.rejected), (1445, 30));
}

/// Needs the cases file: `FABLE_CROSS` or /tmp/fable_cross.json, written by crosscheck.py.
#[test]
#[ignore]
fn crosscheck_cases() {
    let cases = std::env::var("FABLE_CROSS").unwrap_or_else(|_| "/tmp/fable_cross.json".into());
    let r = crosscheck(&load(&cases), &load(concat!(env!("CARGO_MANIFEST_DIR"), "/../vectors.json")));
    report(&r);
}
