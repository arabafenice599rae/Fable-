//! Signature verification speed: `cargo run --release --example bench`.
fn main() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../vectors.json");
    let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let s = &v["wallet"]["signature"];
    let b = |k: &str| fable::consensus::unhex(s[k].as_str().unwrap()).unwrap();
    let (pk, msg, sig) = (b("public_key"), b("message"), b("signature"));
    let t = std::time::Instant::now();
    for _ in 0..200 {
        assert!(fable::consensus::verify_sig(&pk, &msg, &sig));
    }
    let one = t.elapsed().as_secs_f64() / 200.0;
    let jobs: Vec<(&[u8], [u8; 32], &[u8])> = (0..80).map(|_| (&pk[..], msg.clone().try_into().unwrap(), &sig[..])).collect();
    let t = std::time::Instant::now();
    assert!(fable::consensus::first_bad_sig(&jobs).is_none());
    println!(
        "one signature: {:.2} ms; a full block (80) on {} threads: {:.1} ms",
        one * 1e3,
        std::thread::available_parallelism().map_or(1, |n| n.get()),
        t.elapsed().as_secs_f64() * 1e3
    );
}
