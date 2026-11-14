//! `cargo test` runs every vector in ../vectors.json, the same file the Python and JS implementations check.
use fable::vectors;

#[test]
fn all_vectors() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../vectors.json");
    let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let r = vectors::run(&v);
    for f in r.fails.iter().take(20) {
        eprintln!("FAIL {f}");
    }
    assert!(r.fails.is_empty(), "{} failures", r.fails.len());
    assert_eq!((r.applied, r.rejected), (1445, 30));
    eprintln!("{} checks passed", r.pass);
}
