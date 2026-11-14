# Fable

Proof-of-work chain on SHA-256 with SLH-DSA signatures. The spec is in [`SPEC.md`](SPEC.md) (v0.13).

This repository holds the consensus rules in two implementations, the test vectors, a Stratum server, and the full node in Rust (see [`node/`](node/README.md)).

| File | What it does |
| --- | --- |
| `fable.py` | Reference implementation of the consensus rules |
| `fable.mjs` | Second implementation, in JavaScript and on another SLH-DSA library |
| `vectors.json` | Test vectors and a simulated chain of 1,445 blocks with 30 invalid blocks |
| `gen_vectors.py` | Regenerates `vectors.json` from the reference |
| `check_vectors.mjs` | Runs every vector through the second implementation |
| `crosscheck.py` / `.mjs` | Differential comparison on random cases and altered blocks |
| `stratum.py` | Stratum v1 server for mining with a Bitaxe |
| `bitaxe_sim.py` | Simulated Bitaxe, ported from the ESP-Miner firmware |
| `test_stratum.py` | Full test: simulated miner ↔ server ↔ both implementations |
| `cli.mjs` | Keys, addresses and signatures from the command line |
| `node/` | Rust reference node: consensus, storage, reorgs, mempool, P2P, Stratum, wallet |

## Installation

```
pip install slh-dsa==0.2.5
npm install
```

The Rust node needs `cargo` (Rust 1.85 or later).

## Checks

```
python3 gen_vectors.py        # about 20 seconds
node check_vectors.mjs
python3 crosscheck.py 1       # the number is the random seed
python3 test_stratum.py 40
cd node && cargo test --release && cd ..
(cd node && cargo test --release --test vectors -- --ignored)   # after crosscheck.py
python3 node/tests/e2e.py
python3 node/tests/e2e_snapshot.py
```

## Trying it with a real Bitaxe

```
node cli.mjs wallet "<your 24 words>" 0 0     # prints the fb1... address
python3 stratum.py --net lab --address fb1...
```

On the Bitaxe: pool = this computer's IP address, port 3333, any user name.
The `lab` network has mainnet difficulty and a throwaway genesis: at 1.2 TH/s a block comes out about once a minute.
Blocks go to `chain.txt`; to start over, delete `chain.txt` and `chain.txt.genesis`.
