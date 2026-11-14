# Rust reference node

A full node for Fable, spec v0.13. The consensus code (`src/consensus.rs`) is a line-by-line port of `fable.py`: the same checks, in the same order, with the same error codes.
Signatures use a third SLH-DSA library, RustCrypto's `slh-dsa` (pinned to `=0.2.0-rc.5`), different from the Python and JavaScript ones.

```
cd node
cargo build --release
cargo test --release
```

## Checks

| Command | What it checks |
| --- | --- |
| `cargo test --release` | Every vector in `../vectors.json`, the same chain fed through the block tree, reorgs, mempool, the block file, snapshot chunk proofs, message encoding |
| `./target/release/fable vectors ../vectors.json` | The vectors, with the same summary as `check_vectors.mjs` |
| `python3 crosscheck.py 1 && node/target/release/fable crosscheck` | The `crosscheck.py` differential test (from the repository root) |
| `python3 node/tests/e2e.py` | Three nodes over real sockets, the simulated Bitaxe, a payment, a reorg, a restart, replay on `fable.py` and `fable.mjs` |
| `python3 node/tests/e2e_snapshot.py` | Starting from a UTXO snapshot between nodes |
| `cargo run --release --example bench` | Signature verification speed |

Current state: 1,755 checks on the vectors (30 invalid blocks refused with the expected code) and 39,900 differential cases per seed (seeds 1, 2 and 3), all matching the reference.
One signature verifies in about 0.15 ms; a block's signatures are verified in parallel, a full block of 80 in about 4 ms on 4 cores (at the 2,048 cap, about 0.1 s).

## Usage

```
fable node --net test -v                                      # test network, data in ~/.fable/test
fable node --net test --connect 10.0.0.2:17171                # with a fixed peer
fable node --net lab --stratum 0.0.0.0:3333 --payout fb1...   # for a real Bitaxe, like stratum.py
fable node --net test --snapshot-sync --connect ...           # start from the latest UTXO snapshot
fable rpc getinfo
fable rpc generate 10 fb1...                                  # CPU mining, for the test network
fable wallet new
fable wallet address --words "<24 words>" --count 3
fable wallet balance --words "<24 words>"
fable wallet send --words "<24 words>" --to fb1... --amount 1.5
```

Default ports: P2P 17171 and control 17172 (7171 and 7172 for `main`). The phrase can also be given in `FABLE_WORDS`.
The control interface is line-delimited JSON with no authentication: keep it on `127.0.0.1`.
Methods: `getinfo`, `getpeers`, `getblockhash`, `getblock`, `submitblock`, `sendtx`, `getmempool`, `getutxos`, `gettemplate`, `generate`, `addpeer`, `getsnapshot`, `stop`.

## How it is built

| File | What it does |
| --- | --- |
| `src/consensus.rs` | Consensus rules, ported from `fable.py`; Merkle proofs for snapshot chunks |
| `src/wallet.rs` | BIP39 phrase, key derivation, Bech32m, transaction signing (section 7) |
| `src/chainstate.rs` | Header and block index, chain selection, reorgs, block file, snapshots |
| `src/mempool.rs` | The section 8 policy and transaction selection for blocks |
| `src/miner.rs` | Block templates and a CPU miner |
| `src/p2p.rs`, `src/node.rs` | P2P messages and the running node; the message format is in [`PROTOCOL.md`](PROTOCOL.md) |
| `src/snapsync.rs` | Collecting and checking the chunks of a snapshot |
| `src/stratum.rs` | Stratum v1 server, ported from `stratum.py` |
| `src/rpc.rs`, `src/main.rs` | Control interface and command line |

- **Chain selection.** Every header that passes the parent-relative checks (time, ASERT `bits`, proof of work) enters the index, even before its block arrives.
  The chain with the most work among those that can be connected wins; on a tie the one seen first stays.
  A block that fails during a reorg is marked invalid together with its descendants, and the node goes back to the best valid chain.
  A block with a wrong Merkle root does not invalidate its header, because the body may have been altered in transit.
- **Error codes.** A block's signatures are collected and verified together at the end. An error found later in the block is reported only if every signature the reference would have checked before it is valid, so the code stays the one `fable.py` gives.
- **Mempool.** Minimum fee 0.001 coin per signature and minimum output 0.001 coin; a cap of 5,000 signatures, the lowest fee per signature leaves first; a replacement must pay more than the total it replaces (descendants included) and more per signature than every transaction it conflicts with; at most 64 linked unconfirmed transactions. After a reorg, the transactions of the disconnected blocks go back into the mempool. Signatures already verified are not verified again.
- **Stratum.** Like `stratum.py`, but jobs include the mempool's transactions, so the Merkle branch is not empty. A new job on every new tip and every 30 seconds.
- **Snapshots.** The node keeps the last two UTXO sets committed by a snapshot block and serves them in chunks of 4,096 entries, each with its proof against `utxo_root`.
  With `--snapshot-sync` a new node downloads the headers, the snapshot block, the chunks (each one checked) and then only the blocks after it. It cannot reorganise below the snapshot.
- **Peers.** At most 8 outbound, one per /16 network; peers given with `--connect` are always kept. Blocks are requested only from peers that announced them.

## Known limits

- The UTXO set lives in memory. At startup the node rereads `blocks.dat` and revalidates everything, signatures included: fine for the test network and young chains, not for years of mainnet.
- No pruning: the node keeps every block it received. The spec allows pruning but does not require it.
- The P2P message format is not in the spec: `PROTOCOL.md` is a proposal.
- `MAIN` still has the placeholder genesis `prev_hash` and no seeds in the binary.
- Minimal network defences: disconnection for invalid messages or headers, an orphan pool capped at 256, a work threshold for downloading blocks (`--min-chain-work`, 0 by default). No misbehaviour scoring.
- Snapshot sync is tested over the network with a single chunk (1,439 entries); several chunks are covered by the unit tests.
