# Fable, spec v0.11

A proof-of-work chain that moves coins from one key to another. SHA-256 is the only cryptographic primitive and the rules are frozen at genesis.
The reference implementation is `fable.py`. If this text and the code disagree, the code wins and the text must be corrected.

## 1. Encodings and cryptography

- All integers are little-endian. Hashes are written in the byte order in which they come out of SHA-256.
- `H(tag, x) = SHA-256(byte(tag) ‖ x)`. Tags: TX = 1, SIG = 2, LEAF = 3, WIT = 4, ADDR = 5, UTXO = 6.
- `sha256d(x) = SHA-256(SHA-256(x))`, used for headers, coinbases and Merkle nodes, as in Bitcoin.
- Signature: SLH-DSA-SHA2-128s (FIPS 205), "pure" interface with an empty context. Public key 32 bytes, signature 7,856 bytes.
  Consensus defines only verification: signatures with or without added randomness are both valid.
- Address: `H(ADDR, public key)`, 32 bytes, reusable.
- Units: 1 coin = 10^8 units. Ticker: FABLE.

## 2. Transaction

| Field | Bytes | Values |
| --- | --- | --- |
| `n_in` | 1 | 1–32 |
| per input: `prev_txid`, `prev_index` | 32 + 1 | index 0–3 |
| `n_out` | 1 | 1–4 |
| per output: `amount`, `address` | 8 + 32 | amount 1–2^62 |
| `n_wit` | 1 | 1–min(4, n_in) |
| per witness: public key, signature | 32 + 7,856 | |

- The **body** is everything up to and including the outputs. The **witnesses** are `n_wit` followed by the pairs.
- `txid = H(TX, body)`. Signed message: `H(SIG, chain_id ‖ body)`, the same for every witness.
- Merkle leaf: `H(LEAF, txid ‖ H(WIT, witnesses))`.
- Sizes: 1 input and 2 outputs, 8,004 bytes. 32 inputs from one address and 1 output, 8,987 bytes. Maximum 32,771 bytes.

**Rules**

1. Counters within limits, all inputs distinct, exact length.
2. Every input points to an unspent output, possibly created earlier in the same block. A coinbase output created at height `c` is spendable from `c + 100`.
3. The witnesses are exactly the distinct addresses of the inputs, in the order in which they first appear, each as `H(ADDR, pk)`.
4. Every signature is valid on the message.
5. Sum of inputs ≥ sum of outputs. The difference is the fee.

## 3. Block

`block = header (80) ‖ coinbase ‖ n_tx (1 byte, 0–80) ‖ transactions`, with no trailing bytes.

**Header, Bitcoin layout**: `version` (4, any value), `prev_hash` (32), `merkle_root` (32), `time` (4, the low 32 bits), `bits` (4), `nonce` (4).

**Coinbase**: `height` (4) ‖ `extra` (8) ‖ `utxo_root` (32) ‖ `n_out` (1–2) ‖ 40-byte outputs. Its id is `sha256d` of its bytes.

**Merkle**: leaves = the coinbase id, then the transaction leaves in order. Inner node `sha256d(left ‖ right)`; an unpaired node moves up unchanged.

**Rules**

1. `prev_hash` is the hash of the tip; `bits` is the ASERT value; `sha256d(header)`, read as a little-endian integer, is ≤ target.
2. `merkle_root` matches; the coinbase `height` is the block's height.
3. `utxo_root` is the one from section 6 in snapshot blocks, 32 zero bytes in the others.
4. At most 80 witnesses in the block, coinbase excluded.
5. Coinbase outputs ≤ subsidy + fees. Collecting less is allowed: the difference is burned.
6. No new output may have a `(txid, index)` that already exists.

## 4. Consensus

- Block time 60 s. The chain with the most cumulative work wins, work of one block = `2^256 / (target + 1)`. On a tie, the first seen wins. No checkpoints.
- **Time**: the full 64-bit value is the smallest one greater than the previous block's time with those low 32 bits. It must be ≤ local clock + 600 s.
- **Difficulty (Bitcoin Cash's aserti3-2d, anchored at genesis)**, for the block after a parent of height `h` and time `t`:
  ```
  time_delta = t − (t_genesis − 60)
  num = (time_delta − 60 × (h + 1)) × 65536
  exponent = num / 3600            division truncated toward zero
  shifts = exponent >> 16          arithmetic shift
  exponent −= shifts × 65536
  factor = ((195766423245049·e + 971821376·e² + 5127·e³ + 2^47) >> 48) + 65536
  target = (target_genesis × factor) << shifts (or >> −shifts), then >> 16
  ```
  If `shifts > 300` or the result exceeds `0x1d00ffff`, `0x1d00ffff` is used; if `shifts < −300` or the result is 0, 1 is used. `bits` in canonical compact form.
- **Genesis**: header with `version` 1, `prev_hash` = the hash of a Bitcoin block chosen on launch day, `merkle_root` zero, `bits` `0x1b040000`, `nonce` 0. It is a constant in the code, it is not validated and it creates no coins. `chain_id = sha256d(genesis header)`.
- Test network `test`: same rules, genesis `bits` and maximum `0x207fffff`.

## 5. Emission

- `r = 50 coins`; every 131,400 blocks `r = r − (r >> 4)`; never below 1 coin.
- Slow start: for `h < 43,200`, subsidy = `r × h / 43,200` (integer division).
- Tail of 1 coin per block from the 61st quarter. About 102 million coins at the start of the tail. No premine.

## 6. State and snapshots

- UTXO entry (78 bytes): `txid (32) ‖ index (1) ‖ amount (8) ‖ address (32) ‖ height (4) ‖ coinbase (1)`.
- In blocks whose height is a multiple of 1,440, `utxo_root` is the Merkle root of the leaves `H(UTXO, entry)` of the set after the previous block, sorted by `(txid, index)` in bytes.
- A snapshot is downloaded in chunks of 4,096 consecutive entries, each with its Merkle proof against `utxo_root`.
- Pruning: headers, UTXOs and the last 2,880 full blocks; below that, signatures may be discarded.

## 7. Wallet (outside consensus)

- 24-word phrase with the BIP39 word list and checksum.
- `seed = PBKDF2-HMAC-SHA256(NFKD phrase, "fable" ‖ NFKD passphrase, 2048 rounds, 32 bytes)`.
- For `(account, index)`: `HMAC-SHA256(seed, "fable/0" ‖ u32 account ‖ u32 index)` ‖ the first 16 bytes of `HMAC-SHA256(seed, "fable/1" ‖ u32 account ‖ u32 index)`: 48 bytes used as SK.seed, SK.prf and PK.seed for FIPS 205 key generation.
- Address: Bech32m with the `fb` prefix, 61 characters.

## 8. Node policy (outside consensus, changeable defaults)

- Minimum relay fee 0.001 coin per signature; minimum relayed output 0.001 coin.
- Mempool: cap of 5,000 signatures, ordered by fee per signature, replacement with a higher fee, at most 64 unconfirmed transactions linked to each other.
- Headers accepted only if the chain exceeds a work threshold; message size limits; outbound peers from different /16 networks.

## 9. Network and mining

- P2P over TCP, frames `length (4) ‖ type (1) ‖ content`. Messages: `hello`, `peers`, `inv`, `get`, `tx`, `block`, `headers`, `snap`. Static seeds in the binary. No encryption.
- Stratum v1: `coinb1` = `height`, `extranonce1` + `extranonce2` = 4 + 4 bytes = `extra`, `coinb2` = `utxo_root` ‖ outputs. Version rolling with mask `0x1fffe000`.

## 10. Known limits

- No protocol defence against a 51% attack.
- About 1.3 transactions per second with typical 8 KB transactions.
- History before a snapshot is guaranteed by PoW alone.
- The rules are frozen: a consensus bug can only be fixed by an agreed hard fork.
