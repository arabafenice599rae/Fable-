# P2P messages of the Rust node

The spec (section 9) fixes the frame and the names of the eight messages, not their contents.
This is the format `node/src/p2p.rs` uses. It is a proposal: if it is accepted, the text can go into the spec.

All integers are little-endian and hashes are in SHA-256 byte order, as in the rest of the spec.

## Frame

```
length (4) ‖ type (1) ‖ content
```

`length` counts the content bytes only. The maximum content follows the block limit and is checked before the content is read:

```
max_message = max(max_block_size(h), 327,664)
max_block_size(h) = 207 + max_sigs(h) × 9,587
```

- `h` is one more than the higher of the node's tip and its best header, so that the blocks of a header chain that is ahead of the tip still fit.
- 9,587 bytes is the most one witness can carry: a transaction with 32 inputs, 16 outputs and one witness. A transaction with `w` witnesses is at most `w × 9,587` bytes, so `max_sigs(h)` bounds the block. 207 bytes are the header, the largest coinbase (two outputs) and the transaction counter.
- 327,664 bytes is the largest `snap` reply: 4,096 entries and a proof of up to 255 hashes. A `headers` reply is at most 160,002 bytes, below both.
- At the start that is 767,167 bytes; after 4 years 1,073,951; at the 2,048 cap, 19,634,383.

A message that is too long, does not decode, or has bytes left over closes the connection.

| Type | Name | Content |
| --- | --- | --- |
| 0 | `hello` | `version (4) ‖ chain_id (32) ‖ height (4) ‖ tip (32) ‖ port (2) ‖ nonce (8)` |
| 1 | `peers` | `n (2, ≤ 100) ‖ n × (IPv6 (16) ‖ port (2))`; IPv4 as `::ffff:a.b.c.d`. `n = 0` asks for addresses |
| 2 | `inv` | `kind (1) ‖ n (2, ≤ 1,000) ‖ n × hash (32)`; kind 1 = transaction (txid), 2 = block |
| 3 | `get` | as `inv`; kinds 1 and 2 ask for those objects, kind 3 asks for the headers after a locator |
| 4 | `tx` | the serialized transaction |
| 5 | `block` | the serialized block |
| 6 | `headers` | `n (2, ≤ 2,000) ‖ n × header (80)` |
| 7 | `snap` | subtype (1) and fields, below |

`version` is 1. `port` is the one the node listens on, 0 if it does not listen. `nonce` is random per process and is used to detect a connection to oneself.

## Exchange

1. The side that opens the connection sends `hello`; the other answers with its own. A different `chain_id` closes the connection, and no other message is valid before `hello`.
2. Each side asks for headers (`get` kind 3) with a locator: the hashes of its active chain from the tip backwards, the first 10 one by one, then with a doubling step, and the genesis last.
   The reply holds up to 2,000 headers of the active chain after the first locator hash the replying side recognises. With 2,000 headers, more are requested.
3. Every header is checked against its parent (time, ASERT `bits`, proof of work) before it enters the index. A header with wrong `bits` or proof of work closes the connection.
4. When the best header chain has more work than the tip, the node asks for the missing blocks (`get` kind 2), at most 16 per peer and only from peers that announced them. A request with no answer within 30 seconds becomes available again.
5. A new block on the active chain is announced with `inv` kind 2 of the tip hash. A node that does not know it asks for the headers, then the block.
6. A transaction accepted into the mempool is announced with `inv` kind 1. After `hello` each side announces its mempool.

## Snapshots (`snap`)

| Subtype | Fields |
| --- | --- |
| 0 request | `height (4) ‖ chunk (4)` |
| 1 chunk | `height (4) ‖ chunk (4) ‖ total entries (4) ‖ n (2) ‖ n × UTXO entry (78) ‖ m (1) ‖ m × hash (32)` |
| 2 not available | `height (4) ‖ chunk (4)` |

`height` is a multiple of 1,440: the snapshot is the set the block at that height commits to in its `utxo_root`, that is the set after the previous block.
Chunk `k` holds the entries from `4,096·k` to `4,096·k + 4,095`, in `(txid, index)` order.

The proof relies on 4,096 being 2^12: chunk `k` is the node at index `k` on level 12 of the section 6 Merkle tree, and its root is `merkle_root` of its leaves `H(UTXO, entry)`.
The proof lists the siblings from level 12 up to the root, skipping the levels where the node is unpaired and moves up unchanged.
Checking it needs only `k` and the total number of entries: from those, the number of nodes on every level is known, and so whether the sibling exists.
The functions are `chunk_proof` and `chunk_root` in `node/src/consensus.rs`.
