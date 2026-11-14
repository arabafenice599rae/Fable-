// Runs every vector in vectors.json through the second implementation.
//   node check_vectors.mjs [vectors.json]
import { readFileSync } from 'node:fs';
import * as F from './fable.mjs';

const v = JSON.parse(readFileSync(process.argv[2] || 'vectors.json', 'utf8'));
const hex = (b) => Buffer.from(b).toString('hex'), bin = (h) => Buffer.from(h, 'hex');
const nets = { main: F.MAIN, test: F.TEST };
let pass = 0;
const fails = [];
const eq = (group, got, want, what = '') => { if (String(got) === String(want)) pass++; else fails.push(`${group} ${what}: got ${got}, want ${want}`); };

const u = v.unit;
for (const c of u.hash) eq('hash', hex(F.H(c.tag, bin(c.data))), c.out);
for (const c of u.sha256d) eq('sha256d', hex(F.sha256d(bin(c.data))), c.out);
for (const c of u.bits) { const t = F.bitsToTarget(c.bits); eq('bits', '0x' + t.toString(16), c.target, c.bits); eq('bits back', F.targetToBits(t), c.back, c.bits); }
for (const c of u.asert) eq('asert', F.asertBits(nets[c.net], c.height, c.time), c.bits, `${c.net} h=${c.height} t=${c.time}`);
for (const c of u.subsidy) eq('subsidy', F.subsidy(c.height), c.units, c.height);
for (const c of u.time) eq('time', F.fullTime(c.prev, c.time32), c.full, c.prev);
for (const c of u.merkle) eq('merkle', hex(F.merkleRoot(c.leaves.map(bin))), c.root, c.leaves.length);
for (const c of u.merkle) {                                   // fold the branch the way a Stratum miner does
  if (!c.leaves.length) continue;
  let h = bin(c.leaves[0]);
  for (const s of c.coinbase_branch) h = F.sha256d(Buffer.concat([h, bin(s)]));
  eq('merkle branch', hex(h), c.root, c.leaves.length);
}
for (const c of u.tx) {
  const raw = bin(c.raw), blk = F.readBlock(Buffer.concat([Buffer.alloc(80), Buffer.alloc(44), Buffer.from([1]), Buffer.alloc(7, 1), Buffer.alloc(33, 1), Buffer.from([1]), raw]));
  const tx = blk.txs[0];
  eq('tx size', raw.length, c.size); eq('tx roundtrip', hex(F.txSerialize(tx)), c.raw, 'bytes'); eq('txid', hex(F.txId(tx)), c.txid);
  eq('sighash', hex(F.sigHash(tx, F.MAIN.chainId)), c.sighash_main); eq('leaf', hex(F.txLeaf(tx)), c.leaf);
}
for (const c of u.genesis) { eq('genesis', hex(nets[c.net].genesis), c.header, c.net); eq('chain id', hex(nets[c.net].chainId), c.chain_id, c.net); }

const w = v.wallet, seed = F.seedFromMnemonic(w.mnemonic);
eq('wallet seed', hex(seed), w.seed);
for (const k of w.keys) {
  const ks = F.keySeed(seed, k.account, k.index), kp = F.keygen(ks), addr = F.address(Buffer.from(kp.publicKey));
  eq('key seed', hex(ks), k.key_seed, k.index); eq('public key', hex(kp.publicKey), k.public_key, k.index);
  eq('address hash', hex(addr), k.address_hash, k.index); eq('address', F.encodeAddress(addr), k.address, k.index);
  eq('address decode', hex(F.decodeAddress(k.address)), k.address_hash, k.index);
}
for (const a of w.address_errors) eq('address error', F.decodeAddress(a), null, a);
{
  const s = w.signature, kp = F.keygen(F.keySeed(seed, 0, 0));
  eq('signature verifies', F.verifySig(bin(s.public_key), bin(s.message), bin(s.signature)), true);
  eq('signature is byte-identical', hex(F.sign(bin(s.message), kp.secretKey)), s.signature, 'deterministic signing');
}

const chain = new F.Chain(nets[v.chain.net]);
let applied = 0, rejected = 0;
for (const e of v.chain.events) {
  if (e.op === 'apply') {
    const verdict = chain.verdict(bin(e.block), e.now);
    if (verdict !== 'ok') { fails.push(`block ${e.height} refused: ${verdict}`); break; }
    eq('block hash', hex(chain.apply(bin(e.block), e.now)), e.hash, e.height); applied++;
  } else { eq('reject', chain.verdict(bin(e.block), e.now), e.code, e.name); rejected++; }
}
eq('tip', hex(chain.tip), v.chain.tip); eq('height', chain.height, v.chain.height);
eq('utxo root', hex(F.utxoRoot(chain.utxo)), v.chain.utxo_root); eq('utxo count', chain.utxo.size, v.chain.utxo_count);
eq('supply', [...chain.utxo.values()].reduce((s, e) => s + e.amount, 0n), v.chain.supply);

console.log(`spec ${v.spec}: ${pass} checks passed, ${fails.length} failed (${applied} blocks applied, ${rejected} invalid blocks refused with the expected code)`);
for (const f of fails.slice(0, 20)) console.log('  FAIL', f);
process.exit(fails.length ? 1 : 0);
