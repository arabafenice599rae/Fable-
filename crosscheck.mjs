// Second half of the differential test: recompute everything crosscheck.py produced and compare.
import { readFileSync } from 'node:fs';
import * as F from './fable.mjs';

const d = JSON.parse(readFileSync(process.argv[2], 'utf8'));
const v = JSON.parse(readFileSync('vectors.json', 'utf8'));
const bin = (h) => Buffer.from(h, 'hex'), hex = (b) => Buffer.from(b).toString('hex');
const nets = { main: F.MAIN, test: F.TEST };
const counts = {}, diffs = [];
const cmp = (group, got, want, what) => { counts[group] = (counts[group] || 0) + 1; if (String(got) !== String(want)) diffs.push(`${group} ${what}: second=${got} reference=${want}`); };

const n = d.numeric;
for (const [net, h, t, bits] of n.asert) cmp('asert', F.asertBits(nets[net], h, t), bits, `${net} h=${h} t=${t}`);
for (const [target, bits, back] of n.bits) { cmp('bits', F.targetToBits(BigInt(target)), bits, target); cmp('bits', '0x' + F.bitsToTarget(bits).toString(16), back, bits); }
for (const [h, units] of n.subsidy) cmp('subsidy', F.subsidy(h), units, h);
for (const [prev, t32, full] of n.time) cmp('time', F.fullTime(prev, t32), full, `${prev} ${t32}`);
for (const [leaves, root] of n.merkle) cmp('merkle', hex(F.merkleRoot(leaves.map(bin))), root, leaves.length);
for (const [s, want] of n.address) { const got = F.decodeAddress(s); cmp('address', got ? hex(got) : null, want, s); }

const chain = new F.Chain(F.TEST);
const byHeight = new Map(d.blocks.map((b) => [b.height, b]));
for (const e of v.chain.events) {
  if (e.op !== 'apply') continue;
  const set = byHeight.get(chain.height);
  if (set) for (const [raw, code] of set.cases) cmp('block', chain.verdict(bin(raw), set.now), code, `at height ${set.height}`);
  chain.apply(bin(e.block), e.now);
}
console.log('compared:', JSON.stringify(counts));
console.log(diffs.length ? `DISAGREEMENTS: ${diffs.length}` : 'the two implementations agree on every case');
for (const x of diffs.slice(0, 15)) console.log('  ', x);
process.exit(diffs.length ? 1 : 0);
