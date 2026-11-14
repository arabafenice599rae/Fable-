// Fable: second implementation of the consensus rules, spec v0.11.
// Written separately from fable.py, in another language and on another SLH-DSA library,
// so that the two can be run against each other.
import { createHash, createHmac, pbkdf2Sync } from 'node:crypto';
import { slh_dsa_sha2_128s as SLH } from '@noble/post-quantum/slh-dsa.js';

export const TAG = { TX: 1, SIG: 2, LEAF: 3, WIT: 4, ADDR: 5, UTXO: 6 };
export const COIN = 100000000n;
const MAX_AMOUNT = 1n << 62n;
const BLOCK_TIME = 60n, HALFLIFE = 3600n, FUTURE_LIMIT = 600;
const QUARTER = 131400, SLOW_START = 43200, MATURITY = 100, SNAPSHOT_EVERY = 1440, MAX_SIGS = 80;
const MAX_IN = 32, MAX_OUT = 4, MAX_WIT = 4, MAX_CB_OUT = 2;
const PK_LEN = 32, SIG_LEN = 7856;
const ZERO32 = Buffer.alloc(32);

export class Invalid extends Error { constructor(code) { super(code); this.code = code; } }
const bad = (code) => { throw new Invalid(code); };

export const sha256 = (b) => createHash('sha256').update(b).digest();
export const sha256d = (b) => sha256(sha256(b));
export const H = (tag, b) => sha256(Buffer.concat([Buffer.from([tag]), b]));
const u32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32LE(n >>> 0); return b; };
const u64 = (n) => { const b = Buffer.alloc(8); b.writeBigUInt64LE(n); return b; };
const key = (txid, idx) => Buffer.from(txid).toString('hex') + String(idx);   // idx is one digit, 0-3: sorts like the raw bytes
const leInt = (buf) => BigInt('0x' + Buffer.from(buf).reverse().toString('hex'));

// ---------------------------------------------------------------- networks
export function makeHeader(version, prev, merkle, time32, bits, nonce) {
  return Buffer.concat([u32(version), prev, merkle, u32(time32), u32(bits), u32(nonce)]);
}
export function net(name, genesisTime, genesisBits, maxBits, genesisPrev = ZERO32) {
  const genesis = makeHeader(1, genesisPrev, ZERO32, genesisTime % 4294967296, genesisBits, 0);
  return { name, genesisTime, genesisBits, maxBits, genesis, chainId: sha256d(genesis) };
}
export const MAIN = net('main', 1794441600, 0x1b040000, 0x1d00ffff);
export const TEST = net('test', 1794441600, 0x207fffff, 0x207fffff);

// ---------------------------------------------------------------- compact targets
export function bitsToTarget(bits) {
  const exp = bits >>> 24, mant = BigInt(bits & 0x007fffff);
  if (bits & 0x00800000) bad('bits');
  return exp <= 3 ? mant >> BigInt(8 * (3 - exp)) : mant << BigInt(8 * (exp - 3));
}
export function targetToBits(target) {
  let size = Math.ceil(target.toString(2).length / 8);
  if (target === 0n) size = 0;
  let c = size <= 3 ? target << BigInt(8 * (3 - size)) : target >> BigInt(8 * (size - 3));
  if (c & 0x00800000n) { c >>= 8n; size += 1; }
  return Number(c) + size * 16777216;
}

// ---------------------------------------------------------------- difficulty
export function asertBits(n, parentHeight, parentTime) {
  const anchor = bitsToTarget(n.genesisBits), maxTarget = bitsToTarget(n.maxBits);
  const timeDelta = BigInt(parentTime) - (BigInt(n.genesisTime) - BLOCK_TIME);
  const num = (timeDelta - BLOCK_TIME * (BigInt(parentHeight) + 1n)) * 65536n;
  let exponent = num / HALFLIFE;                       // BigInt division truncates toward zero
  let shifts = exponent >> 16n;                        // arithmetic shift
  exponent -= shifts * 65536n;
  if (shifts > 300n) return n.maxBits;
  if (shifts < -300n) return targetToBits(1n);
  const factor = ((195766423245049n * exponent + 971821376n * exponent ** 2n + 5127n * exponent ** 3n + (1n << 47n)) >> 48n) + 65536n;
  let nt = anchor * factor;
  nt = shifts >= 0n ? nt << shifts : nt >> -shifts;
  nt >>= 16n;
  if (nt === 0n) return targetToBits(1n);
  if (nt > maxTarget) return n.maxBits;
  return targetToBits(nt);
}

// ---------------------------------------------------------------- emission
export function subsidy(height) {
  let r = 50n * COIN;
  const steps = Math.floor(height / QUARTER);
  for (let i = 0; i < steps; i++) {
    r -= r >> 4n;
    if (r < COIN) { r = COIN; break; }
  }
  if (height < SLOW_START) r = r * BigInt(height) / BigInt(SLOW_START);
  return r;
}

// ---------------------------------------------------------------- time
export function fullTime(prevTime, time32) {
  let t = Math.floor(prevTime / 4294967296) * 4294967296 + time32;
  if (t <= prevTime) t += 4294967296;
  return t;
}

// ---------------------------------------------------------------- merkle
export function merkleRoot(leaves) {
  if (leaves.length === 0) return ZERO32;
  let level = leaves.slice();
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i + 1 < level.length; i += 2) next.push(sha256d(Buffer.concat([level[i], level[i + 1]])));
    if (level.length % 2) next.push(level[level.length - 1]);
    level = next;
  }
  return level[0];
}

// ---------------------------------------------------------------- parsing
class Reader {
  constructor(buf) { this.b = buf; this.o = 0; }
  take(n) { if (this.o + n > this.b.length) bad('parse'); const v = this.b.subarray(this.o, this.o + n); this.o += n; return v; }
  u8() { return this.take(1)[0]; }
  u32() { return this.take(4).readUInt32LE(); }
  u64() { return this.take(8).readBigUInt64LE(); }
}
function readOutputs(r, limit) {
  const n = r.u8();
  if (n < 1 || n > limit) bad('parse');
  const outs = [];
  for (let i = 0; i < n; i++) {
    const amount = r.u64(), addr = r.take(32);
    if (amount < 1n || amount > MAX_AMOUNT) bad('parse');
    outs.push({ amount, addr });
  }
  return outs;
}
const serOutputs = (outs) => Buffer.concat([Buffer.from([outs.length]), ...outs.map((o) => Buffer.concat([u64(o.amount), o.addr]))]);

export const txBody = (tx) => Buffer.concat([Buffer.from([tx.ins.length]), ...tx.ins.map((i) => Buffer.concat([i.txid, Buffer.from([i.idx])])), serOutputs(tx.outs)]);
export const txWitness = (tx) => Buffer.concat([Buffer.from([tx.wits.length]), ...tx.wits.map((w) => Buffer.concat([w.pk, w.sig]))]);
export const txSerialize = (tx) => Buffer.concat([txBody(tx), txWitness(tx)]);
export const txId = (tx) => H(TAG.TX, txBody(tx));
export const sigHash = (tx, chainId) => H(TAG.SIG, Buffer.concat([chainId, txBody(tx)]));
export const txLeaf = (tx) => H(TAG.LEAF, Buffer.concat([txId(tx), H(TAG.WIT, txWitness(tx))]));

function readTx(r) {
  const nIn = r.u8();
  if (nIn < 1 || nIn > MAX_IN) bad('parse');
  const ins = [], seen = new Set();
  for (let i = 0; i < nIn; i++) {
    const txid = r.take(32), idx = r.u8();
    if (idx >= MAX_OUT) bad('parse');
    const k = key(txid, idx);
    if (seen.has(k)) bad('parse');
    seen.add(k);
    ins.push({ txid, idx });
  }
  const outs = readOutputs(r, MAX_OUT);
  const nWit = r.u8();
  if (nWit < 1 || nWit > Math.min(MAX_WIT, nIn)) bad('parse');
  const wits = [];
  for (let i = 0; i < nWit; i++) wits.push({ pk: r.take(PK_LEN), sig: r.take(SIG_LEN) });
  return { ins, outs, wits };
}
export const coinbaseSerialize = (cb) => Buffer.concat([u32(cb.height), cb.extra, cb.utxoRoot, serOutputs(cb.outs)]);
export const coinbaseId = (cb) => sha256d(coinbaseSerialize(cb));
function readCoinbase(r) { return { height: r.u32(), extra: r.take(8), utxoRoot: r.take(32), outs: readOutputs(r, MAX_CB_OUT) }; }

export function readBlock(buf) {
  const r = new Reader(buf);
  const header = r.take(80), coinbase = readCoinbase(r), n = r.u8();
  if (n > MAX_SIGS) bad('parse');
  const txs = [];
  for (let i = 0; i < n; i++) txs.push(readTx(r));
  if (r.o !== buf.length) bad('parse');
  return { header, coinbase, txs };
}
export const blockSerialize = (b) => Buffer.concat([b.header, coinbaseSerialize(b.coinbase), Buffer.from([b.txs.length]), ...b.txs.map(txSerialize)]);

// ---------------------------------------------------------------- signatures and addresses
export const address = (pk) => H(TAG.ADDR, pk);
export function verifySig(pk, msg, sig) {
  try { return SLH.verify(sig, msg, pk) === true; } catch { return false; }
}
export const keygen = (seed48) => SLH.keygen(seed48);
export const sign = (msg, secretKey) => Buffer.from(SLH.sign(msg, secretKey, { extraEntropy: false }));

// ---------------------------------------------------------------- state
export function utxoRoot(utxo) {
  const keys = [...utxo.keys()].sort();                // hex of txid, then index: the same order as the raw bytes
  return merkleRoot(keys.map((k) => {
    const e = utxo.get(k);
    return H(TAG.UTXO, Buffer.concat([Buffer.from(k.slice(0, 64), 'hex'), Buffer.from([Number(k[64])]), u64(e.amount), e.addr, u32(e.height), Buffer.from([e.cb ? 1 : 0])]));
  }));
}

export class Chain {
  constructor(n) { this.net = n; this.height = 0; this.tip = sha256d(n.genesis); this.time = n.genesisTime; this.utxo = new Map(); }
  nextBits() { return asertBits(this.net, this.height, this.time); }
  nextUtxoRoot() { return (this.height + 1) % SNAPSHOT_EVERY === 0 ? utxoRoot(this.utxo) : ZERO32; }

  check(raw, now) {
    const blk = readBlock(raw), h = this.height + 1, hd = blk.header;
    const prev = hd.subarray(4, 36), mroot = hd.subarray(36, 68), time32 = hd.readUInt32LE(68), bits = hd.readUInt32LE(72);
    if (!prev.equals(this.tip)) bad('prev');
    const t = fullTime(this.time, time32);
    if (t > now + FUTURE_LIMIT) bad('time');
    if (bits !== this.nextBits()) bad('bits');
    const blockHash = sha256d(hd);
    if (leInt(blockHash) > bitsToTarget(bits)) bad('pow');
    if (!mroot.equals(merkleRoot([coinbaseId(blk.coinbase), ...blk.txs.map(txLeaf)]))) bad('merkle');
    if (blk.coinbase.height !== h) bad('cbheight');
    if (!blk.coinbase.utxoRoot.equals(this.nextUtxoRoot())) bad('utxoroot');
    if (blk.txs.reduce((s, x) => s + x.wits.length, 0) > MAX_SIGS) bad('sigs');

    const view = new Map(), spent = new Set();
    let fees = 0n;
    for (const tx of blk.txs) {
      let totalIn = 0n;
      const addrs = [];
      for (const i of tx.ins) {
        const k = key(i.txid, i.idx);
        if (spent.has(k)) bad('missing');
        const e = view.get(k) ?? this.utxo.get(k);
        if (!e) bad('missing');
        if (e.cb && h < e.height + MATURITY) bad('immature');
        totalIn += e.amount;
        addrs.push(e.addr);
      }
      // witnesses: the distinct input addresses, in order of first appearance
      const want = [];
      for (const a of addrs) if (!want.some((w) => w.equals(a))) want.push(a);
      const wa = tx.wits.map((w) => address(w.pk));
      if (wa.length !== want.length || wa.some((a, i) => !a.equals(want[i]))) bad('witness');
      const msg = sigHash(tx, this.net.chainId);
      for (const w of tx.wits) if (!verifySig(w.pk, msg, w.sig)) bad('sig');
      const totalOut = tx.outs.reduce((s, o) => s + o.amount, 0n);
      if (totalOut > totalIn) bad('value');
      fees += totalIn - totalOut;
      const id = txId(tx);
      for (const i of tx.ins) spent.add(key(i.txid, i.idx));
      tx.outs.forEach((o, n) => {
        const k = key(id, n);
        if (view.has(k) || this.utxo.has(k)) bad('dup');
        view.set(k, { amount: o.amount, addr: Buffer.from(o.addr), height: h, cb: false });
      });
    }
    if (blk.coinbase.outs.reduce((s, o) => s + o.amount, 0n) > subsidy(h) + fees) bad('cbvalue');
    const cbid = coinbaseId(blk.coinbase);
    blk.coinbase.outs.forEach((o, n) => {
      const k = key(cbid, n);
      if (view.has(k) || this.utxo.has(k)) bad('dup');
      view.set(k, { amount: o.amount, addr: Buffer.from(o.addr), height: h, cb: true });
    });
    return { blockHash, t, view, spent };
  }

  apply(raw, now) {
    const { blockHash, t, view, spent } = this.check(raw, now);
    for (const k of spent) { if (view.has(k)) view.delete(k); else this.utxo.delete(k); }
    for (const [k, e] of view) this.utxo.set(k, e);
    this.height += 1; this.tip = blockHash; this.time = t;
    return blockHash;
  }

  verdict(raw, now) {
    try { this.check(raw, now); return 'ok'; } catch (e) { if (e instanceof Invalid) return e.code; throw e; }
  }
}

// ---------------------------------------------------------------- wallet standard (outside consensus)
const B32 = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l', BECH32M = 0x2bc830a3;
function polymod(values) {
  const gen = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  let chk = 1;
  for (const v of values) {
    const b = chk >>> 25;
    chk = (((chk & 0x1ffffff) << 5) ^ v) >>> 0;
    for (let i = 0; i < 5; i++) if ((b >>> i) & 1) chk = (chk ^ gen[i]) >>> 0;
  }
  return chk;
}
const hrpExpand = (hrp) => [...hrp].map((c) => c.charCodeAt(0) >> 5).concat([0], [...hrp].map((c) => c.charCodeAt(0) & 31));
function convert(data, from, to, pad) {
  let acc = 0, n = 0;
  const out = [], mask = (1 << to) - 1;
  for (const v of data) {
    acc = ((acc << from) | v) & 0xffffff; n += from;
    while (n >= to) { n -= to; out.push((acc >> n) & mask); }
  }
  if (pad && n) out.push((acc << (to - n)) & mask);
  else if (!pad && (n >= from || ((acc << (to - n)) & mask))) return null;
  return out;
}
export function encodeAddress(addr, hrp = 'fb') {
  const data = convert(addr, 8, 5, true);
  const pm = (polymod(hrpExpand(hrp).concat(data, [0, 0, 0, 0, 0, 0])) ^ BECH32M) >>> 0;
  const chk = [0, 1, 2, 3, 4, 5].map((i) => (pm >>> (5 * (5 - i))) & 31);
  return hrp + '1' + data.concat(chk).map((d) => B32[d]).join('');
}
export function decodeAddress(str, hrp = 'fb') {
  if (str.toLowerCase() !== str && str.toUpperCase() !== str) return null;
  const s = str.toLowerCase(), pos = s.lastIndexOf('1');
  if (s.slice(0, pos) !== hrp) return null;
  const data = [...s.slice(pos + 1)].map((c) => B32.indexOf(c));
  if (data.includes(-1) || data.length < 6 || polymod(hrpExpand(hrp).concat(data)) !== BECH32M) return null;
  const raw = convert(data.slice(0, -6), 5, 8, false);
  return raw && raw.length === 32 ? Buffer.from(raw) : null;
}
export const seedFromMnemonic = (mnemonic, passphrase = '') =>
  pbkdf2Sync(Buffer.from(mnemonic.normalize('NFKD')), Buffer.concat([Buffer.from('fable'), Buffer.from(passphrase.normalize('NFKD'))]), 2048, 32, 'sha256');
export function keySeed(seed, account, index) {
  const path = Buffer.concat([u32(account), u32(index)]);
  const h = (p) => createHmac('sha256', seed).update(Buffer.concat([Buffer.from(p), path])).digest();
  return Buffer.concat([h('fable/0'), h('fable/1').subarray(0, 16)]);
}
