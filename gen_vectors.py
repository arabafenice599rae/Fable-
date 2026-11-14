"""Builds vectors.json from the reference implementation: unit vectors, wallet vectors,
and one simulated chain with valid blocks and hand-made invalid ones."""
import json
import random
import struct
import subprocess
import sys

import slhdsa

import fable as F

MNEMONIC = 'abandon ' * 23 + 'art'
hx = lambda b: b.hex()


def node_keygen(seed48):
    out = subprocess.run(['node', 'cli.mjs', 'keygen', seed48.hex()], capture_output=True, text=True, check=True).stdout
    d = json.loads(out)
    return bytes.fromhex(d['pk']), bytes.fromhex(d['sk'])


class Key:
    def __init__(self, seed, account, index):
        self.seed48 = F.key_seed(seed, account, index)
        self.pk, self.sk = node_keygen(self.seed48)
        self.addr = F.address(self.pk)
        self._sk = slhdsa.SecretKey.from_digest(self.sk, slhdsa.sha2_128s)

    def sign(self, msg):
        return self._sk.sign_pure(msg)


def sign_tx(tx, keys, chain_id):
    msg = tx.sighash(chain_id)
    tx.wits = [(k.pk, k.sign(msg)) for k in keys]
    return tx


def build_block(chain, time32, outs, txs=(), *, height=None, utxo_root=None, bits=None, prev=None, extra=bytes(8), want_pow=True, version=0x20000000):
    """Assemble and mine a block on top of chain. Keyword arguments override single fields, to make invalid blocks."""
    cb = F.Coinbase(chain.height + 1 if height is None else height, extra,
                    chain.next_utxo_root() if utxo_root is None else utxo_root, outs)
    blk = F.Block(b'', cb, list(txs))
    root = F.merkle_root(blk.leaves())
    bits = chain.next_bits() if bits is None else bits
    target = F.bits_to_target(bits)
    nonce = 0
    while True:
        blk.header = F.make_header(version, chain.tip if prev is None else prev, root, time32, bits, nonce)
        ok = int.from_bytes(F.sha256d(blk.header), 'little') <= target
        if ok == want_pow:
            return blk
        nonce += 1


def remine(chain, raw):
    """Recompute the merkle root of a (possibly altered) block and mine it again. None if it no longer parses."""
    try:
        blk = F.read_block(raw)
    except F.Invalid:
        return None
    version, prev, _, time32, bits, _ = struct.unpack('<I32s32sIII', blk.header)
    root = F.merkle_root(blk.leaves())
    try:
        target = F.bits_to_target(bits)
    except F.Invalid:
        return None
    for nonce in range(1 << 20):
        blk.header = F.make_header(version, prev, root, time32, bits, nonce)
        if int.from_bytes(F.sha256d(blk.header), 'little') <= target:
            return blk.serialize()
    return None


def unit_vectors(rng):
    v = {}
    v['hash'] = [{'tag': t, 'data': hx(d), 'out': hx(F.H(t, d))} for t, d in [(1, b''), (2, b'fable'), (6, bytes(range(64)))]]
    v['sha256d'] = [{'data': hx(d), 'out': hx(F.sha256d(d))} for d in (b'', b'fable', bytes(80))]
    v['bits'] = [{'bits': b, 'target': hex(F.bits_to_target(b)), 'back': F.target_to_bits(F.bits_to_target(b))}
                 for b in (0x1B040000, 0x1D00FFFF, 0x207FFFFF, 0x1A05DB8B, 0x03123456, 0x02008000, 0x01120000, 0x04923456 & 0xFF7FFFFF)]
    cases = [(0, F.MAIN.genesis_time), (1, F.MAIN.genesis_time + 60), (100, F.MAIN.genesis_time + 6000), (100, F.MAIN.genesis_time + 6000 + 3600),
             (100, F.MAIN.genesis_time + 6000 - 3600), (1000, F.MAIN.genesis_time + 1000), (1000, F.MAIN.genesis_time + 10 ** 7),
             (10 ** 6, F.MAIN.genesis_time + 60 * 10 ** 6 + 12345), (50, F.MAIN.genesis_time - 10 ** 6), (5, F.MAIN.genesis_time + 2 ** 33)]
    for _ in range(40):
        h = rng.randrange(0, 5 * 10 ** 6)
        cases.append((h, F.MAIN.genesis_time + 60 * h + rng.randrange(-200000, 200000)))
    v['asert'] = [{'net': n.name, 'height': h, 'time': t, 'bits': F.asert_bits(n, h, t)} for n in (F.MAIN, F.TEST) for h, t in cases]
    hs = [0, 1, 2, 43199, 43200, 43201, 131399, 131400, 131401, 262800, 61 * 131400 - 1, 61 * 131400, 62 * 131400, 10 ** 8, 2 ** 32 - 1]
    v['subsidy'] = [{'height': h, 'units': str(F.subsidy(h))} for h in hs]
    v['time'] = [{'prev': p, 'time32': t, 'full': F.full_time(p, t)} for p, t in
                 [(1794441600, 1794441660), (1794441600, 1794441600), (2 ** 32 - 10, 5), (2 ** 32 + 100, 100), (2 ** 32 + 100, 101), (3 * 2 ** 32 + 7, 6), (5 * 10 ** 12, 0)]]
    v['merkle'] = []
    for n in list(range(0, 10)) + [16, 17, 33]:
        leaves = [F.sha256(bytes([n, i])) for i in range(n)]
        v['merkle'].append({'leaves': [hx(x) for x in leaves], 'root': hx(F.merkle_root(leaves)), 'coinbase_branch': [hx(x) for x in F.coinbase_branch(leaves)]})
    v['tx'] = []
    for n_in, n_out, n_wit in [(1, 1, 1), (1, 2, 1), (2, 2, 1), (2, 2, 2), (2, 1, 2), (5, 4, 3), (32, 4, 4), (32, 1, 1), (3, 16, 2), (32, 16, 4)]:
        tx = F.Tx([(rng.randbytes(32), i % 16) for i in range(n_in)], [(rng.randrange(1, 10 ** 12), rng.randbytes(32)) for _ in range(n_out)],
                  [(rng.randbytes(32), rng.randbytes(F.SIG_LEN)) for _ in range(n_wit)])
        v['tx'].append({'raw': hx(tx.serialize()), 'size': len(tx.serialize()), 'txid': hx(tx.txid()), 'sighash_main': hx(tx.sighash(F.MAIN.chain_id)), 'leaf': hx(tx.leaf())})
    v['genesis'] = [{'net': n.name, 'header': hx(n.genesis), 'chain_id': hx(n.chain_id)} for n in (F.MAIN, F.TEST)]
    return v


def wallet_vectors():
    seed = F.seed_from_mnemonic(MNEMONIC)
    keys = [Key(seed, 0, i) for i in range(3)]
    v = {'mnemonic': MNEMONIC, 'seed': hx(seed), 'keys': [], 'address_errors': []}
    for i, k in enumerate(keys):
        v['keys'].append({'account': 0, 'index': i, 'key_seed': hx(k.seed48), 'public_key': hx(k.pk), 'address_hash': hx(k.addr), 'address': F.encode_address(k.addr)})
    good = F.encode_address(keys[0].addr)
    for bad in (good[:-1] + ('q' if good[-1] != 'q' else 'p'), good[:10] + good[11:], 'bc' + good[2:], good.replace('1', '2', 1)):
        assert F.decode_address(bad) is None
        v['address_errors'].append(bad)
    assert F.decode_address(good) == keys[0].addr and F.decode_address(good.upper()) == keys[0].addr
    msg = F.sha256(b'fable signature vector')
    sig = keys[0].sign(msg)
    v['signature'] = {'public_key': hx(keys[0].pk), 'message': hx(msg), 'signature': hx(sig), 'deterministic': True}
    return v, keys


def chain_vectors(keys, rng, tip_height=1445):
    k0, k1, k2 = keys
    net = F.TEST
    c = F.Chain(net)
    events, t = [], net.genesis_time
    cb = {}                                            # height -> coinbase txid

    def step(txs=(), outs=None):
        nonlocal t
        t += rng.randint(20, 100)
        h = c.height + 1
        fees = 0
        for tx in txs:
            fees += tx._fee
        outs = outs or [(F.subsidy(h) + fees, k0.addr)]
        blk = build_block(c, t & 0xFFFFFFFF, outs, txs)
        raw = blk.serialize()
        c.apply(raw, t)
        cb[h] = blk.coinbase.txid()
        events.append({'op': 'apply', 'now': t, 'block': hx(raw), 'hash': hx(c.tip), 'height': c.height})
        return blk

    def reject(name, raw, now=None):
        code = c.verdict(raw, t + 60 if now is None else now)
        assert code != 'ok', name
        events.append({'op': 'reject', 'name': name, 'now': t + 60 if now is None else now, 'block': hx(raw), 'code': code})
        return code

    def mk(ins, outs, signers, fee):
        tx = sign_tx(F.Tx(ins, outs, []), signers, net.chain_id)
        tx._fee = fee
        return tx

    while c.height < 4:
        step()
    step(outs=[(F.subsidy(5) - 1000, k0.addr), (1000, k1.addr)])            # two coinbase outputs
    while c.height < 101:
        step()
    s = F.subsidy
    tx1 = mk([(cb[1], 0)], [(50000, k1.addr), (60000, k0.addr)], [k0], s(1) - 110000)
    step([tx1])                                                              # 102: one input, two outputs
    tx2 = mk([(cb[2], 0), (cb[3], 0)], [(400000, k2.addr), (170000, k1.addr)], [k0], s(2) + s(3) - 570000)
    step([tx2])                                                              # 103: two inputs of one address, one witness
    tx3 = mk([(tx1.txid(), 0), (tx1.txid(), 1)], [(100000, k2.addr)], [k1, k0], 10000)
    tx4 = mk([(tx3.txid(), 0)], [(99000, k0.addr)], [k2], 1000)
    step([tx3, tx4])                                                         # 104: two witnesses, then a spend inside the same block
    assert c.height == 104

    # ---- invalid blocks, each tried against the tip at height 104
    nt = (t + 60) & 0xFFFFFFFF
    pay = lambda extra=0: [(s(105) + extra, k0.addr)]
    dummy = (k0.pk, bytes(F.SIG_LEN))
    good = mk([(cb[4], 0)], [(s(4) - 500, k1.addr)], [k0], 500)
    reject('wrong previous hash', build_block(c, nt, pay(), prev=bytes(32)).serialize())
    reject('time too far ahead', build_block(c, nt, pay()).serialize(), now=t + 60 - 601)
    reject('wrong bits', build_block(c, nt, pay(), bits=0x207FFFFE).serialize())
    reject('proof of work not met', build_block(c, nt, pay(), want_pow=False).serialize())
    b = build_block(c, nt, pay())
    b.coinbase.extra = b'\x01' * 8
    reject('merkle root does not match', b.serialize())
    reject('coinbase height wrong', build_block(c, nt, pay(), height=106).serialize())
    reject('utxo root set outside a snapshot height', build_block(c, nt, pay(), utxo_root=b'\x01' * 32).serialize())
    reject('coinbase pays one unit too much', build_block(c, nt, pay(1)).serialize())
    reject('trailing byte', build_block(c, nt, pay()).serialize() + b'\x00')
    raw = bytearray(build_block(c, nt, pay()).serialize())
    raw[80 + 44] = 3
    reject('three coinbase outputs', bytes(raw))
    reject('input does not exist', build_block(c, nt, pay(), [F.Tx([(bytes(32), 0)], [(1, k0.addr)], [dummy])]).serialize())
    reject('coinbase spent before maturity', build_block(c, nt, pay(), [F.Tx([(cb[104], 0)], [(1, k0.addr)], [dummy])]).serialize())
    reject('witness key does not match the address', build_block(c, nt, pay(), [F.Tx([(cb[4], 0)], [(1, k0.addr)], [(k1.pk, bytes(F.SIG_LEN))])]).serialize())
    reject('same key given as two witnesses', build_block(c, nt, pay(), [F.Tx([(cb[4], 0), (cb[5], 0)], [(1, k0.addr)], [dummy, dummy])]).serialize())
    reject('signature of zeros', build_block(c, nt, pay(), [F.Tx([(cb[4], 0)], [(1, k0.addr)], [dummy])]).serialize())
    flipped = F.Tx(good.ins, good.outs, [(k0.pk, good.wits[0][1][:4000] + bytes([good.wits[0][1][4000] ^ 1]) + good.wits[0][1][4001:])])
    reject('one signature bit flipped', build_block(c, nt, pay(), [flipped]).serialize())
    other = sign_tx(F.Tx(good.ins, good.outs, []), [k0], F.MAIN.chain_id)
    reject('signature made for another chain', build_block(c, nt, pay(), [other]).serialize())
    over = sign_tx(F.Tx([(cb[4], 0)], [(s(4) + 1, k1.addr)], []), [k0], net.chain_id)
    reject('outputs exceed inputs', build_block(c, nt, pay(), [over]).serialize())
    reject('same output spent twice in one block', build_block(c, nt, pay(500), [good, good]).serialize())
    reject('fee claimed but transaction left out', build_block(c, nt, pay(500)).serialize())
    step([good])                                                             # 105: the valid version goes in
    reject('output already spent in an earlier block', build_block(c, (t + 60) & 0xFFFFFFFF, [(s(106) + 500, k0.addr)], [good]).serialize())

    while c.height < 129:                                                    # let coinbases 6 to 21 mature
        step()
    # ---- larger transactions: 16 coinbase outputs of one address consolidated with one witness,
    #      then four inputs from three addresses spent with three witnesses, in the same block
    ins5 = [(cb[i], 0) for i in range(6, 22)]
    total5 = sum(s(i) for i in range(6, 22))
    q = (total5 - 2000) // 4
    outs5 = [(q, k1.addr), (q, k0.addr), (q, k2.addr), (total5 - 2000 - 3 * q, k0.addr)]
    tx5 = mk(ins5, outs5, [k0], 2000)
    ins6 = [(tx5.txid(), 0), (tx5.txid(), 1), (tx5.txid(), 2), (tx5.txid(), 3)]
    tx6 = mk(ins6, [(total5 - 5000, k0.addr)], [k1, k0, k2], 3000)
    nt = (t + 60) & 0xFFFFFFFF
    pay = lambda extra=0: [(s(130) + extra, k0.addr)]
    wrong = F.Tx(tx6.ins, tx6.outs, [tx6.wits[1], tx6.wits[0], tx6.wits[2]])
    reject('witnesses in the wrong order', build_block(c, nt, pay(5000), [tx5, wrong]).serialize())
    extra_wit = F.Tx(tx5.ins, tx5.outs, tx5.wits + [(k1.pk, bytes(F.SIG_LEN))])
    reject('unused extra witness', build_block(c, nt, pay(2000), [extra_wit]).serialize())
    reject('33 inputs', build_block(c, nt, pay(), [F.Tx([(cb[i], 0) for i in range(6, 39)], [(1, k0.addr)], [dummy])]).serialize())
    reject('17 outputs', build_block(c, nt, pay(), [F.Tx([(cb[6], 0)], [(1, k0.addr)] * 17, [dummy])]).serialize())
    reject('input listed twice', build_block(c, nt, pay(), [F.Tx([(cb[6], 0), (cb[7], 0), (cb[6], 0)], [(1, k0.addr)], [dummy])]).serialize())
    reject('output index 16', build_block(c, nt, pay(), [F.Tx([(cb[6], 16)], [(1, k0.addr)], [dummy])]).serialize())
    step([tx5, tx6])                                                         # 130
    assert c.height == 130

    # ---- one payer, sixteen outputs; then outputs 10 and 15 are spent (two-digit indexes)
    total6 = total5 - 5000
    each = (total6 - 1000) // 16
    outs7 = [(each, [k0, k1, k2][i % 3].addr) for i in range(15)] + [(total6 - 1000 - 15 * each, k1.addr)]
    tx7 = mk([(tx6.txid(), 0)], outs7, [k0], 1000)
    step([tx7])                                                              # 131
    tx8 = mk([(tx7.txid(), 10), (tx7.txid(), 15)], [(each, k2.addr), (outs7[15][0] - 1500, k0.addr)], [k1], 1500)
    step([tx8])                                                              # 132

    while c.height < tip_height:
        step()
        if c.height == 1439:                                                 # the block at 1440 must carry the snapshot root
            n2 = (t + 60) & 0xFFFFFFFF
            reject('snapshot root missing', build_block(c, n2, [(s(1440), k0.addr)], utxo_root=bytes(32)).serialize())
            reject('snapshot root wrong', build_block(c, n2, [(s(1440), k0.addr)], utxo_root=F.sha256(b'x')).serialize())
    return {'net': net.name, 'events': events, 'tip': hx(c.tip), 'height': c.height, 'utxo_root': hx(F.utxo_root(c.utxo)),
            'utxo_count': len(c.utxo), 'supply': str(sum(e[0] for e in c.utxo.values()))}


def main():
    rng = random.Random(20261111)
    out = {'spec': 'v0.12', 'unit': unit_vectors(rng)}
    out['wallet'], keys = wallet_vectors()
    out['chain'] = chain_vectors(keys, rng)
    json.dump(out, open('vectors.json', 'w'), separators=(',', ':'))
    ev = out['chain']['events']
    print('vectors.json written:', sum(len(x) for x in out['unit'].values()), 'unit vectors,', sum(e['op'] == 'apply' for e in ev), 'valid blocks,',
          sum(e['op'] == 'reject' for e in ev), 'invalid blocks')
    for e in ev:
        if e['op'] == 'reject':
            print('  %-10s %s' % (e['code'], e['name']))


if __name__ == '__main__':
    sys.exit(main())
