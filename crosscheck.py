"""Differential test: random inputs go through the reference implementation, then the second
implementation must give the same answers. Run after gen_vectors.py.
    python3 crosscheck.py [seed]
"""
import json
import random
import subprocess
import sys

import fable as F
from gen_vectors import remine


def numeric(rng):
    out = {'asert': [], 'bits': [], 'subsidy': [], 'time': [], 'merkle': [], 'address': [], 'max_sigs': []}
    for _ in range(2000):
        h = rng.choice((rng.randrange(0, 2 ** 32), F.SIGS_STEP * rng.randrange(0, 15) + rng.randrange(-2, 3)))
        h = max(h, 0)
        out['max_sigs'].append([h, F.max_sigs(h)])
    for _ in range(20000):
        net = rng.choice((F.MAIN, F.TEST))
        h = rng.choice((rng.randrange(0, 200), rng.randrange(0, 10 ** 7), rng.randrange(0, 2 ** 32)))
        spread = rng.choice((100, 4000, 100000, 10 ** 7, 10 ** 10))
        t = net.genesis_time + 60 * h + rng.randrange(-spread, spread)
        out['asert'].append([net.name, h, t, F.asert_bits(net, h, t)])
    for _ in range(5000):
        target = rng.getrandbits(rng.randrange(1, 257)) or 1
        b = F.target_to_bits(target)
        out['bits'].append([hex(target), b, hex(F.bits_to_target(b))])
    for _ in range(3000):
        h = rng.choice((rng.randrange(0, 50000), rng.randrange(0, 9 * 10 ** 6), rng.randrange(0, 2 ** 32), F.QUARTER * rng.randrange(0, 70) + rng.randrange(-2, 3)))
        h = max(h, 0)
        out['subsidy'].append([h, str(F.subsidy(h))])
    for _ in range(3000):
        prev = rng.randrange(0, 2 ** rng.choice((31, 33, 40, 50)))
        t32 = rng.choice((rng.getrandbits(32), prev & 0xFFFFFFFF, (prev + 1) & 0xFFFFFFFF, (prev - 1) & 0xFFFFFFFF))
        out['time'].append([prev, t32, F.full_time(prev, t32)])
    for _ in range(300):
        leaves = [rng.randbytes(32) for _ in range(rng.randrange(0, 90))]
        out['merkle'].append([[x.hex() for x in leaves], F.merkle_root(leaves).hex()])
    for _ in range(300):
        a = F.encode_address(rng.randbytes(32))
        s = list(a)
        if rng.random() < 0.7:
            for _ in range(rng.randrange(1, 4)):
                s[rng.randrange(len(s))] = rng.choice(F.B32 + '1bB')
        s = ''.join(s)
        d = F.decode_address(s)
        out['address'].append([s, d.hex() if d else None])
    return out


def mutate(rng, raw):
    b = bytearray(raw)
    kind = rng.randrange(7)
    i = rng.randrange(len(b))
    if kind == 0:
        b[i] ^= 1 << rng.randrange(8)
    elif kind == 1:
        b[i] = rng.randrange(256)
    elif kind == 2:
        del b[i]
    elif kind == 3:
        b.insert(i, rng.randrange(256))
    elif kind == 4:
        i = rng.randrange(80, min(len(b), 400))                 # aim at the coinbase and the start of the first transaction
        b[i] = (b[i] + rng.choice((1, 255))) % 256
    elif kind == 5:
        b = b[:rng.randrange(1, len(b))]
    else:
        i = rng.randrange(0, 80)                                # header fields
        b[i] ^= 1 << rng.randrange(8)
    return bytes(b)


def blocks(rng, events):
    out = []
    c = F.Chain(F.TEST)
    targets = {50: (60, 120), 104: (60, 300), 129: (60, 300), 130: (40, 200), 1439: (40, 120)}  # height -> (raw mutations, mutations mined again)
    for e in events:
        if e['op'] != 'apply':
            continue
        if c.height in targets:
            raw_n, mined_n = targets[c.height]
            base, cases = bytes.fromhex(e['block']), []
            for _ in range(raw_n):
                m = mutate(rng, base)
                cases.append(m)
            for _ in range(mined_n):
                m = mutate(rng, base)
                cases.append(remine(c, m) or m)
            now = e['now']
            out.append({'height': c.height, 'now': now, 'cases': [[m.hex(), c.verdict(m, now)] for m in cases]})
        c.apply(bytes.fromhex(e['block']), e['now'])
    return out


def main():
    seed = int(sys.argv[1]) if len(sys.argv) > 1 else 1
    rng = random.Random(seed)
    v = json.load(open('vectors.json'))
    data = {'numeric': numeric(rng), 'blocks': blocks(rng, v['chain']['events'])}
    tally = {}
    for s in data['blocks']:
        for _, code in s['cases']:
            tally[code] = tally.get(code, 0) + 1
    json.dump(data, open('/tmp/fable_cross.json', 'w'))
    print('reference verdicts on mutated blocks:', dict(sorted(tally.items(), key=lambda kv: -kv[1])))
    return subprocess.run(['node', 'crosscheck.mjs', '/tmp/fable_cross.json']).returncode


if __name__ == '__main__':
    sys.exit(main())
