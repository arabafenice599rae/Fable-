"""End-to-end test: the simulated Bitaxe mines blocks through the Stratum server over a real TCP socket.
Every block is then replayed by both implementations.
    python3 test_stratum.py [blocks]
"""
import asyncio
import json
import subprocess
import sys
import threading

import bitaxe_sim
import fable as F
import stratum

N = int(sys.argv[1]) if len(sys.argv) > 1 else 40
payout = F.address(bytes(32))
pool = None


def clock():                                              # a fake clock: about one minute per block, with jitter
    h = pool.chain.height if pool else 0
    return F.TEST.genesis_time + 60 * (h + 1) + (h * 31) % 41 - 20


pool = stratum.Pool(F.TEST, payout, clock=clock)
loop = asyncio.new_event_loop()
ready = threading.Event()


def run():
    asyncio.set_event_loop(loop)
    loop.run_until_complete(stratum.serve(pool, '127.0.0.1', 13333, log=lambda m: None))
    ready.set()
    loop.run_forever()


threading.Thread(target=run, daemon=True).start()
ready.wait()
bitaxe_sim.selftest()
m = bitaxe_sim.Miner('127.0.0.1', 13333)
m.start()
print('negotiated version mask %08x, extranonce1 %s, extranonce2 size %d, share difficulty %g' % (m.mask, m.en1.hex(), m.en2_len, m.diff))
m.mine(N)
print('miner: %d shares accepted, %d rejected, %d blocks' % (m.accepted, len(m.rejected), m.blocks))
assert pool.chain.height == N and not m.rejected, (pool.chain.height, m.rejected)

replay = F.Chain(F.TEST)
for raw in pool.blocks:
    replay.apply(raw, 1 << 62)
assert replay.tip == pool.chain.tip
versions = sorted({raw[0:4][::-1].hex() for raw in pool.blocks})
print('reference replay: height %d, tip %s, header versions seen %s' % (replay.height, replay.tip[::-1].hex(), versions))
js = '''
import * as F from './fable.mjs';
const blocks = %s;
const c = new F.Chain(F.TEST);
for (const b of blocks) c.apply(Buffer.from(b, 'hex'), 2 ** 52);
console.log('second implementation replay: height ' + c.height + ', tip ' + Buffer.from(c.tip).reverse().toString('hex'));
''' % json.dumps([b.hex() for b in pool.blocks])
open('/tmp/fable_replay.mjs', 'w').write(js.replace("'./fable.mjs'", "'%s/fable.mjs'" % __import__('os').getcwd()))
out = subprocess.run(['node', '/tmp/fable_replay.mjs'], capture_output=True, text=True)
print(out.stdout.strip() or out.stderr.strip())
assert replay.tip[::-1].hex() in out.stdout
print('OK: both implementations accept every block the miner produced')
