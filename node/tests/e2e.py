"""End-to-end test of the Rust node over real sockets. Run from the repository root after
`cargo build --release` in node/:

    python3 node/tests/e2e.py

1. node A (with Stratum) and node B (connected to A); A mines 110 blocks, B follows;
2. a wallet payment sent to A reaches B's mempool;
3. the simulated Bitaxe mines it through Stratum: the job has a non-empty merkle branch;
4. node C, given the first 110 blocks, mines a longer branch alone; connected to A it makes A and B reorganise,
   and the payment goes back into their mempools; C then mines it;
5. A restarts from its block file at the same tip;
6. every block of the final chain is replayed by fable.py and by fable.mjs.
"""
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
import bitaxe_sim  # noqa: E402
import fable as F  # noqa: E402

BIN = os.path.join(ROOT, 'node', 'target', 'release', 'fable')
WORDS = 'abandon ' * 23 + 'art'
TMP = tempfile.mkdtemp(prefix='fable-e2e-')
procs = {}


def free_port():
    s = socket.socket()
    s.bind(('127.0.0.1', 0))
    p = s.getsockname()[1]
    s.close()
    return p


def start(name, *extra):
    p2p, rpc = free_port(), free_port()
    log = open(os.path.join(TMP, name + '.log'), 'a')
    proc = subprocess.Popen([BIN, 'node', '--datadir', os.path.join(TMP, name), '--listen', '127.0.0.1:%d' % p2p,
                             '--rpc', '127.0.0.1:%d' % rpc, '-v', *extra], stdout=log, stderr=log)
    procs[name] = (proc, p2p, rpc)
    for _ in range(100):
        try:
            call(name, 'getinfo')
            return p2p, rpc
        except OSError:
            time.sleep(0.05)
    raise RuntimeError(name + ' did not start')


def call(name, method, *params):
    s = socket.create_connection(('127.0.0.1', procs[name][2]))
    s.sendall((json.dumps({'id': 1, 'method': method, 'params': list(params)}) + '\n').encode())
    buf = b''
    while not buf.endswith(b'\n'):
        chunk = s.recv(1 << 20)
        if not chunk:
            break
        buf += chunk
    s.close()
    r = json.loads(buf)
    if r['error'] is not None:
        raise RuntimeError('%s %s: %s' % (name, method, r['error']))
    return r['result']


def cli(*args):
    return subprocess.run([BIN, *args], capture_output=True, text=True, check=True).stdout


def stop(name):
    proc = procs.pop(name)[0]
    try:
        call_proc = socket.create_connection(('127.0.0.1', 1))
        call_proc.close()
    except OSError:
        pass
    proc.terminate()
    proc.wait(10)


def wait(what, cond, timeout=60):
    t = time.time()
    while time.time() - t < timeout:
        if cond():
            return
        time.sleep(0.1)
    for n in procs:
        print(n, call(n, 'getinfo'), file=sys.stderr)
    raise AssertionError('timed out waiting for ' + what)


def main():
    addrs = [json.loads(line)['address'] for line in cli('wallet', 'address', '--words', WORDS, '--count', '2').splitlines()]
    a0, a1 = addrs
    stratum_port = free_port()
    pa, _ = start('a', '--stratum', '127.0.0.1:%d' % stratum_port, '--payout', a0)
    start('b', '--connect', '127.0.0.1:%d' % pa)
    wait('b connects', lambda: call('b', 'getinfo')['peers'] == 1)

    call('a', 'generate', 110, a0)
    wait('b syncs', lambda: call('b', 'getinfo')['tip'] == call('a', 'getinfo')['tip'])
    print('1. A mined 110 blocks, B is at the same tip')

    out = json.loads(cli('wallet', 'send', '--words', WORDS, '--to', a1, '--amount', '0.01', '--rpc', '127.0.0.1:%d' % procs['a'][2]))
    txid = out['txid']
    wait('tx relay', lambda: any(t['txid'] == txid for t in call('b', 'getmempool')))
    print('2. payment %s… (%d bytes, fee %s) is in both mempools' % (txid[:16], out['size'], out['fee']))

    m = bitaxe_sim.Miner('127.0.0.1', stratum_port)
    m.start()
    branch = len(m.job['path'])
    assert branch, 'a job with a transaction has a merkle branch'
    m.mine(1)
    assert not m.rejected, m.rejected
    wait('confirmation', lambda: not call('a', 'getmempool') and not call('b', 'getmempool'))
    tip = call('a', 'getblock', str(call('a', 'getinfo')['height']))
    assert txid in tip['txs'], tip
    wait('b follows', lambda: call('b', 'getinfo')['tip'] == call('a', 'getinfo')['tip'])
    print('3. the simulated Bitaxe mined it at height %d (branch of %d), B agrees' % (tip['height'], branch))

    pc, _ = start('c')
    for h in range(1, 111):                                  # the common history, given by hand
        assert call('c', 'submitblock', call('a', 'getblock', str(h))['hex']) == 'stored'
    call('c', 'generate', 5, a1)                             # then 111 to 115 alone, without the payment
    call('a', 'addpeer', '127.0.0.1:%d' % pc)
    wait('reorg', lambda: call('a', 'getinfo')['tip'] == call('c', 'getinfo')['tip'] == call('b', 'getinfo')['tip'], timeout=90)
    wait('payment back in the mempool', lambda: any(t['txid'] == txid for t in call('a', 'getmempool')))
    wait('c learns it', lambda: any(t['txid'] == txid for t in call('c', 'getmempool')))
    call('c', 'generate', 1, a1)
    wait('all agree', lambda: len({call(n, 'getinfo')['tip'] for n in 'abc'}) == 1)
    info = call('a', 'getinfo')
    last = call('a', 'getblock', str(info['height']))
    assert txid in last['txs']
    print('4. C (5 blocks alone after the common 110) took over A and B; the payment returned to the mempools and C mined it at %d' % info['height'])

    height, tip_hash = info['height'], info['tip']
    raws = [bytes.fromhex(call('a', 'getblock', str(h))['hex']) for h in range(1, height + 1)]
    stop('a')
    start('a')
    info2 = call('a', 'getinfo')
    assert (info2['height'], info2['tip']) == (height, tip_hash), info2
    print('5. A restarted from its block file at height %d' % height)

    c = F.Chain(F.TEST)
    for raw in raws:
        c.apply(raw, 1 << 62)
    assert c.tip[::-1].hex() == tip_hash
    js = '''import * as F from '%s/fable.mjs';
import { readFileSync } from 'node:fs';
const c = new F.Chain(F.TEST);
for (const b of JSON.parse(readFileSync(process.argv[2], 'utf8'))) c.apply(Buffer.from(b, 'hex'), 2 ** 52);
console.log(Buffer.from(c.tip).reverse().toString('hex'));''' % ROOT
    open(os.path.join(TMP, 'replay.mjs'), 'w').write(js)
    json.dump([r.hex() for r in raws], open(os.path.join(TMP, 'blocks.json'), 'w'))
    out = subprocess.run(['node', os.path.join(TMP, 'replay.mjs'), os.path.join(TMP, 'blocks.json')], capture_output=True, text=True)
    assert out.stdout.strip() == tip_hash, out.stdout + out.stderr
    print('6. fable.py and fable.mjs replay all %d blocks to the same tip %s…' % (height, tip_hash[:16]))
    print('OK')


if __name__ == '__main__':
    try:
        main()
    finally:
        for n in list(procs):
            procs[n][0].terminate()
        if os.environ.get('KEEP'):
            print('logs in', TMP)
        else:
            shutil.rmtree(TMP, ignore_errors=True)
