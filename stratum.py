"""Stratum v1 server for Fable: lets a Bitaxe (or any SHA-256 miner) mine onto a local chain.

    python3 stratum.py --net lab --address fb1... [--port 3333] [--data chain.txt]

Networks:
    test  trivial difficulty, for software tests
    lab   mainnet difficulty with a throwaway genesis stamped at first start, for a real Bitaxe
In the miner's settings: pool = this machine's address, port 3333, any user name.
"""
import argparse
import asyncio
import json
import os
import struct
import time

import fable as F

MASK = 0x1FFFE000
JOB_VERSION = 0x20000000
DIFF1 = 0xFFFF << 208


def swap_words(b32):
    """Stratum sends the previous hash with the bytes of every 4-byte word reversed."""
    return b''.join(b32[i:i + 4][::-1] for i in range(0, 32, 4))


class Pool:
    def __init__(self, net, payout, data=None, share_diff=None, clock=time.time):
        self.chain = F.Chain(net)
        self.payout, self.data, self.clock = payout, data, clock
        self.clients, self.jobs, self.job_n, self.sid = set(), {}, 0, 0
        self.blocks = []
        net_diff = DIFF1 / F.bits_to_target(net.genesis_bits)
        self.share_diff = share_diff or min(256.0, net_diff)
        if data and os.path.exists(data):
            for line in open(data):
                raw = bytes.fromhex(line.strip())
                self.chain.apply(raw, 1 << 62)
                self.blocks.append(raw)
        self.new_job()

    def new_job(self):
        c = self.chain
        now = int(self.clock())
        cb2 = c.next_utxo_root() + F.ser_outputs([(F.subsidy(c.height + 1), self.payout)])
        self.job_n += 1
        job = {'id': '%x' % self.job_n, 'height': c.height + 1, 'prev': c.tip, 'bits': c.next_bits(),
               'ntime': max(now, c.time + 1) & 0xFFFFFFFF, 'cb1': struct.pack('<I', c.height + 1), 'cb2': cb2}
        self.jobs = {job['id']: job}                      # one live job: anything older is stale
        self.job = job
        return job

    def notify(self, job):
        return {'id': None, 'method': 'mining.notify', 'params': [
            job['id'], swap_words(job['prev']).hex(), job['cb1'].hex(), job['cb2'].hex(), [],
            '%08x' % JOB_VERSION, '%08x' % job['bits'], '%08x' % job['ntime'], True]}

    def submit(self, extranonce1, params):
        """Returns (accepted, message). A share that is also a block is added to the chain."""
        _, job_id, en2, ntime, nonce = params[:5]
        vbits = int(params[5], 16) if len(params) > 5 else 0
        job = self.jobs.get(job_id)
        if job is None:
            return False, 'stale job'
        if vbits & ~MASK:
            return False, 'version bits outside the mask'
        coinbase = job['cb1'] + extranonce1 + bytes.fromhex(en2) + job['cb2']
        if len(coinbase) != 4 + 8 + len(job['cb2']):
            return False, 'bad extranonce2 size'
        root = F.sha256d(coinbase)                       # the coinbase is the only transaction: the branch is empty
        header = F.make_header((JOB_VERSION & ~MASK) | (vbits & MASK), job['prev'], root, int(ntime, 16), job['bits'], int(nonce, 16))
        value = int.from_bytes(F.sha256d(header), 'little')
        if value > DIFF1 / self.share_diff:
            return False, 'share above target'
        if value > F.bits_to_target(job['bits']):
            return True, 'share'
        raw = header + coinbase + b'\x00\x00'
        try:
            self.chain.apply(raw, int(self.clock()))
        except F.Invalid as e:
            return False, 'block refused: ' + e.args[0]
        self.blocks.append(raw)
        if self.data:
            with open(self.data, 'a') as f:
                f.write(raw.hex() + '\n')
        return True, 'block %d %s' % (self.chain.height, self.chain.tip[::-1].hex())


async def serve(pool, host, port, log=print):
    async def push(writer, msg):
        writer.write((json.dumps(msg) + '\n').encode())
        await writer.drain()

    async def handle(reader, writer):
        pool.sid += 1
        en1 = struct.pack('>I', pool.sid)
        pool.clients.add(writer)
        try:
            while True:
                line = await reader.readline()
                if not line:
                    break
                try:
                    m = json.loads(line)
                except ValueError:
                    continue
                method, mid, params = m.get('method'), m.get('id'), m.get('params') or []
                if method == 'mining.configure':
                    await push(writer, {'id': mid, 'error': None, 'result': {'version-rolling': True, 'version-rolling.mask': '%08x' % MASK}})
                elif method == 'mining.subscribe':
                    await push(writer, {'id': mid, 'error': None, 'result': [[['mining.notify', en1.hex()]], en1.hex(), 4]})
                elif method == 'mining.authorize':
                    await push(writer, {'id': mid, 'error': None, 'result': True})
                    await push(writer, {'id': None, 'method': 'mining.set_difficulty', 'params': [pool.share_diff]})
                    await push(writer, pool.notify(pool.job))
                elif method == 'mining.submit':
                    try:
                        ok, msg = pool.submit(en1, params)
                    except (ValueError, IndexError):
                        ok, msg = False, 'malformed submit'
                    await push(writer, {'id': mid, 'error': None if ok else [20, msg, None], 'result': ok})
                    if msg.startswith('block '):
                        log(msg)
                        job = pool.new_job()
                        for w in list(pool.clients):
                            try:
                                await push(w, pool.notify(job))
                            except ConnectionError:
                                pool.clients.discard(w)
                else:
                    await push(writer, {'id': mid, 'error': None, 'result': True})
        except ConnectionError:
            pass
        finally:
            pool.clients.discard(writer)
            writer.close()

    async def refresh():                                  # a fresh timestamp every 30 seconds
        while True:
            await asyncio.sleep(30)
            job = pool.new_job()
            for w in list(pool.clients):
                try:
                    await push(w, pool.notify(job))
                except ConnectionError:
                    pool.clients.discard(w)

    server = await asyncio.start_server(handle, host, port)
    return server, asyncio.ensure_future(refresh())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--net', choices=('test', 'lab'), default='lab')
    ap.add_argument('--address', required=True, help='payout address, fb1...')
    ap.add_argument('--port', type=int, default=3333)
    ap.add_argument('--data', default='chain.txt')
    a = ap.parse_args()
    payout = F.decode_address(a.address)
    if payout is None:
        raise SystemExit('not a valid Fable address')
    if a.net == 'test':
        net = F.TEST
    else:
        stamp = a.data + '.genesis'
        if not os.path.exists(stamp):
            open(stamp, 'w').write(str(int(time.time())))
        net = F.Net('lab', int(open(stamp).read()), 0x1B040000, 0x1D00FFFF)
    pool = Pool(net, payout, a.data)

    async def run():
        server, _ = await serve(pool, '0.0.0.0', a.port)
        print('Fable %s chain at height %d, share difficulty %g, listening on port %d' % (net.name, pool.chain.height, pool.share_diff, a.port))
        async with server:
            await server.serve_forever()

    asyncio.run(run())


if __name__ == '__main__':
    main()
