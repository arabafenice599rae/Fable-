"""A software stand-in for a Bitaxe, to test stratum.py without the hardware.

The job handling is a line-by-line port of the open-source Bitaxe firmware (ESP-Miner):
components/stratum/mining.c, mining_job.c, hash_bytes.c, stratum_api.c and components/mining_job/asic_job.c.
The self-test replays the firmware's own unit-test vector.

    python3 bitaxe_sim.py --selftest
    python3 bitaxe_sim.py --host 127.0.0.1 --port 3333 --blocks 5
"""
import argparse
import hashlib
import json
import socket
import struct

BIP320_MASK = 0x1FFFE000
DIFF1 = 0xFFFF << 208


def double_sha256(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def reverse_endianness_per_word(b32):                     # hash_bytes.c
    return b''.join(struct.pack('<I', struct.unpack('>I', b32[i:i + 4])[0]) for i in range(0, 32, 4))


def calculate_coinbase_tx_hash(prefix, extranonce1, extranonce2, suffix):   # mining.c
    return double_sha256(prefix + extranonce1 + extranonce2 + suffix)


def calculate_merkle_root_hash(coinbase_hash, branches):  # mining.c
    both = coinbase_hash
    for br in branches:
        both = double_sha256(both + br)
    return both


def asic_job_header(version, prev_hash, merkle_root, ntime, nbits, nonce):  # asic_job.c
    return struct.pack('<I', version) + prev_hash + merkle_root + struct.pack('<III', ntime, nbits, nonce)


def increment_bitmask(value, mask):                       # mining.c
    return (value & ~mask) | (((value | (~mask & 0xFFFFFFFF)) + 1) & mask)


def extranonce2_bytes(counter, length):                   # mining_job.c: the counter is written low byte first
    return bytes((counter >> (8 * i)) & 0xFF for i in range(length))


def selftest():
    # test_mining.c, "Validate merkle root calculation"
    c1 = bytes.fromhex('01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff20020862062f503253482f04b8864e5008e969579199999999072f736c7573682f0000000001')
    c2 = bytes.fromhex('1976a914d23fcdf86f7e756a64a7a9688ef9903327048ed988ac00000000')
    branches = [bytes.fromhex(x) for x in (
        'ae23055e00f0f697cc3640124812d96d4fe8bdfa03484c1c638ce5a1c0e9aa81', '980fb87cb61021dd7afd314fcb0dabd096f3d56a7377f6f320684652e7410a21',
        'a52e9868343c55ce405be8971ff340f562ae9ab6353f07140d01666180e19b52', '7435bdfa004e603953b2ed39f118803934d9cf17b06d979ceb682f2251bafac2',
        '2a91f061a22d27cb8f44eea79938fb241ebeb359891aa907f05ffde7ed44e52e', '302401f80eb5e958155135e25200bb8ea181ad2d05e804a531c7314d86403cdc',
        '318ecb6161eb9b4cfd802bd730e2d36c167ddf102e70aa7b4158e2870dd47392', '1114332a9858e0cf84b2425bb1e59eaabf91dd102d114aa443d57fc1b3beb0c9',
        'f43f38095c810613ed795a44d9fab02ff25269706f454885db9be05cdf9c06e1', '3e2fc26b27fddc39668b59099cd9635761bb72ed92404204e12bdff08b16fb75',
        '463c19427286342120039a83218fa87ce45448e246895abac11fff0036076758', '03d287f655813e540ddb9c4e7aeb922478662b0f5d8e9d0cbd564b20146bab76')]
    root = calculate_merkle_root_hash(calculate_coinbase_tx_hash(c1, bytes.fromhex('00f2052a'), bytes.fromhex('01000000'), c2), branches)
    assert root.hex() == 'adbcbc21e20388422198a55957aedfa0e61be0b8f2b87d7c08510bb9f099a893', root.hex()
    assert increment_bitmask(0x20000000, BIP320_MASK) == 0x20002000
    assert increment_bitmask(0x3FFFE000, BIP320_MASK) == 0x20000000
    print('self-test passed: the port reproduces the firmware merkle-root vector')


class Miner:
    def __init__(self, host, port, user='fable.sim'):
        self.s = socket.create_connection((host, port))
        self.buf = b''
        self.user, self.uid = user, 0
        self.mask, self.diff, self.job = 0, 1.0, None
        self.en1, self.en2_len = b'', 4
        self.accepted, self.rejected, self.blocks = 0, [], 0

    def send(self, method, params):
        self.uid += 1
        self.s.sendall((json.dumps({'id': self.uid, 'method': method, 'params': params}) + '\n').encode())
        return self.uid

    def read(self, timeout=None):
        """One message from the pool, or None if nothing arrives within the timeout."""
        self.s.settimeout(timeout)
        while b'\n' not in self.buf:
            try:
                chunk = self.s.recv(65536)
            except socket.timeout:
                return None
            if not chunk:
                raise ConnectionError('server closed the connection')
            self.buf += chunk
        line, self.buf = self.buf.split(b'\n', 1)
        return json.loads(line)

    def handle(self, m):
        method = m.get('method')
        if method == 'mining.set_difficulty':
            self.diff = float(m['params'][0])
        elif method == 'mining.notify':
            p = m['params']                                # stratum_api.c, the notify parser
            assert len(p[1]) == 64 and len(p[5]) == 8 and len(p[7]) == 8
            self.job = {'id': p[0], 'prev': reverse_endianness_per_word(bytes.fromhex(p[1])), 'c1': bytes.fromhex(p[2]), 'c2': bytes.fromhex(p[3]),
                        'path': [bytes.fromhex(x) for x in p[4]], 'version': int(p[5], 16), 'nbits': int(p[6], 16), 'ntime': int(p[7], 16)}
        elif method == 'mining.set_version_mask':
            self.mask = int(m['params'][0], 16) & BIP320_MASK
        return m

    def wait(self, uid):
        while True:
            m = self.handle(self.read())
            if m.get('id') == uid:
                return m

    def start(self):
        r = self.wait(self.send('mining.configure', [['version-rolling'], {'version-rolling.mask': 'ffffffff'}]))['result']
        if r.get('version-rolling') is True:
            self.mask = int(r['version-rolling.mask'], 16) & BIP320_MASK
        r = self.wait(self.send('mining.subscribe', ['bitaxe/BM1370/sim']))['result']
        self.en1, self.en2_len = bytes.fromhex(r[1]), r[2]
        self.wait(self.send('mining.authorize', [self.user, 'x']))
        while self.job is None:
            self.handle(self.read())

    def mine(self, blocks):
        counter = 0
        while self.blocks < blocks:
            job = self.job
            counter += 1
            en2 = extranonce2_bytes(counter, self.en2_len)
            root = calculate_merkle_root_hash(calculate_coinbase_tx_hash(job['c1'], self.en1, en2, job['c2']), job['path'])
            target = DIFF1 / self.diff
            version, found = job['version'], False
            if counter % 2 == 0:                           # start half the attempts from a rolled version, as the chip would
                version = increment_bitmask(version, self.mask)
            for _ in range(8):                             # the chip rolls the version inside the mask
                for nonce in range(0, 40000, 7):
                    h = double_sha256(asic_job_header(version, job['prev'], root, job['ntime'], job['nbits'], nonce))
                    if int.from_bytes(h, 'little') <= target:
                        found = True
                        break
                if found:
                    break
                version = increment_bitmask(version, self.mask)
            if not found:
                continue
            uid = self.send('mining.submit', [self.user, job['id'], en2.hex(), '%08x' % job['ntime'], '%08x' % nonce, '%08x' % (version ^ job['version'])])
            r = self.wait(uid)
            if r.get('result') is True:
                self.accepted += 1
                while True:                                # a new job right after our share means the share was a block
                    m = self.read(0.3)
                    if m is None:
                        break
                    self.handle(m)
                if self.job is not job:
                    self.blocks += 1
            else:
                self.rejected.append(r.get('error'))
                if len(self.rejected) > 20:
                    raise RuntimeError('too many rejected shares: %r' % self.rejected[-1])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--selftest', action='store_true')
    ap.add_argument('--host', default='127.0.0.1')
    ap.add_argument('--port', type=int, default=3333)
    ap.add_argument('--blocks', type=int, default=5)
    a = ap.parse_args()
    if a.selftest:
        return selftest()
    m = Miner(a.host, a.port)
    m.start()
    m.mine(a.blocks)
    print('accepted shares: %d, rejected: %d, blocks found: %d' % (m.accepted, len(m.rejected), m.blocks))


if __name__ == '__main__':
    main()
