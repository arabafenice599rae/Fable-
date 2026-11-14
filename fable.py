"""Fable: reference implementation of the consensus rules, spec v0.12.

Everything a node needs to decide whether a block is valid. No networking, no storage.
The only dependency outside the standard library is an SLH-DSA verifier.
"""
import hashlib
import hmac
import struct
import unicodedata

import slhdsa

# ---------------------------------------------------------------- constants
TX, SIG, LEAF, WIT, ADDR, UTXO = 1, 2, 3, 4, 5, 6          # hash tags
COIN = 10 ** 8
MAX_AMOUNT = 1 << 62
BLOCK_TIME = 60
HALFLIFE = 3600
FUTURE_LIMIT = 600                # seconds a block time may run ahead of the local clock
QUARTER = 131_400                 # blocks between subsidy steps
SLOW_START = 43_200               # blocks of linear ramp
MATURITY = 100
SNAPSHOT_EVERY = 1_440
MAX_SIGS = 80                     # witnesses per block, coinbase excluded
MAX_IN, MAX_OUT, MAX_WIT = 32, 16, 4  # per transaction
MAX_CB_OUT = 2
PK_LEN, SIG_LEN = 32, 7_856
ZERO32 = bytes(32)


class Invalid(Exception):
    """A consensus rule was broken. args[0] is a short stable code."""


def sha256(b):
    return hashlib.sha256(b).digest()


def sha256d(b):
    return sha256(sha256(b))


def H(tag, b):
    return sha256(bytes([tag]) + b)


# ---------------------------------------------------------------- networks
def make_header(version, prev, merkle, time32, bits, nonce):
    return struct.pack('<I', version) + prev + merkle + struct.pack('<III', time32, bits, nonce)


class Net:
    def __init__(self, name, genesis_time, genesis_bits, max_bits, genesis_prev=ZERO32):
        self.name = name
        self.max_bits = max_bits
        self.genesis = make_header(1, genesis_prev, ZERO32, genesis_time & 0xFFFFFFFF, genesis_bits, 0)
        self.genesis_time = genesis_time
        self.genesis_bits = genesis_bits
        self.chain_id = sha256d(self.genesis)


# MAIN: genesis_prev is a placeholder. On launch day it becomes the hash of a recent Bitcoin block.
MAIN = Net('main', 1_794_441_600, 0x1B040000, 0x1D00FFFF)
# TEST: same rules, trivial difficulty, so a chain can be mined on a laptop.
TEST = Net('test', 1_794_441_600, 0x207FFFFF, 0x207FFFFF)


# ---------------------------------------------------------------- compact targets
def bits_to_target(bits):
    exp, mant = bits >> 24, bits & 0x007FFFFF
    if bits & 0x00800000:
        raise Invalid('bits')
    return mant >> (8 * (3 - exp)) if exp <= 3 else mant << (8 * (exp - 3))


def target_to_bits(target):
    size = (target.bit_length() + 7) // 8
    c = target << (8 * (3 - size)) if size <= 3 else target >> (8 * (size - 3))
    if c & 0x00800000:
        c >>= 8
        size += 1
    return c | (size << 24)


# ---------------------------------------------------------------- difficulty (aserti3-2d, anchored at genesis)
def asert_bits(net, parent_height, parent_time):
    """Compact target required of the block that follows the given parent."""
    anchor = bits_to_target(net.genesis_bits)
    max_target = bits_to_target(net.max_bits)
    time_delta = parent_time - (net.genesis_time - BLOCK_TIME)       # virtual parent of the anchor
    num = (time_delta - BLOCK_TIME * (parent_height + 1)) * 65536
    exponent = abs(num) // HALFLIFE
    if num < 0:
        exponent = -exponent                                          # truncate toward zero
    shifts = exponent >> 16                                           # arithmetic shift
    exponent -= shifts * 65536
    if shifts > 300:
        return net.max_bits
    if shifts < -300:
        return target_to_bits(1)
    factor = ((195766423245049 * exponent + 971821376 * exponent ** 2 + 5127 * exponent ** 3 + (1 << 47)) >> 48) + 65536
    nt = anchor * factor
    nt = nt << shifts if shifts >= 0 else nt >> -shifts
    nt >>= 16
    if nt == 0:
        return target_to_bits(1)
    if nt > max_target:
        return net.max_bits
    return target_to_bits(nt)


# ---------------------------------------------------------------- emission
def subsidy(height):
    r = 50 * COIN
    for _ in range(height // QUARTER):
        r -= r >> 4
        if r < COIN:
            r = COIN
            break
    if height < SLOW_START:
        r = r * height // SLOW_START
    return r


# ---------------------------------------------------------------- time
def full_time(prev_time, time32):
    """The header carries the low 32 bits. The full value is the smallest one after the parent."""
    t = (prev_time & ~0xFFFFFFFF) | time32
    if t <= prev_time:
        t += 1 << 32
    return t


# ---------------------------------------------------------------- merkle
def merkle_root(leaves):
    if not leaves:
        return ZERO32
    level = list(leaves)
    while len(level) > 1:
        nxt = [sha256d(level[i] + level[i + 1]) for i in range(0, len(level) - 1, 2)]
        if len(level) % 2:
            nxt.append(level[-1])                                     # an unpaired node moves up unchanged
        level = nxt
    return level[0]


def coinbase_branch(leaves):
    """Siblings on the path from leaf 0 to the root: what a Stratum miner folds in."""
    out, level = [], list(leaves)
    while len(level) > 1:
        out.append(level[1])
        nxt = [sha256d(level[i] + level[i + 1]) for i in range(0, len(level) - 1, 2)]
        if len(level) % 2:
            nxt.append(level[-1])
        level = nxt
    return out


# ---------------------------------------------------------------- parsing
class Reader:
    def __init__(self, buf):
        self.b, self.o = buf, 0

    def take(self, n):
        if self.o + n > len(self.b):
            raise Invalid('parse')
        v = self.b[self.o:self.o + n]
        self.o += n
        return v

    def u8(self):
        return self.take(1)[0]

    def u32(self):
        return struct.unpack('<I', self.take(4))[0]

    def u64(self):
        return struct.unpack('<Q', self.take(8))[0]


def read_outputs(r, limit):
    n = r.u8()
    if not 1 <= n <= limit:
        raise Invalid('parse')
    outs = []
    for _ in range(n):
        amount, addr = r.u64(), r.take(32)
        if not 1 <= amount <= MAX_AMOUNT:
            raise Invalid('parse')
        outs.append((amount, addr))
    return outs


def ser_outputs(outs):
    return bytes([len(outs)]) + b''.join(struct.pack('<Q', a) + addr for a, addr in outs)


class Tx:
    def __init__(self, ins, outs, wits):
        self.ins, self.outs, self.wits = ins, outs, wits

    def body(self):
        return bytes([len(self.ins)]) + b''.join(t + bytes([i]) for t, i in self.ins) + ser_outputs(self.outs)

    def witness(self):
        return bytes([len(self.wits)]) + b''.join(pk + sig for pk, sig in self.wits)

    def serialize(self):
        return self.body() + self.witness()

    def txid(self):
        return H(TX, self.body())

    def sighash(self, chain_id):
        return H(SIG, chain_id + self.body())

    def leaf(self):
        return H(LEAF, self.txid() + H(WIT, self.witness()))


def read_tx(r):
    n_in = r.u8()
    if not 1 <= n_in <= MAX_IN:
        raise Invalid('parse')
    ins = []
    for _ in range(n_in):
        txid, idx = r.take(32), r.u8()
        if idx >= MAX_OUT:
            raise Invalid('parse')
        ins.append((txid, idx))
    if len(set(ins)) != n_in:
        raise Invalid('parse')
    outs = read_outputs(r, MAX_OUT)
    n_wit = r.u8()
    if not 1 <= n_wit <= min(MAX_WIT, n_in):
        raise Invalid('parse')
    wits = [(r.take(PK_LEN), r.take(SIG_LEN)) for _ in range(n_wit)]
    return Tx(ins, outs, wits)


class Coinbase:
    def __init__(self, height, extra, utxo_root, outs):
        self.height, self.extra, self.utxo_root, self.outs = height, extra, utxo_root, outs

    def serialize(self):
        return struct.pack('<I', self.height) + self.extra + self.utxo_root + ser_outputs(self.outs)

    def txid(self):
        return sha256d(self.serialize())


def read_coinbase(r):
    return Coinbase(r.u32(), r.take(8), r.take(32), read_outputs(r, MAX_CB_OUT))


class Block:
    def __init__(self, header, coinbase, txs):
        self.header, self.coinbase, self.txs = header, coinbase, txs

    def serialize(self):
        return self.header + self.coinbase.serialize() + bytes([len(self.txs)]) + b''.join(t.serialize() for t in self.txs)

    def leaves(self):
        return [self.coinbase.txid()] + [t.leaf() for t in self.txs]


def read_block(buf):
    r = Reader(buf)
    header = r.take(80)
    cb = read_coinbase(r)
    n = r.u8()
    if n > MAX_SIGS:
        raise Invalid('parse')
    txs = [read_tx(r) for _ in range(n)]
    if r.o != len(buf):
        raise Invalid('parse')
    return Block(header, cb, txs)


# ---------------------------------------------------------------- signatures and addresses
def address(pk):
    return H(ADDR, pk)


def verify_sig(pk, msg, sig):
    try:
        return slhdsa.PublicKey.from_digest(pk, slhdsa.sha2_128s).verify_pure(msg, sig)
    except Exception:
        return False


# ---------------------------------------------------------------- state
def utxo_entry(txid, idx, amount, addr, height, is_cb):
    return txid + bytes([idx]) + struct.pack('<Q', amount) + addr + struct.pack('<I', height) + bytes([1 if is_cb else 0])


def utxo_root(utxo):
    return merkle_root([H(UTXO, utxo_entry(k[0], k[1], *utxo[k])) for k in sorted(utxo)])


class Chain:
    """The tip of one chain and its unspent outputs. Blocks are applied in order."""

    def __init__(self, net):
        self.net = net
        self.height = 0
        self.tip = sha256d(net.genesis)
        self.time = net.genesis_time
        self.utxo = {}                       # (txid, index) -> (amount, address, height, is_coinbase)

    def next_bits(self):
        return asert_bits(self.net, self.height, self.time)

    def next_utxo_root(self):
        return utxo_root(self.utxo) if (self.height + 1) % SNAPSHOT_EVERY == 0 else ZERO32

    def check(self, raw, now):
        """Validate a block against the tip. Returns what apply() needs. Raises Invalid."""
        blk = read_block(raw)
        h = self.height + 1
        version, prev, mroot, time32, bits, nonce = struct.unpack('<I32s32sIII', blk.header)
        if prev != self.tip:
            raise Invalid('prev')
        t = full_time(self.time, time32)
        if t > now + FUTURE_LIMIT:
            raise Invalid('time')
        if bits != self.next_bits():
            raise Invalid('bits')
        block_hash = sha256d(blk.header)
        if int.from_bytes(block_hash, 'little') > bits_to_target(bits):
            raise Invalid('pow')
        if mroot != merkle_root(blk.leaves()):
            raise Invalid('merkle')
        if blk.coinbase.height != h:
            raise Invalid('cbheight')
        if blk.coinbase.utxo_root != self.next_utxo_root():
            raise Invalid('utxoroot')
        if sum(len(t_.wits) for t_ in blk.txs) > MAX_SIGS:
            raise Invalid('sigs')

        view, spent, fees = {}, set(), 0     # outputs created and spent inside this block
        for tx in blk.txs:
            total_in, addrs = 0, []
            for op in tx.ins:
                if op in spent:
                    raise Invalid('missing')
                e = view.get(op) or self.utxo.get(op)
                if e is None:
                    raise Invalid('missing')
                if e[3] and h < e[2] + MATURITY:
                    raise Invalid('immature')
                total_in += e[0]
                addrs.append(e[1])
            # one witness per distinct input address, in the order the addresses first appear
            if [address(pk) for pk, _ in tx.wits] != list(dict.fromkeys(addrs)):
                raise Invalid('witness')
            msg = tx.sighash(self.net.chain_id)
            for pk, sig in tx.wits:
                if not verify_sig(pk, msg, sig):
                    raise Invalid('sig')
            total_out = sum(a for a, _ in tx.outs)
            if total_out > total_in:
                raise Invalid('value')
            fees += total_in - total_out
            txid = tx.txid()
            for op in tx.ins:
                spent.add(op)
            for i, (a, addr) in enumerate(tx.outs):
                if (txid, i) in view or (txid, i) in self.utxo:
                    raise Invalid('dup')
                view[(txid, i)] = (a, addr, h, False)
        if sum(a for a, _ in blk.coinbase.outs) > subsidy(h) + fees:
            raise Invalid('cbvalue')
        cbid = blk.coinbase.txid()
        for i, (a, addr) in enumerate(blk.coinbase.outs):
            if (cbid, i) in view or (cbid, i) in self.utxo:
                raise Invalid('dup')
            view[(cbid, i)] = (a, addr, h, True)
        return block_hash, t, view, spent

    def apply(self, raw, now):
        block_hash, t, view, spent = self.check(raw, now)
        for op in spent:
            if op in view:
                del view[op]
            else:
                del self.utxo[op]
        self.utxo.update(view)
        self.height += 1
        self.tip, self.time = block_hash, t
        return block_hash

    def verdict(self, raw, now):
        try:
            self.check(raw, now)
            return 'ok'
        except Invalid as e:
            return e.args[0]


# ---------------------------------------------------------------- wallet standard (outside consensus)
B32 = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'
BECH32M = 0x2BC830A3


def _polymod(values):
    gen, chk = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3), 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            chk ^= gen[i] if (b >> i) & 1 else 0
    return chk


def _hrp_expand(hrp):
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _bits(data, frm, to, pad):
    acc, n, out = 0, 0, []
    for v in data:
        acc, n = (acc << frm) | v, n + frm
        while n >= to:
            n -= to
            out.append((acc >> n) & ((1 << to) - 1))
    if pad and n:
        out.append((acc << (to - n)) & ((1 << to) - 1))
    elif not pad and (n >= frm or (acc << (to - n)) & ((1 << to) - 1)):
        return None
    return out


def encode_address(addr, hrp='fb'):
    data = _bits(addr, 8, 5, True)
    pm = _polymod(_hrp_expand(hrp) + data + [0] * 6) ^ BECH32M
    return hrp + '1' + ''.join(B32[d] for d in data + [(pm >> 5 * (5 - i)) & 31 for i in range(6)])


def decode_address(s, hrp='fb'):
    if s.lower() != s and s.upper() != s:
        return None
    s = s.lower()
    pos = s.rfind('1')
    if s[:pos] != hrp or any(c not in B32 for c in s[pos + 1:]):
        return None
    data = [B32.index(c) for c in s[pos + 1:]]
    if len(data) < 6 or _polymod(_hrp_expand(hrp) + data) != BECH32M:
        return None
    raw = _bits(data[:-6], 5, 8, False)
    return bytes(raw) if raw is not None and len(raw) == 32 else None


def seed_from_mnemonic(mnemonic, passphrase=''):
    norm = lambda s: unicodedata.normalize('NFKD', s).encode()
    return hashlib.pbkdf2_hmac('sha256', norm(mnemonic), b'fable' + norm(passphrase), 2048, 32)


def key_seed(seed, account, index):
    """48 bytes for SLH-DSA key generation: SK.seed, SK.prf, PK.seed."""
    path = struct.pack('<II', account, index)
    return hmac.new(seed, b'fable/0' + path, 'sha256').digest() + hmac.new(seed, b'fable/1' + path, 'sha256').digest()[:16]
