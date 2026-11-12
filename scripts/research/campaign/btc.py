"""Self-contained Bitcoin primitives for the MULADDMOD adversarial campaign.

Pure-Python secp256k1, BIP340 Schnorr, ECDSA, BIP341/BIP143/legacy sighashes,
transaction and block serialization. Everything here is test-only and
variable-time. Never use these signers with real funds.
"""
from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field

P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
NUMS_X = bytes.fromhex('50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0')

SIGHASH_DEFAULT = 0x00
SIGHASH_ALL = 0x01
SIGHASH_NONE = 0x02
SIGHASH_SINGLE = 0x03
SIGHASH_ANYONECANPAY = 0x80


def sha(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hash256(data: bytes) -> bytes:
    return sha(sha(data))


def hash160(data: bytes) -> bytes:
    return hashlib.new('ripemd160', sha(data)).digest()


def tagged(tag: str, data: bytes) -> bytes:
    prefix = sha(tag.encode())
    return sha(prefix + prefix + data)


# ---------------------------------------------------------------- secp256k1 (Jacobian)

def _jadd(p, q):
    if p is None:
        return q
    if q is None:
        return p
    x1, y1, z1 = p
    x2, y2, z2 = q
    z1z1 = z1 * z1 % P
    z2z2 = z2 * z2 % P
    u1 = x1 * z2z2 % P
    u2 = x2 * z1z1 % P
    s1 = y1 * z2 * z2z2 % P
    s2 = y2 * z1 * z1z1 % P
    if u1 == u2:
        if s1 != s2:
            return None
        return _jdouble(p)
    h = (u2 - u1) % P
    r = (s2 - s1) % P
    h2 = h * h % P
    h3 = h * h2 % P
    u1h2 = u1 * h2 % P
    x3 = (r * r - h3 - 2 * u1h2) % P
    y3 = (r * (u1h2 - x3) - s1 * h3) % P
    z3 = h * z1 * z2 % P
    return (x3, y3, z3)


def _jdouble(p):
    if p is None:
        return None
    x, y, z = p
    if y == 0:
        return None
    ysq = y * y % P
    s = 4 * x * ysq % P
    m = 3 * x * x % P
    x3 = (m * m - 2 * s) % P
    y3 = (m * (s - x3) - 8 * ysq * ysq) % P
    z3 = 2 * y * z % P
    return (x3, y3, z3)


def _affine(p):
    if p is None:
        return None
    x, y, z = p
    zi = pow(z, -1, P)
    zi2 = zi * zi % P
    return (x * zi2 % P, y * zi2 * zi % P)


def point_mul(k: int, point=G):
    k %= N
    result = None
    addend = (point[0], point[1], 1)
    while k:
        if k & 1:
            result = _jadd(result, addend)
        addend = _jdouble(addend)
        k >>= 1
    return _affine(result)


def point_add(a, b):
    ja = None if a is None else (a[0], a[1], 1)
    jb = None if b is None else (b[0], b[1], 1)
    return _affine(_jadd(ja, jb))


def lift_x(x: int):
    if x >= P:
        return None
    ysq = (pow(x, 3, P) + 7) % P
    y = pow(ysq, (P + 1) // 4, P)
    if y * y % P != ysq:
        return None
    return (x, y if y % 2 == 0 else P - y)


def xonly(secret: int) -> bytes:
    return point_mul(secret)[0].to_bytes(32, 'big')


def schnorr_sign(msg: bytes, secret: int, aux: bytes = bytes(32)) -> bytes:
    assert len(msg) == 32 and 1 <= secret < N
    pt = point_mul(secret)
    d = secret if pt[1] % 2 == 0 else N - secret
    t = (d ^ int.from_bytes(tagged('BIP0340/aux', aux), 'big')).to_bytes(32, 'big')
    k0 = int.from_bytes(tagged('BIP0340/nonce', t + pt[0].to_bytes(32, 'big') + msg), 'big') % N
    assert k0
    r = point_mul(k0)
    k = k0 if r[1] % 2 == 0 else N - k0
    e = int.from_bytes(tagged('BIP0340/challenge', r[0].to_bytes(32, 'big') + pt[0].to_bytes(32, 'big') + msg), 'big') % N
    return r[0].to_bytes(32, 'big') + ((k + e * d) % N).to_bytes(32, 'big')


def schnorr_verify(msg: bytes, pubkey: bytes, sig: bytes) -> bool:
    if len(pubkey) != 32 or len(sig) != 64:
        return False
    pt = lift_x(int.from_bytes(pubkey, 'big'))
    r = int.from_bytes(sig[:32], 'big')
    s = int.from_bytes(sig[32:], 'big')
    if pt is None or r >= P or s >= N:
        return False
    e = int.from_bytes(tagged('BIP0340/challenge', sig[:32] + pubkey + msg), 'big') % N
    R = point_add(point_mul(s), point_mul(N - e, pt))
    return R is not None and R[1] % 2 == 0 and R[0] == r


def ecdsa_sign(msghash: bytes, secret: int, nonce_seed: bytes = b'') -> bytes:
    """Deterministic (non-RFC6979) low-S DER ECDSA. Test only."""
    z = int.from_bytes(msghash, 'big')
    ctr = 0
    while True:
        k = int.from_bytes(sha(secret.to_bytes(32, 'big') + msghash + nonce_seed + ctr.to_bytes(4, 'big')), 'big') % N
        ctr += 1
        if not k:
            continue
        r = point_mul(k)[0] % N
        if not r:
            continue
        s = pow(k, -1, N) * (z + r * secret) % N
        if not s:
            continue
        if s > N // 2:
            s = N - s
        return der(r, s)


def der(r: int, s: int) -> bytes:
    def enc(v):
        b = v.to_bytes((v.bit_length() + 8) // 8, 'big')
        return b'\x02' + bytes([len(b)]) + b
    body = enc(r) + enc(s)
    return b'\x30' + bytes([len(body)]) + body


def compressed_pubkey(secret: int) -> bytes:
    pt = point_mul(secret)
    return bytes([2 + (pt[1] & 1)]) + pt[0].to_bytes(32, 'big')


# ---------------------------------------------------------------- serialization

def compact(n: int) -> bytes:
    if n < 253:
        return bytes([n])
    if n <= 0xffff:
        return b'\xfd' + n.to_bytes(2, 'little')
    if n <= 0xffffffff:
        return b'\xfe' + n.to_bytes(4, 'little')
    return b'\xff' + n.to_bytes(8, 'little')


def var(data: bytes) -> bytes:
    return compact(len(data)) + data


def push(data: bytes) -> bytes:
    """Minimal push encoding for script literals."""
    if not data:
        return b'\x00'
    if len(data) == 1 and 1 <= data[0] <= 16:
        return bytes([0x50 + data[0]])
    if data == b'\x81':
        return b'\x4f'
    if len(data) <= 75:
        return bytes([len(data)]) + data
    if len(data) <= 255:
        return b'\x4c' + bytes([len(data)]) + data
    if len(data) <= 520:
        return b'\x4d' + len(data).to_bytes(2, 'little') + data
    raise ValueError('push too large')


def script_num(value: int) -> bytes:
    if value == 0:
        return b''
    neg = value < 0
    v = abs(value)
    out = bytearray()
    while v:
        out.append(v & 0xff)
        v >>= 8
    if out[-1] & 0x80:
        out.append(0x80 if neg else 0)
    elif neg:
        out[-1] |= 0x80
    return bytes(out)


def push_int(value: int) -> bytes:
    if value == 0:
        return b'\x00'
    if value == -1:
        return b'\x4f'
    if 1 <= value <= 16:
        return bytes([0x50 + value])
    return push(script_num(value))


@dataclass
class TxIn:
    txid: str  # display hex (big-endian)
    vout: int
    script_sig: bytes = b''
    sequence: int = 0xffffffff
    witness: list = field(default_factory=list)

    def outpoint(self) -> bytes:
        return bytes.fromhex(self.txid)[::-1] + self.vout.to_bytes(4, 'little')


@dataclass
class TxOut:
    value: int
    spk: bytes

    def ser(self) -> bytes:
        return self.value.to_bytes(8, 'little', signed=True) + var(self.spk)


@dataclass
class Tx:
    vin: list
    vout: list
    version: int = 2
    locktime: int = 0

    def has_witness(self) -> bool:
        return any(i.witness for i in self.vin)

    def ser_base(self) -> bytes:
        out = self.version.to_bytes(4, 'little', signed=True) + compact(len(self.vin))
        for i in self.vin:
            out += i.outpoint() + var(i.script_sig) + i.sequence.to_bytes(4, 'little')
        out += compact(len(self.vout)) + b''.join(o.ser() for o in self.vout)
        return out + self.locktime.to_bytes(4, 'little')

    def ser(self) -> bytes:
        if not self.has_witness():
            return self.ser_base()
        out = self.version.to_bytes(4, 'little', signed=True) + b'\x00\x01' + compact(len(self.vin))
        for i in self.vin:
            out += i.outpoint() + var(i.script_sig) + i.sequence.to_bytes(4, 'little')
        out += compact(len(self.vout)) + b''.join(o.ser() for o in self.vout)
        for i in self.vin:
            out += compact(len(i.witness)) + b''.join(var(w) for w in i.witness)
        return out + self.locktime.to_bytes(4, 'little')

    def hex(self) -> str:
        return self.ser().hex()

    def txid(self) -> str:
        return hash256(self.ser_base())[::-1].hex()

    def wtxid(self) -> str:
        return hash256(self.ser())[::-1].hex()

    def weight(self) -> int:
        return len(self.ser_base()) * 3 + len(self.ser())

    def vsize(self) -> int:
        return (self.weight() + 3) // 4

    def copy(self) -> 'Tx':
        return Tx([TxIn(i.txid, i.vout, i.script_sig, i.sequence, list(i.witness)) for i in self.vin],
                  [TxOut(o.value, o.spk) for o in self.vout], self.version, self.locktime)


# ---------------------------------------------------------------- sighashes

def taproot_sighash(tx: Tx, index: int, spent: list, hash_type: int = SIGHASH_DEFAULT,
                    leaf_hash: bytes | None = None, annex: bytes | None = None,
                    codesep_pos: int = 0xffffffff, key_version: int = 0) -> bytes:
    """BIP341 signature message. spent = [(value, spk)] for every input."""
    out_type = SIGHASH_ALL if hash_type == SIGHASH_DEFAULT else hash_type & 3
    acp = bool(hash_type & SIGHASH_ANYONECANPAY)
    m = bytes([hash_type]) + tx.version.to_bytes(4, 'little', signed=True) + tx.locktime.to_bytes(4, 'little')
    if not acp:
        m += sha(b''.join(i.outpoint() for i in tx.vin))
        m += sha(b''.join(v.to_bytes(8, 'little') for v, _ in spent))
        m += sha(b''.join(var(s) for _, s in spent))
        m += sha(b''.join(i.sequence.to_bytes(4, 'little') for i in tx.vin))
    if out_type not in (SIGHASH_NONE, SIGHASH_SINGLE):
        m += sha(b''.join(o.ser() for o in tx.vout))
    ext_flag = 0 if leaf_hash is None else 1
    m += bytes([ext_flag * 2 + (1 if annex is not None else 0)])
    if acp:
        i = tx.vin[index]
        m += i.outpoint() + spent[index][0].to_bytes(8, 'little') + var(spent[index][1]) + i.sequence.to_bytes(4, 'little')
    else:
        m += index.to_bytes(4, 'little')
    if annex is not None:
        m += sha(var(annex))
    if out_type == SIGHASH_SINGLE:
        m += sha(tx.vout[index].ser())
    if leaf_hash is not None:
        m += leaf_hash + bytes([key_version]) + codesep_pos.to_bytes(4, 'little')
    return tagged('TapSighash', b'\x00' + m)


def bip143_sighash(tx: Tx, index: int, script_code: bytes, amount: int, hash_type: int = SIGHASH_ALL) -> bytes:
    acp = hash_type & SIGHASH_ANYONECANPAY
    base = hash_type & 0x1f
    hp = hash256(b''.join(i.outpoint() for i in tx.vin)) if not acp else bytes(32)
    hs = hash256(b''.join(i.sequence.to_bytes(4, 'little') for i in tx.vin)) \
        if not acp and base not in (SIGHASH_SINGLE, SIGHASH_NONE) else bytes(32)
    if base not in (SIGHASH_SINGLE, SIGHASH_NONE):
        ho = hash256(b''.join(o.ser() for o in tx.vout))
    elif base == SIGHASH_SINGLE and index < len(tx.vout):
        ho = hash256(tx.vout[index].ser())
    else:
        ho = bytes(32)
    i = tx.vin[index]
    m = tx.version.to_bytes(4, 'little', signed=True) + hp + hs + i.outpoint() + var(script_code)
    m += amount.to_bytes(8, 'little') + i.sequence.to_bytes(4, 'little') + ho
    m += tx.locktime.to_bytes(4, 'little') + hash_type.to_bytes(4, 'little')
    return hash256(m)


def legacy_sighash(tx: Tx, index: int, script_code: bytes, hash_type: int = SIGHASH_ALL) -> bytes:
    """SIGHASH_ALL legacy digest (no FindAndDelete corner cases)."""
    assert hash_type == SIGHASH_ALL
    t = tx.copy()
    for j, i in enumerate(t.vin):
        i.script_sig = script_code if j == index else b''
        i.witness = []
    return hash256(t.ser_base() + hash_type.to_bytes(4, 'little'))


# ---------------------------------------------------------------- taproot

def tapleaf_hash(script: bytes, version: int = 0xc0) -> bytes:
    return tagged('TapLeaf', bytes([version]) + var(script))


def tapbranch(a: bytes, b: bytes) -> bytes:
    return tagged('TapBranch', min(a, b) + max(a, b))


def taproot_output(internal_x: bytes, merkle_root: bytes | None):
    """Return (output_x, parity) for internal key and optional merkle root."""
    pt = lift_x(int.from_bytes(internal_x, 'big'))
    t = int.from_bytes(tagged('TapTweak', internal_x + (merkle_root or b'')), 'big')
    assert t < N
    q = point_add(pt, point_mul(t))
    return q[0].to_bytes(32, 'big'), q[1] & 1


def tweak_secret(secret: int, merkle_root: bytes | None) -> int:
    pt = point_mul(secret)
    d = secret if pt[1] % 2 == 0 else N - secret
    t = int.from_bytes(tagged('TapTweak', pt[0].to_bytes(32, 'big') + (merkle_root or b'')), 'big')
    return (d + t) % N


@dataclass
class TapTree:
    """A taproot output with a list of tapscript leaves (balanced pairwise tree)."""
    internal_x: bytes
    leaves: list  # list[(script, version)]

    def _levels(self):
        hashes = [tapleaf_hash(s, v) for s, v in self.leaves]
        paths = [[] for _ in hashes]
        groups = [[i] for i in range(len(hashes))]
        while len(hashes) > 1:
            nh, ng = [], []
            for k in range(0, len(hashes), 2):
                if k + 1 == len(hashes):
                    nh.append(hashes[k]); ng.append(groups[k]); continue
                for i in groups[k]:
                    paths[i].append(hashes[k + 1])
                for i in groups[k + 1]:
                    paths[i].append(hashes[k])
                nh.append(tapbranch(hashes[k], hashes[k + 1]))
                ng.append(groups[k] + groups[k + 1])
            hashes, groups = nh, ng
        return (hashes[0] if hashes else None), paths

    def merkle_root(self):
        return self._levels()[0]

    def output(self):
        return taproot_output(self.internal_x, self.merkle_root())

    def spk(self) -> bytes:
        return b'\x51\x20' + self.output()[0]

    def control(self, index: int) -> bytes:
        _, paths = self._levels()
        _, parity = self.output()
        return bytes([self.leaves[index][1] | parity]) + self.internal_x + b''.join(paths[index])


# ---------------------------------------------------------------- blocks

def merkle_root(hashes: list) -> bytes:
    if not hashes:
        return bytes(32)
    layer = list(hashes)
    while len(layer) > 1:
        if len(layer) % 2:
            layer.append(layer[-1])
        layer = [hash256(layer[i] + layer[i + 1]) for i in range(0, len(layer), 2)]
    return layer[0]


def subsidy(height: int, halving: int = 150) -> int:
    halvings = height // halving
    return 0 if halvings >= 64 else (50 * 100_000_000) >> halvings


def bip34_height(height: int) -> bytes:
    return push_int(height) if height > 16 else (bytes([0x50 + height]) if height else b'\x00')


def coinbase_tx(height: int, value: int, spk: bytes, wtxids: list, extra: bytes = b'') -> Tx:
    """wtxids: internal byte-order wtxids of non-coinbase txs (coinbase slot is zero)."""
    script_sig = bip34_height(height) + push(b'muladdmod-campaign' + extra)
    if len(script_sig) < 2:
        script_sig += b'\x51'
    outs = [TxOut(value, spk)]
    if wtxids is not None:
        root = merkle_root([bytes(32)] + wtxids)
        commitment = hash256(root + bytes(32))
        outs.append(TxOut(0, b'\x6a\x24\xaa\x21\xa9\xed' + commitment))
    cb = Tx([TxIn('00' * 32, 0xffffffff, script_sig, 0xffffffff, [bytes(32)] if wtxids is not None else [])], outs, 2, 0)
    return cb


def block_bytes(prev_hash_hex: str, height: int, txs: list, time_: int, payout_spk: bytes,
                fees: int = 0, bits: int = 0x207fffff, version: int = 0x20000000, extra: bytes = b'',
                coinbase_value: int | None = None) -> tuple[bytes, str]:
    wtxids = [bytes.fromhex(t.wtxid())[::-1] for t in txs]
    value = subsidy(height) + fees if coinbase_value is None else coinbase_value
    cb = coinbase_tx(height, value, payout_spk, wtxids, extra)
    all_txs = [cb] + txs
    root = merkle_root([bytes.fromhex(t.txid())[::-1] for t in all_txs])
    target = (bits & 0xffffff) << (8 * ((bits >> 24) - 3))
    header_prefix = version.to_bytes(4, 'little') + bytes.fromhex(prev_hash_hex)[::-1] + root + \
        time_.to_bytes(4, 'little') + bits.to_bytes(4, 'little')
    nonce = 0
    while True:
        header = header_prefix + nonce.to_bytes(4, 'little')
        h = hash256(header)
        if int.from_bytes(h, 'little') <= target:
            break
        nonce += 1
    body = header + compact(len(all_txs)) + b''.join(t.ser() for t in all_txs)
    return body, h[::-1].hex()


def bech32m_address(program: bytes, hrp: str = 'bcrt', version: int = 1) -> str:
    def polymod(values):
        gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
        chk = 1
        for v in values:
            b = chk >> 25
            chk = ((chk & 0x1FFFFFF) << 5) ^ v
            for i in range(5):
                chk ^= gen[i] if ((b >> i) & 1) else 0
        return chk
    data = [version]
    acc = bits = 0
    for byte in program:
        acc = (acc << 8) | byte
        bits += 8
        while bits >= 5:
            bits -= 5
            data.append((acc >> bits) & 31)
    if bits:
        data.append((acc << (5 - bits)) & 31)
    const = 0x2BC830A3 if version else 1
    expanded = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    pm = polymod(expanded + data + [0] * 6) ^ const
    checksum = [(pm >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + '1' + ''.join('qpzry9x8gf2tvdw0s3jn54khce6mua7l'[d] for d in data + checksum)
