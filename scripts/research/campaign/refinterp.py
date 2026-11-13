"""Independent Python reference interpreter for BIP341/BIP342 script-path
spends extended with the proposed OP_MULADDMOD (0xf0).

Written from the BIPs and the research specification in
docs/research/muladdmod.md, not from the Rust source. Used as the oracle for
consensus differential testing (Bitcoin Core does not implement 0xf0).

Scope: taproot (witness v1) script-path and key-path spends; every tapscript
opcode. Legacy/v0 are out of scope here (covered by Core vectors).
"""
from __future__ import annotations

import hashlib

from btc import (SIGHASH_ANYONECANPAY, Tx, lift_x, point_add, point_mul, schnorr_verify, sha, tagged,
                 tapleaf_hash, taproot_sighash, N)

MAX_STACK = 1000
MAX_ELEMENT = 520
ANNEX_TAG = 0x50
LEAF_TAPSCRIPT = 0xc0
OP_MULADDMOD = 0xf0
MULADDMOD_COST = 50
SEQUENCE_DISABLE = 1 << 31
SEQUENCE_TYPE = 1 << 22
SEQUENCE_MASK = 0x0000ffff
LOCKTIME_THRESHOLD = 500_000_000


class ScriptFail(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def is_op_success(op: int) -> bool:
    return (op == 80 or op == 98 or 126 <= op <= 129 or 131 <= op <= 134 or 137 <= op <= 138
            or 141 <= op <= 142 or 149 <= op <= 153 or 187 <= op <= 254)


def parse(script: bytes):
    """Yield (opcode, data_or_None). Raises ScriptFail('BAD_OPCODE') on truncation."""
    i = 0
    while i < len(script):
        op = script[i]
        i += 1
        if op <= 0x4e:
            if op < 0x4c:
                n = op
            elif op == 0x4c:
                if i + 1 > len(script):
                    raise ScriptFail('BAD_OPCODE')
                n = script[i]; i += 1
            elif op == 0x4d:
                if i + 2 > len(script):
                    raise ScriptFail('BAD_OPCODE')
                n = int.from_bytes(script[i:i + 2], 'little'); i += 2
            else:
                if i + 4 > len(script):
                    raise ScriptFail('BAD_OPCODE')
                n = int.from_bytes(script[i:i + 4], 'little'); i += 4
            if i + n > len(script):
                raise ScriptFail('BAD_OPCODE')
            yield op, script[i:i + n]
            i += n
        else:
            yield op, None


def minimal_push(op: int, data: bytes) -> bool:
    if len(data) == 0:
        return op == 0x00
    if len(data) == 1 and 1 <= data[0] <= 16:
        return False
    if data == b'\x81':
        return False
    if len(data) <= 75:
        return op == len(data)
    if len(data) <= 255:
        return op == 0x4c
    if len(data) <= 65535:
        return op == 0x4d
    return True


def to_bool(v: bytes) -> bool:
    for i, b in enumerate(v):
        if b:
            return not (i == len(v) - 1 and b == 0x80)
    return False


def _num_decode(v: bytes, max_len: int = 4, minimal: bool = True) -> int:
    if len(v) > max_len:
        raise ScriptFail('UNKNOWN_ERROR')  # Core: scriptnum overflow
    if minimal and v and (v[-1] & 0x7f) == 0 and (len(v) == 1 or not (v[-2] & 0x80)):
        raise ScriptFail('MINIMALDATA')  # Core: non-minimal scriptnum (tapscript always requires minimal numbers)
    if not v:
        return 0
    n = int.from_bytes(v, 'little')
    if v[-1] & 0x80:
        return -(n & ~(0x80 << (8 * (len(v) - 1))))
    return n


def num_encode(n: int) -> bytes:
    if n == 0:
        return b''
    neg, a = n < 0, abs(n)
    out = bytearray()
    while a:
        out.append(a & 0xff); a >>= 8
    if out[-1] & 0x80:
        out.append(0x80 if neg else 0)
    elif neg:
        out[-1] |= 0x80
    return bytes(out)


def muladdmod(a: bytes, b: bytes, c: bytes, m: bytes) -> bytes:
    """Specification: unsigned LE; minimal modulus 2..2^256-1 (1..32 bytes);
    operands width-matched and strictly below the modulus."""
    w = len(m)
    if not 1 <= w <= 32 or m[-1] == 0:
        raise ScriptFail('MULADDMOD_ENCODING')
    mi = int.from_bytes(m, 'little')
    if mi < 2:
        raise ScriptFail('MULADDMOD_ENCODING')
    vals = []
    for x in (a, b, c):
        if len(x) != w:
            raise ScriptFail('MULADDMOD_ENCODING')
        xi = int.from_bytes(x, 'little')
        if xi >= mi:
            raise ScriptFail('MULADDMOD_ENCODING')
        vals.append(xi)
    return ((vals[0] * vals[1] + vals[2]) % mi).to_bytes(w, 'little')


class Context:
    """Transaction context for signature and lock-time checks."""

    def __init__(self, tx: Tx, index: int, spent: list, flags: set, annex=None, leaf_hash=None):
        self.tx, self.index, self.spent, self.flags = tx, index, spent, flags
        self.annex, self.leaf_hash = annex, leaf_hash
        self.codesep_pos = 0xffffffff

    def check_schnorr(self, sig: bytes, pubkey: bytes) -> bool:
        if len(sig) == 0:
            return False
        if len(sig) == 65:
            ht = sig[64]
            if ht == 0x00:
                raise ScriptFail('SCHNORR_SIG_HASHTYPE')
            sig = sig[:64]
        elif len(sig) == 64:
            ht = 0x00
        else:
            raise ScriptFail('SCHNORR_SIG_SIZE')
        if not (ht <= 0x03 or 0x81 <= ht <= 0x83):
            raise ScriptFail('SCHNORR_SIG_HASHTYPE')
        if (ht & 3) == 3 and self.index >= len(self.tx.vout):
            raise ScriptFail('SCHNORR_SIG_HASHTYPE')
        msg = taproot_sighash(self.tx, self.index, self.spent, ht, leaf_hash=self.leaf_hash,
                              annex=self.annex, codesep_pos=self.codesep_pos)
        if not schnorr_verify(msg, pubkey, sig):
            raise ScriptFail('SCHNORR_SIG')
        return True

    def check_csv(self, n: int) -> bool:
        if n & SEQUENCE_DISABLE:
            return True
        if self.tx.version < 2:
            return False
        seq = self.tx.vin[self.index].sequence
        if seq & SEQUENCE_DISABLE:
            return False
        mask = SEQUENCE_TYPE | SEQUENCE_MASK
        if (n & SEQUENCE_TYPE) != (seq & SEQUENCE_TYPE):
            return False
        return (n & mask) <= (seq & mask)

    def check_cltv(self, n: int) -> bool:
        lt = self.tx.locktime
        if (lt < LOCKTIME_THRESHOLD) != (n < LOCKTIME_THRESHOLD):
            return False
        if n > lt:
            return False
        return self.tx.vin[self.index].sequence != 0xffffffff


def exec_tapscript(script: bytes, stack: list, ctx: Context, budget: int, enabled: bool) -> tuple:
    """Execute a tapscript. Returns (stack, budget_left). Raises ScriptFail."""
    alt = []
    cond = []  # list of bools
    pos = -1
    standard = 'STANDARD' in ctx.flags

    def num_decode(v, max_len=4):  # tapscript: minimal numbers are policy (MINIMALDATA), not consensus
        return _num_decode(v, max_len, standard)

    def pop():
        if not stack:
            raise ScriptFail('INVALID_STACK_OPERATION')
        return stack.pop()

    def need(n):
        if len(stack) < n:
            raise ScriptFail('INVALID_STACK_OPERATION')

    for op, data in parse(script):
        pos += 1
        executing = all(cond)
        if data is not None:
            if len(data) > MAX_ELEMENT:
                raise ScriptFail('PUSH_SIZE')
            if executing:
                if standard and not minimal_push(op, data):
                    raise ScriptFail('MINIMALDATA')
                stack.append(bytes(data))
        elif 0x63 <= op <= 0x68 or executing:
            if op == 0x4f:
                stack.append(b'\x81')
            elif 0x51 <= op <= 0x60:
                stack.append(bytes([op - 0x50]))
            elif op == 0x61 or op == 0xb0 or 0xb3 <= op <= 0xb9:  # NOP, NOP1, NOP4-10
                if op != 0x61 and standard:
                    raise ScriptFail('DISCOURAGE_UPGRADABLE_NOPS')
            elif op in (0x63, 0x64):  # IF / NOTIF
                v = False
                if executing:
                    top = pop()
                    if len(top) > 1 or (len(top) == 1 and top[0] != 1):
                        raise ScriptFail('TAPSCRIPT_MINIMALIF')
                    v = len(top) == 1
                    if op == 0x64:
                        v = not v
                cond.append(v)
            elif op == 0x67:
                if not cond:
                    raise ScriptFail('UNBALANCED_CONDITIONAL')
                cond[-1] = not cond[-1]
            elif op == 0x68:
                if not cond:
                    raise ScriptFail('UNBALANCED_CONDITIONAL')
                cond.pop()
            elif op == 0x69:
                if not to_bool(pop()):
                    raise ScriptFail('VERIFY')
            elif op == 0x6a:
                raise ScriptFail('OP_RETURN')
            elif op == 0x6b:
                alt.append(pop())
            elif op == 0x6c:
                if not alt:
                    raise ScriptFail('INVALID_ALTSTACK_OPERATION')
                stack.append(alt.pop())
            elif op == 0x6d:
                need(2); stack.pop(); stack.pop()
            elif op == 0x6e:
                need(2); stack.extend(stack[-2:])
            elif op == 0x6f:
                need(3); stack.extend(stack[-3:])
            elif op == 0x70:
                need(4); stack.extend(stack[-4:-2])
            elif op == 0x71:
                need(6); x = stack[-6:-4]; del stack[-6:-4]; stack.extend(x)
            elif op == 0x72:
                need(4); stack[-4:] = stack[-2:] + stack[-4:-2]
            elif op == 0x73:
                need(1)
                if to_bool(stack[-1]):
                    stack.append(stack[-1])
            elif op == 0x74:
                stack.append(num_encode(len(stack)))
            elif op == 0x75:
                pop()
            elif op == 0x76:
                need(1); stack.append(stack[-1])
            elif op == 0x77:
                need(2); del stack[-2]
            elif op == 0x78:
                need(2); stack.append(stack[-2])
            elif op in (0x79, 0x7a):
                need(2)
                n = num_decode(pop())
                if n < 0 or n >= len(stack):
                    raise ScriptFail('INVALID_STACK_OPERATION')
                v = stack[-n - 1]
                if op == 0x7a:
                    del stack[-n - 1]
                stack.append(v)
            elif op == 0x7b:
                need(3); stack.append(stack.pop(-3))
            elif op == 0x7c:
                need(2); stack[-2], stack[-1] = stack[-1], stack[-2]
            elif op == 0x7d:
                need(2); stack.insert(-2, stack[-1])
            elif op == 0x82:
                need(1); stack.append(num_encode(len(stack[-1])))
            elif op in (0x87, 0x88):
                need(2); b = pop(); a = pop()
                eq = a == b
                if op == 0x88:
                    if not eq:
                        raise ScriptFail('EQUALVERIFY')
                else:
                    stack.append(b'\x01' if eq else b'')
            elif op in (0x8b, 0x8c, 0x8f, 0x90, 0x91, 0x92):
                a = num_decode(pop())
                r = {0x8b: a + 1, 0x8c: a - 1, 0x8f: -a, 0x90: abs(a), 0x91: int(a == 0), 0x92: int(a != 0)}[op]
                stack.append(num_encode(r))
            elif 0x93 <= op <= 0xa4 and op not in (0x95, 0x96, 0x97, 0x98, 0x99):
                need(2); b = num_decode(pop()); a = num_decode(pop())
                r = {0x93: a + b, 0x94: a - b, 0x9a: int(a != 0 and b != 0), 0x9b: int(a != 0 or b != 0),
                     0x9c: int(a == b), 0x9d: int(a == b), 0x9e: int(a != b), 0x9f: int(a < b),
                     0xa0: int(a > b), 0xa1: int(a <= b), 0xa2: int(a >= b), 0xa3: min(a, b), 0xa4: max(a, b)}[op]
                if op == 0x9d:
                    if not r:
                        raise ScriptFail('NUMEQUALVERIFY')
                else:
                    stack.append(num_encode(r))
            elif op == 0xa5:
                need(3); mx = num_decode(pop()); mn = num_decode(pop()); x = num_decode(pop())
                stack.append(num_encode(int(mn <= x < mx)))
            elif op == 0xa6:
                stack.append(hashlib.new('ripemd160', pop()).digest())
            elif op == 0xa7:
                stack.append(hashlib.sha1(pop()).digest())
            elif op == 0xa8:
                stack.append(sha(pop()))
            elif op == 0xa9:
                stack.append(hashlib.new('ripemd160', sha(pop())).digest())
            elif op == 0xaa:
                stack.append(sha(sha(pop())))
            elif op == 0xab:
                ctx.codesep_pos = pos
            elif op in (0xac, 0xad, 0xba):
                if op == 0xba:
                    need(3); pk = pop(); n = num_decode(pop()); sig = pop()
                else:
                    need(2); pk = pop(); sig = pop()
                if sig:
                    budget -= 50
                    if budget < 0:
                        raise ScriptFail('TAPSCRIPT_VALIDATION_WEIGHT')
                if len(pk) == 0:
                    raise ScriptFail('TAPSCRIPT_EMPTY_PUBKEY')
                if len(pk) == 32:
                    ok = ctx.check_schnorr(sig, pk) if sig else False
                else:
                    if standard:
                        raise ScriptFail('DISCOURAGE_UPGRADABLE_PUBKEYTYPE')
                    ok = bool(sig)
                if op == 0xba:
                    stack.append(num_encode(n + (1 if ok else 0)))
                elif op == 0xad:
                    if not ok:
                        raise ScriptFail('CHECKSIGVERIFY')
                else:
                    stack.append(b'\x01' if ok else b'')
            elif op in (0xae, 0xaf):
                raise ScriptFail('TAPSCRIPT_CHECKMULTISIG')
            elif op == 0xb1:
                need(1)
                n = num_decode(stack[-1], 5)
                if n < 0:
                    raise ScriptFail('NEGATIVE_LOCKTIME')
                if not ctx.check_cltv(n):
                    raise ScriptFail('UNSATISFIED_LOCKTIME')
            elif op == 0xb2:
                need(1)
                n = num_decode(stack[-1], 5)
                if n < 0:
                    raise ScriptFail('NEGATIVE_LOCKTIME')
                if not ctx.check_csv(n):
                    raise ScriptFail('UNSATISFIED_LOCKTIME')
            elif op == OP_MULADDMOD and enabled:
                need(4)
                budget -= MULADDMOD_COST
                if budget < 0:
                    raise ScriptFail('TAPSCRIPT_VALIDATION_WEIGHT')
                m = pop(); c = pop(); b = pop(); a = pop()
                stack.append(muladdmod(a, b, c, m))
            else:
                raise ScriptFail('BAD_OPCODE')
        if len(stack) + len(alt) > MAX_STACK:
            raise ScriptFail('STACK_SIZE')
    if cond:
        raise ScriptFail('UNBALANCED_CONDITIONAL')
    return stack, budget


def witness_size(witness: list) -> int:
    def cs(n):
        return 1 if n < 253 else 3 if n <= 0xffff else 5
    return cs(len(witness)) + sum(cs(len(w)) + len(w) for w in witness)


def verify_taproot_input(tx: Tx, index: int, spent: list, muladdmod: bool, standard: bool = False) -> str:
    """Return 'OK' or the failing SCRIPT_ERR name for a witness v1 (P2TR) input."""
    flags = {'STANDARD'} if standard else set()
    spk = spent[index][1]
    if not (len(spk) == 34 and spk[0] == 0x51 and spk[1] == 0x20):
        return 'UNSUPPORTED'
    program = spk[2:]
    witness = list(tx.vin[index].witness)
    try:
        if not witness:
            raise ScriptFail('WITNESS_PROGRAM_WITNESS_EMPTY')
        annex = None
        if len(witness) >= 2 and witness[-1] and witness[-1][0] == ANNEX_TAG:
            annex = witness[-1]
            stack = witness[:-1]
        else:
            stack = witness
        if len(stack) == 1:
            ctx = Context(tx, index, spent, flags, annex=annex, leaf_hash=None)
            sig = stack[0]
            if not sig:
                raise ScriptFail('SCHNORR_SIG_SIZE')
            # key path: same signature encoding rules, key = output key
            if len(sig) not in (64, 65):
                raise ScriptFail('SCHNORR_SIG_SIZE')
            ctx.check_schnorr(sig, program)
            return 'OK'
        control = stack[-1]
        script = stack[-2]
        stack = stack[:-2]
        if len(control) < 33 or len(control) > 33 + 32 * 128 or (len(control) - 33) % 32:
            raise ScriptFail('TAPROOT_WRONG_CONTROL_SIZE')
        leaf_version = control[0] & 0xfe
        k = tapleaf_hash(script, leaf_version)
        for i in range(33, len(control), 32):
            e = control[i:i + 32]
            k = tagged('TapBranch', k + e if k < e else e + k)
        p = lift_x(int.from_bytes(control[1:33], 'big'))
        if p is None:
            raise ScriptFail('WITNESS_PROGRAM_MISMATCH')
        t = int.from_bytes(tagged('TapTweak', control[1:33] + k), 'big')
        if t >= N:
            raise ScriptFail('WITNESS_PROGRAM_MISMATCH')
        q = point_add(p, point_mul(t))
        if q is None or q[0].to_bytes(32, 'big') != program or (q[1] & 1) != (control[0] & 1):
            raise ScriptFail('WITNESS_PROGRAM_MISMATCH')
        if leaf_version != LEAF_TAPSCRIPT:
            if standard:
                raise ScriptFail('DISCOURAGE_UPGRADABLE_TAPROOT_VERSION')
            return 'OK'
        # OP_SUCCESS scan (whole script, regardless of reachability)
        for op, data in parse(script):
            if data is None and is_op_success(op) and not (op == OP_MULADDMOD and muladdmod):
                if standard:
                    raise ScriptFail('DISCOURAGE_OP_SUCCESS')
                return 'OK'
        if len(stack) > MAX_STACK:
            raise ScriptFail('STACK_SIZE')
        if any(len(e) > MAX_ELEMENT for e in stack):
            raise ScriptFail('PUSH_SIZE')
        budget = witness_size(witness) + 50
        ctx = Context(tx, index, spent, flags, annex=annex, leaf_hash=tapleaf_hash(script, leaf_version))
        final, _ = exec_tapscript(script, list(stack), ctx, budget, muladdmod)
        if len(final) != 1:
            raise ScriptFail('CLEANSTACK')
        if not to_bool(final[0]):
            raise ScriptFail('EVAL_FALSE')
        return 'OK'
    except ScriptFail as fail:
        return fail.code
