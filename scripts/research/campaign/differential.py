#!/usr/bin/env python3
"""Phase 3: consensus differential testing of the OP_SUCCESS240 activation
boundary.

Generates random script-path (and legacy / witness-v0) spends around 0xf0 and
evaluates each one four ways:

  rust_on   bitcoin-rs interpreter, consensus flags + EXPERIMENTAL_MULADDMOD
  rust_off  bitcoin-rs interpreter, consensus flags only
  py_on     independent Python reference (refinterp), opcode active
  py_off    independent Python reference, 0xf0 = OP_SUCCESS240

Checks: rust_on == py_on, rust_off == py_off (accept/reject; codes recorded),
and the soft-fork property rust_on accepted => rust_off accepted. Optionally a
second oracle binary built *without* the cargo feature must agree with
rust_off on every case.

Usage: differential.py --oracle <script_oracle> [--oracle-off <bin>] --cases N --out <dir>
"""
from __future__ import annotations

import argparse
import json
import random
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from btc import (NUMS_X, TapTree, Tx, TxIn, TxOut, push, schnorr_sign, sha, tapleaf_hash, taproot_sighash, xonly,
                 hash160)
import refinterp

CONSENSUS = 'P2SH,DERSIG,CHECKLOCKTIMEVERIFY,CHECKSEQUENCEVERIFY,WITNESS,NULLDUMMY,TAPROOT'
EXP = CONSENSUS + ',EXPERIMENTAL_MULADDMOD'
STANDARD_EXTRA = ('STRICTENC,LOW_S,MINIMALDATA,DISCOURAGE_UPGRADABLE_NOPS,CLEANSTACK,MINIMALIF,NULLFAIL,'
                  'WITNESS_PUBKEYTYPE,CONST_SCRIPTCODE,DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM,'
                  'DISCOURAGE_UPGRADABLE_TAPROOT_VERSION,DISCOURAGE_OP_SUCCESS,DISCOURAGE_UPGRADABLE_PUBKEYTYPE')
SECRET = 9
OP_SUCCESS_OTHERS = [0x50, 0x62, 0x7e, 0x89, 0xbb, 0xc0, 0xef, 0xf1, 0xfe]


class Oracle:
    def __init__(self, binary):
        self.p = subprocess.Popen([str(binary)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1)

    def ask(self, flags: str, tx: Tx, spent: list, index: int = 0) -> str:
        prev = ' '.join(f'{v} {s.hex() or "-"}' for v, s in spent)
        self.p.stdin.write(f'{flags} {index} {tx.hex()} {len(spent)} {prev}\n')
        self.p.stdin.flush()
        return self.p.stdout.readline().strip()

    def close(self):
        self.p.stdin.close()
        self.p.wait(timeout=10)


def norm(rust: str) -> str:
    if rust == 'OK':
        return 'OK'
    if rust.startswith('ERR '):
        return rust[4:]
    return rust


# ------------------------------------------------------------------ case generation

def rand_modulus(rng):
    w = rng.choice([1, 1, 2, 4, 8, 16, 31, 32, 32])
    lo = max(2, 1 << (8 * (w - 1)))
    return rng.randrange(lo, 1 << (8 * w)), w


def encode_operand(rng, value, m, w, malformed_p):
    if rng.random() >= malformed_p:
        return value.to_bytes(w, 'little')
    kind = rng.choice(['short', 'long', 'ge', 'eqm', 'empty', 'neg0'])
    if kind == 'short':
        return value.to_bytes(w, 'little')[:-1]
    if kind == 'long':
        return value.to_bytes(w, 'little') + b'\x00'
    if kind == 'ge':
        v = m + rng.randrange(0, (1 << (8 * w)) - m) if (1 << (8 * w)) > m else m
        return (v % (1 << (8 * w))).to_bytes(w, 'little') if v < (1 << (8 * w)) else b'\xff' * w
    if kind == 'eqm':
        return m.to_bytes(w, 'little')
    if kind == 'empty':
        return b''
    return b'\x80'


def encode_modulus(rng, m, w, malformed_p):
    if rng.random() >= malformed_p:
        return m.to_bytes(w, 'little')
    return rng.choice([m.to_bytes(w, 'little') + b'\x00', b'\x00', b'\x01', b'', bytes([1]) * 33,
                       (0).to_bytes(w, 'little')])


def arith_block(rng, stack_items: list, malformed_p: float):
    """Returns (script_bytes, witness_items_to_append, n_muladdmod) for one arithmetic check."""
    m, w = rand_modulus(rng)
    a, b, c = (rng.randrange(m) for _ in range(3))
    r = (a * b + c) % m
    ea, eb, ec = (encode_operand(rng, v, m, w, malformed_p) for v in (a, b, c))
    em = encode_modulus(rng, m, w, malformed_p)
    expected = r.to_bytes(w, 'little')
    if rng.random() < 0.25:
        expected = ((r + 1) % m).to_bytes(w, 'little')
    source = rng.choice(['script', 'witness', 'mixed'])
    script = b''
    wit = []
    for i, v in enumerate([ea, eb, ec, em]):
        if source == 'script' or (source == 'mixed' and i % 2):
            if len(v) <= 520:
                script += push(v) if v else b'\x00'
            else:
                script += push(v[:520])
        else:
            wit.append(v)
    # witness items come first on the stack; script pushes after -> keep order a,b,c,m by moving
    if source == 'witness':
        pass
    elif source == 'mixed':
        # witness provides a and c, script provides b and m: reorder with SWAP sequence
        # stack after pushes: a c b m -> want a b c m : (a c b m) -> ROT ROT? use 2SWAP-free approach:
        # a c b m  --SWAP--> a c m b --ROT--> a m b c --ROT--> a b c m
        script += b'\x7c\x7b\x7b'
    tail = rng.choice(['equal', 'equalverify', 'drop', 'none'])
    script += bytes([0xf0])
    if tail == 'equal':
        script += push(expected) + b'\x87'
    elif tail == 'equalverify':
        script += push(expected) + b'\x88\x51'
    elif tail == 'drop':
        script += b'\x75\x51'
    else:
        script += b'\x82\x75\x51'  # SIZE DROP -> leaves result and TRUE: cleanstack failure unless consumed
        script += b'\x77'           # NIP
    return script, wit


def gen_case(rng, idx):
    malformed_p = rng.choice([0.0, 0.05, 0.3])
    kind = rng.choices(['tapscript', 'legacy_p2sh', 'p2wsh'], weights=[90, 5, 5])[0]
    meta = {'kind': kind}
    if kind != 'tapscript':
        # 0xf0 outside tapscript must be BAD_OPCODE when executed, ignored when skipped
        branch = rng.choice(['exec', 'skip'])
        meta['branch'] = branch
        inner = (b'\x00\x63\xf0\x68\x51' if branch == 'skip' else b'\x51\x63\xf0\x68\x51')
        if kind == 'legacy_p2sh':
            spk = b'\xa9\x14' + hash160(inner) + b'\x87'
            tx = Tx([TxIn('22' * 32, idx, push(inner), 0xffffffff)], [TxOut(1000, b'\x51')])
        else:
            spk = b'\x00\x20' + sha(inner)
            tx = Tx([TxIn('22' * 32, idx, b'', 0xffffffff, [inner])], [TxOut(1000, b'\x51')])
        return tx, [(10_000, spk)], meta
    script = b''
    witness = []
    n_ops = 0
    shape = rng.choice(['plain', 'if_exec', 'if_skip', 'else', 'nested', 'multi', 'budget', 'stack', 'success',
                        'sig', 'underflow', 'element'])
    meta['shape'] = shape
    if shape in ('plain', 'success'):
        s, w = arith_block(rng, witness, malformed_p)
        script, witness = s, w
        n_ops = 1
        if shape == 'success':
            other = rng.choice(OP_SUCCESS_OTHERS)
            pos = rng.choice(['before', 'after', 'skipped'])
            meta['other_success'] = hex(other); meta['pos'] = pos
            if pos == 'before':
                script = bytes([other]) + script
            elif pos == 'after':
                script = script + bytes([other])
            else:
                script = script + b'\x00\x63' + bytes([other]) + b'\x68'
    elif shape in ('if_exec', 'if_skip', 'else'):
        s, w = arith_block(rng, witness, 0.0 if shape != 'if_exec' else malformed_p)
        if shape == 'if_exec':
            script = b'\x63' + s + b'\x67\x00\x68'
            sel = rng.choice([b'\x01', b'\x01', b'\x02', b'\x01\x00'])
            witness = w + [sel]
        elif shape == 'if_skip':
            # skipped branch contains 0xf0 with garbage operands: must not execute or be charged
            script = b'\x63' + b'\xf0' * rng.randint(1, 4) + s + b'\x67\x51\x68'
            witness = w + [b'']
        else:
            script = b'\x64' + b'\x51' + b'\x67' + s + b'\x68'
            witness = w + [rng.choice([b'', b'\x01'])]
    elif shape == 'nested':
        s, w = arith_block(rng, witness, malformed_p)
        script = b'\x63\x63' + s + b'\x67\x00\x68\x67\x51\x68'
        witness = w + [rng.choice([b'\x01', b'']), rng.choice([b'\x01', b''])]
    elif shape == 'multi':
        k = rng.randint(2, 6)
        parts = []
        for _ in range(k):
            s, w = arith_block(rng, witness, malformed_p / 2)
            if s.endswith(b'\x87'):
                s += b'\x69'   # VERIFY
            elif s.endswith(b'\x51') and s[-2:] != b'\x77\x51':
                s = s[:-1]
            elif s.endswith(b'\x77'):
                s += b'\x75'
            parts.append(s); witness = w + witness
        script = b''.join(parts) + b'\x51'
        n_ops = k
    elif shape == 'budget':
        m, wd = rand_modulus(rng)
        ops = [x.to_bytes(wd, 'little') for x in (rng.randrange(m), rng.randrange(m), rng.randrange(m), m)]
        k = rng.randint(1, 40)
        script = b'\x70\x70\xf0\x75' * k + b'\x6d\x6d\x51'
        witness = ops
        # annex sized to land the budget at exactly -1..+1 units around the threshold
        base_wit = [*ops, script, b'C' * 33]
        target = 50 * k - 50 + rng.choice([-1, 0, 0, 1, 25])
        size_wo_annex = refinterp.witness_size(base_wit)
        need = target - size_wo_annex
        meta['budget_delta'] = need
        if need > 2:
            meta['annex_len'] = need - (1 if need - 1 < 253 else 3) - 1  # placeholder adjusted below
        n_ops = k
    elif shape == 'stack':
        m = 17
        depth = rng.choice([995, 996, 997, 998, 999, 1000, 1001])
        filler = [b''] * (depth - 4)
        witness = filler + [b'\x07', b'\x0b', b'\x03', b'\x11']
        script = b'\xf0' + b'\x75' * (depth - 4) + b'\x75\x51' if depth < 1001 else b'\xf0\x51'
        meta['initial_depth'] = depth
    elif shape == 'sig':
        s, w = arith_block(rng, witness, malformed_p)
        if s.endswith(b'\x87'):
            s += b'\x69'
        elif s.endswith(b'\x51') and not s.endswith(b'\x77\x51'):
            s = s[:-1]
        elif s.endswith(b'\x77'):
            s += b'\x75'
        script = s + push(xonly(SECRET)) + b'\xac'
        witness = [b'SIGPLACEHOLDER'] + w
        meta['sig'] = rng.choice(['valid', 'valid', 'invalid', 'empty'])
    elif shape == 'underflow':
        n = rng.randint(0, 3)
        witness = [b'\x01'] * n
        script = b'\xf0\x51'
    elif shape == 'element':
        big = rng.choice([520, 521])
        witness = [b'\x00' * big, b'\x07', b'\x0b', b'\x03', b'\x11']
        script = b'\xf0\x75\x75\x51'
        meta['element'] = big
    tree = TapTree(NUMS_X, [(script, 0xc0)])
    spk = tree.spk()
    tx = Tx([TxIn('33' * 32, idx, b'', 0xffffffff)], [TxOut(5000, b'\x00\x14' + bytes(20))])
    annex = None
    if shape == 'budget' and meta.get('budget_delta', 0) > 2:
        need = meta['budget_delta']
        # witness size grows by compact(len)+len of the annex and possibly the count byte
        for L in range(max(1, need - 4), need + 2):
            trial = [*witness, script, tree.control(0), b'\x50' + bytes(L - 1)]
            if refinterp.witness_size(trial) == refinterp.witness_size([*witness, script, tree.control(0)]) + need:
                annex = b'\x50' + bytes(L - 1); break
        if annex is None:
            annex = b'\x50' + bytes(max(0, need - 3))
    full = [*witness, script, tree.control(0)] + ([annex] if annex else [])
    spent = [(10_000, spk)]
    if shape == 'sig':
        tx.vin[0].witness = full
        msg = taproot_sighash(tx, 0, spent, leaf_hash=tapleaf_hash(script), annex=annex)
        sig = schnorr_sign(msg, SECRET)
        if meta['sig'] == 'invalid':
            sig = bytes([sig[0] ^ 1]) + sig[1:]
        elif meta['sig'] == 'empty':
            sig = b''
        full[0] = sig
    tx.vin[0].witness = full
    meta['script_hex'] = script.hex()
    return tx, spent, meta


def run(oracle_bin, oracle_off_bin, cases, seed, out_dir):
    rng = random.Random(seed)
    on = Oracle(oracle_bin)
    off_build = Oracle(oracle_off_bin) if oracle_off_bin else None
    stats = {'cases': 0, 'by_kind': {}, 'by_shape': {}, 'accept_on': 0, 'accept_off': 0,
             'mismatch_rust_py_on': 0, 'mismatch_rust_py_off': 0, 'code_mismatch_on': 0,
             'softfork_violations': 0, 'feature_off_build_mismatch': 0, 'flag_changed_verdict': 0,
             'policy_on_accept': 0, 'policy_off_accept': 0}
    failures = []
    code_samples = {}
    t0 = time.time()
    for i in range(cases):
        tx, spent, meta = gen_case(rng, i)
        r_on = norm(on.ask(EXP, tx, spent))
        r_off = norm(on.ask(CONSENSUS, tx, spent))
        p_on_std = norm(on.ask(EXP + ',' + STANDARD_EXTRA, tx, spent))
        p_off_std = norm(on.ask(CONSENSUS + ',' + STANDARD_EXTRA, tx, spent))
        stats['cases'] += 1
        stats['by_kind'][meta['kind']] = stats['by_kind'].get(meta['kind'], 0) + 1
        if 'shape' in meta:
            stats['by_shape'][meta['shape']] = stats['by_shape'].get(meta['shape'], 0) + 1
        stats['accept_on'] += r_on == 'OK'
        stats['accept_off'] += r_off == 'OK'
        stats['policy_on_accept'] += p_on_std == 'OK'
        stats['policy_off_accept'] += p_off_std == 'OK'
        stats['flag_changed_verdict'] += (r_on == 'OK') != (r_off == 'OK')
        rec = {'i': i, 'meta': meta, 'rust_on': r_on, 'rust_off': r_off, 'tx': tx.hex(),
               'spent': [[v, s.hex()] for v, s in spent]}
        if meta['kind'] == 'tapscript':
            py_on = refinterp.verify_taproot_input(tx, 0, spent, muladdmod=True)
            py_off = refinterp.verify_taproot_input(tx, 0, spent, muladdmod=False)
            rec.update(py_on=py_on, py_off=py_off)
            if (py_on == 'OK') != (r_on == 'OK'):
                stats['mismatch_rust_py_on'] += 1; failures.append({'type': 'verdict_on', **rec})
            elif py_on != r_on:
                stats['code_mismatch_on'] += 1
                key = f'{py_on}|{r_on}'
                code_samples.setdefault(key, {'count': 0, 'example': rec})
                code_samples[key]['count'] += 1
            if (py_off == 'OK') != (r_off == 'OK'):
                stats['mismatch_rust_py_off'] += 1; failures.append({'type': 'verdict_off', **rec})
        else:
            expected = 'OK' if meta['branch'] == 'skip' else 'BAD_OPCODE'
            if r_on != expected or r_off != expected:
                failures.append({'type': 'legacy_v0_isolation', 'expected': expected, **rec})
        if r_on == 'OK' and r_off != 'OK':
            stats['softfork_violations'] += 1; failures.append({'type': 'softfork', **rec})
        if off_build is not None:
            r_build = norm(off_build.ask(CONSENSUS, tx, spent))
            if r_build != r_off:
                stats['feature_off_build_mismatch'] += 1
                failures.append({'type': 'feature_off_build', 'rust_off_build': r_build, **rec})
            exp_disabled = norm(off_build.ask(EXP, tx, spent))
            if exp_disabled != 'EXPERIMENTAL_DISABLED':
                failures.append({'type': 'feature_off_build_accepts_flag', 'got': exp_disabled, **rec})
    on.close()
    if off_build:
        off_build.close()
    stats['elapsed_s'] = round(time.time() - t0, 1)
    stats['failures'] = len(failures)
    report = {'seed': seed, 'stats': stats, 'code_mismatches': {k: {'count': v['count'], 'example': v['example']}
                                                                  for k, v in code_samples.items()},
              'failures': failures[:200]}
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / f'phase3-differential-seed{seed}.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(stats, indent=2))
    print('code mismatches:', {k: v['count'] for k, v in code_samples.items()})
    return report


if __name__ == '__main__':
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--oracle', type=Path, required=True)
    ap.add_argument('--oracle-off', type=Path)
    ap.add_argument('--cases', type=int, default=2000)
    ap.add_argument('--seed', type=int, default=20261112)
    ap.add_argument('--out', type=Path, required=True)
    a = ap.parse_args()
    run(a.oracle, a.oracle_off, a.cases, a.seed, a.out)
