#!/usr/bin/env python3
"""Phase 4: full-node block-validation cost of adversarial blocks near the
4,000,000 weight-unit limit, submitted with `submitblock` to an isolated
native regtest node. Measures RPC wall time, node CPU time (utime+stime from
/proc), peak RSS, operation count and block weight for each variant.

Usage: blockbench.py <bitcoin-rs-exp> --out <dir> [--reps 3]
"""
from __future__ import annotations

import argparse
import os
import platform
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from btc import NUMS_X, TapTree, Tx, TxIn, TxOut, block_bytes, push, schnorr_sign, sha, tapleaf_hash, \
    taproot_sighash, xonly, compact
from env import Env, write_json
from node import Node

MAX_WEIGHT = 4_000_000
SECRET = 13
CLK = os.sysconf('SC_CLK_TCK')


def proc_cpu(pid):
    f = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()
    return (int(f[11]) + int(f[12])) / CLK


def proc_mem(pid):
    out = {}
    for line in Path(f'/proc/{pid}/status').read_text().splitlines():
        if line.startswith(('VmRSS', 'VmHWM')):
            k, v = line.split(':')
            out[k] = int(v.split()[0])  # kB
    return out


def operands(width, kind):
    if kind == 'max':
        m = (1 << (8 * width)) - 1
        b = m - 1
    elif kind == 'small_prime':
        m, b = 17, 16
        width = 1
    elif kind == 'composite':
        m, b = 15, 14
        width = 1
    elif kind == 'p25519':
        m = 2**255 - 19
        b = m - 1
        width = 32
    else:
        raise ValueError(kind)
    a = c = m - 1
    return [x.to_bytes(width, 'little') for x in (a, b, c, m)]


def arith_leaf(k):
    return b'\x70\x70\xf0\x75' * k + b'\x6d\x6d\x51'


def sig_leaf(k):
    return b'\x6e\xad' * k + b'\x6d\x51'


def mixed_leaf(k):
    return b'\x70\x70\xf0\x75\x55\x79\x55\x79\xad' * k + b'\x6d\x6d\x6d\x51'


def pad_leaf(_k):
    return b'\x51'


def build_variant(name, inputs, k_per_input, stack_fn, leaf_fn, annex_per_op, sign):
    """Return (leaf, tree, list of (stack items), annex) parameters for each input."""
    leaf = leaf_fn(k_per_input)
    tree = TapTree(NUMS_X, [(leaf, 0xc0)])
    return leaf, tree


def make_spend_tx(fund_txid, vouts, value, leaf, tree, stack, annex_len, sign_slots):
    tx = Tx([TxIn(fund_txid, v, b'', 0xffffffff) for v in vouts],
            [TxOut(value * len(vouts) - 10_000, b'\x51\x20' + xonly(SECRET))])
    annex = (b'\x50' + bytes(annex_len - 1)) if annex_len else None
    spent = [(value, tree.spk())] * len(vouts)
    for i in range(len(vouts)):
        items = list(stack)
        if sign_slots:
            tx.vin[i].witness = items + [leaf, tree.control(0)] + ([annex] if annex else [])
            msg = taproot_sighash(tx, i, spent, leaf_hash=tapleaf_hash(leaf), annex=annex)
            sig = schnorr_sign(msg, SECRET)
            for s in sign_slots:
                items[s] = sig
        tx.vin[i].witness = items + [leaf, tree.control(0)] + ([annex] if annex else [])
    return tx


VARIANTS = {
    # name: (inputs, ops per input, leaf, stack builder, budget bytes per op, sign slots)
    'baseline_annex_only_1in': (1, 0, 'pad', lambda: [], 0, []),
    'muladdmod_w32_max_1in': (1, None, 'arith', lambda: operands(32, 'max'), 50, []),
    'muladdmod_w32_max_500in': (500, None, 'arith', lambda: operands(32, 'max'), 50, []),
    'muladdmod_p25519_1in': (1, None, 'arith', lambda: operands(32, 'p25519'), 50, []),
    'muladdmod_w16_max_1in': (1, None, 'arith', lambda: operands(16, 'max'), 50, []),
    'muladdmod_w1_composite_1in': (1, None, 'arith', lambda: operands(1, 'composite'), 50, []),
    'schnorr_1in': (1, None, 'sig', lambda: [b'S' * 64, xonly(SECRET)], 50, [0]),
    'schnorr_500in': (500, None, 'sig', lambda: [b'S' * 64, xonly(SECRET)], 50, [0]),
    'mixed_arith_schnorr_1in': (1, None, 'mixed', lambda: [b'S' * 64, xonly(SECRET)] + operands(32, 'max'), 100, [0]),
    'mixed_arith_schnorr_500in': (500, None, 'mixed', lambda: [b'S' * 64, xonly(SECRET)] + operands(32, 'max'), 100, [0]),
}
LEAVES = {'arith': (arith_leaf, 4), 'sig': (sig_leaf, 2), 'mixed': (mixed_leaf, 9), 'pad': (pad_leaf, 0)}


def plan(name, budget_weight):
    inputs, _, leaf_kind, stack_fn, per_op, slots = VARIANTS[name]
    fn, script_per_op = LEAVES[leaf_kind]
    per_input_weight = budget_weight // inputs
    overhead = 41 * 4 + 200  # input base bytes (x4) + control/stack/compact overhead
    if leaf_kind == 'pad':
        return inputs, 0, fn, stack_fn, max(0, per_input_weight - overhead - 10), slots
    unit = script_per_op + per_op           # witness bytes per op (script + annex budget)
    k = max(1, (per_input_weight - overhead) // unit)
    annex = per_op * k + 8
    return inputs, k, fn, stack_fn, annex, slots


def run(binary: Path, out: Path, reps: int):
    out.mkdir(parents=True, exist_ok=True)
    hw = {'platform': platform.platform(), 'python': platform.python_version(), 'nproc': os.cpu_count()}
    try:
        hw['cpu'] = next(l.split(':', 1)[1].strip() for l in Path('/proc/cpuinfo').read_text().splitlines()
                         if l.startswith('model name'))
        hw['mem_kb'] = int(next(l.split()[1] for l in Path('/proc/meminfo').read_text().splitlines()
                                if l.startswith('MemTotal')))
    except Exception:
        pass
    results = []
    with tempfile.TemporaryDirectory(prefix='muladdmod-bench-') as tmp:
        node = Node(binary, Path(tmp), 'bench')
        node.start()
        env = Env(node)
        try:
            env.bootstrap(432)
            env.refresh_coins(env.mine(200))
            pid = node.process.pid
            for rep in range(reps):
                for name in VARIANTS:
                    if rep > 0 and name in ('schnorr_1in', 'mixed_arith_schnorr_1in'):
                        continue
                    inputs, k, leaf_fn, stack_fn, annex_len, slots = plan(name, MAX_WEIGHT - 12_000)
                    leaf = leaf_fn(k)
                    tree = TapTree(NUMS_X, [(leaf, 0xc0)])
                    value = 20_000
                    fund = env.funding_tx([(value, tree.spk())] * inputs)
                    node.rpc('generateblock', env.wallet.address, [fund.hex()])
                    tx = make_spend_tx(fund.txid(), list(range(inputs)), value, leaf, tree, stack_fn(), annex_len, slots)
                    # shrink annex until the block fits
                    while tx.weight() > MAX_WEIGHT - 4_000 and annex_len > 0:
                        annex_len -= max(1, (tx.weight() - (MAX_WEIGHT - 4_000)) // inputs + 1)
                        tx = make_spend_tx(fund.txid(), list(range(inputs)), value, leaf, tree, stack_fn(), annex_len, slots)
                    tip = node.tip()
                    hdr = node.rpc('getblockheader', tip)
                    raw, bh = block_bytes(tip, hdr['height'] + 1, [tx], hdr['time'] + 1, env.wallet.spk)
                    cpu0, mem0 = proc_cpu(pid), proc_mem(pid)
                    t0 = time.perf_counter()
                    ok, res = node.try_rpc('submitblock', raw.hex(), timeout=600)
                    wall = time.perf_counter() - t0
                    cpu1, mem1 = proc_cpu(pid), proc_mem(pid)
                    accepted = node.tip() == bh
                    ops = k * inputs * (2 if name.startswith('mixed') else 1)
                    rec = {'variant': name, 'rep': rep, 'accepted': accepted, 'rpc_result': res if not ok or res else None,
                           'inputs': inputs, 'ops_per_input': k, 'total_ops': ops,
                           'block_weight_approx': tx.weight() + 4 * 83 + 800,
                           'tx_weight': tx.weight(), 'block_bytes': len(raw), 'wall_s': round(wall, 4),
                           'node_cpu_s': round(cpu1 - cpu0, 3), 'rss_kb_after': mem1.get('VmRSS'),
                           'rss_hwm_kb': mem1.get('VmHWM')}
                    results.append(rec)
                    print(rec, flush=True)
        finally:
            node.stop()
    base = [r for r in results if r['variant'] == 'baseline_annex_only_1in' and r['accepted']]
    base_cpu = min(r['node_cpu_s'] for r in base) if base else 0
    summary = {}
    for name in VARIANTS:
        rows = [r for r in results if r['variant'] == name and r['accepted']]
        if not rows:
            summary[name] = {'accepted': False}
            continue
        walls = sorted(r['wall_s'] for r in rows)
        cpus = sorted(r['node_cpu_s'] for r in rows)
        summary[name] = {'accepted': True, 'total_ops': rows[0]['total_ops'], 'tx_weight': rows[0]['tx_weight'],
                         'median_wall_s': walls[len(walls) // 2], 'median_node_cpu_s': cpus[len(cpus) // 2],
                         'cpu_over_baseline_s': round(cpus[len(cpus) // 2] - base_cpu, 3),
                         'max_rss_hwm_kb': max(r['rss_hwm_kb'] or 0 for r in rows)}
    write_json(out / 'phase4-blockbench.json', {'hardware': hw, 'binary_sha256': sha(binary.read_bytes()).hex(),
                                                'summary': summary, 'results': results})
    for k, v in summary.items():
        print(k, v)


if __name__ == '__main__':
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('binary', type=Path)
    ap.add_argument('--out', type=Path, required=True)
    ap.add_argument('--reps', type=int, default=3)
    a = ap.parse_args()
    run(a.binary, a.out, a.reps)
