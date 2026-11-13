#!/usr/bin/env python3
"""Phase 5: bounded state-machine exploration of the funded claim lifecycle
on a live native regtest node.

For every action sequence over {M: mine a block from the mempool, E: mine an
empty block, R: broadcast the recovery, S: broadcast the settlement,
X: invalidate the tip block if it was mined inside this sequence} up to a
bound, a fresh claim (false or honest, delay 2) is funded and the sequence is
executed. After every step the node state is compared with an abstract model
and these invariants are checked:

  EXCLUSIVITY  recovery and settlement are never both confirmed on the active chain
  SAFETY       a confirmed recovery implies the claim is false
  TIMELOCK     a confirmed settlement sits at height >= funding_height + delay
  MEMPOOL      the mempool never holds both terminal spends
  MODEL        every broadcast verdict equals the model's prediction

Usage: statemachine.py <bitcoin-rs-exp> --depth 4 [--random 200 --random-depth 7] --out <dir>
"""
from __future__ import annotations

import argparse
import itertools
import random
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from btc import sha
from contract import Claim, spend_claim
from env import Env, write_json
from node import Node

DELAY = 2
AMOUNT = 50_000
ACTIONS = 'MERSX'


def explore(env: Env, seq: str, honest: bool, idx: int):
    node = env.node
    claim = Claim(sha(b'sm' + idx.to_bytes(4, 'big')), 7, 11, 3, 12 if honest else 13, 17, delay=DELAY)
    fund = env.funding_tx([(AMOUNT, claim.spk())])
    node.rpc('generateblock', env.wallet.address, [fund.hex()])
    fund_h = node.height()
    R = spend_claim(claim, fund.txid(), 0, AMOUNT, True)
    S = spend_claim(claim, fund.txid(), 0, AMOUNT, False)
    mined_here = []
    trace = []
    violations = []

    def confirmed(tx):
        """Terminal spends pay to an output nobody spends here: output in the UTXO set
        (excluding the mempool) <=> transaction confirmed on the active chain."""
        out = node.rpc('gettxout', tx.txid(), 0, False)
        if not out:
            return False, None
        return True, node.height() - out['confirmations'] + 1

    def height_of(h):
        return h

    for step, a in enumerate(seq):
        pool = node.mempool()
        r_conf, _ = confirmed(R)
        s_conf, _ = confirmed(S)
        spent = r_conf or s_conf
        tip_h = node.height()
        verdict = None
        if a == 'R':
            predicted = (not honest) and not spent and S.txid() not in pool
            if R.txid() in pool:
                predicted = True  # idempotent resubmission returns the txid
            ok, res = node.try_rpc('sendrawtransaction', R.hex())
            verdict = ok
            if ok != predicted:
                violations.append({'type': 'MODEL', 'step': step, 'action': a, 'predicted': predicted, 'node': ok, 'reason': res})
        elif a == 'S':
            mature = (tip_h + 1) - fund_h >= DELAY
            predicted = mature and not spent and R.txid() not in pool
            if S.txid() in pool:
                predicted = True
            ok, res = node.try_rpc('sendrawtransaction', S.hex())
            verdict = ok
            if ok != predicted:
                violations.append({'type': 'MODEL', 'step': step, 'action': a, 'predicted': predicted, 'node': ok, 'reason': res})
        elif a == 'M':
            mined_here.append(env.mine(1)[0])
        elif a == 'E':
            mined_here.append(node.rpc('generateblock', env.wallet.address, [])['hash'])
        elif a == 'X':
            if mined_here and node.tip() == mined_here[-1]:
                node.rpc('invalidateblock', mined_here.pop())
                verdict = 'invalidated'
            else:
                verdict = 'noop'
        # ----- invariants
        pool = node.mempool()
        r_conf, r_block = confirmed(R)
        s_conf, s_block = confirmed(S)
        if r_conf and s_conf:
            violations.append({'type': 'EXCLUSIVITY', 'step': step})
        if r_conf and honest:
            violations.append({'type': 'SAFETY', 'step': step})
        if s_conf and height_of(s_block) < fund_h + DELAY:
            violations.append({'type': 'TIMELOCK', 'step': step, 'height': height_of(s_block)})
        if R.txid() in pool and S.txid() in pool:
            violations.append({'type': 'MEMPOOL', 'step': step})
        trace.append({'a': a, 'verdict': verdict, 'h': node.height(), 'R_conf': r_conf, 'S_conf': s_conf,
                      'R_pool': R.txid() in pool, 'S_pool': S.txid() in pool})
    # clean up: mine everything so the next sequence starts from an empty mempool
    if node.mempool():
        env.mine(1)
    return {'seq': seq, 'honest': honest, 'funding_height': fund_h, 'trace': trace, 'violations': violations}


def run(binary: Path, depth: int, n_random: int, random_depth: int, out: Path):
    out.mkdir(parents=True, exist_ok=True)
    t0 = time.time()
    with tempfile.TemporaryDirectory(prefix='muladdmod-sm-') as tmp:
        node = Node(binary, Path(tmp), 'sm')
        node.start()
        env = Env(node)
        results = []
        try:
            env.bootstrap(432)
            seqs = [''.join(p) for n in range(1, depth + 1) for p in itertools.product(ACTIONS, repeat=n)]
            rng = random.Random(5)
            seqs += [''.join(rng.choice(ACTIONS) for _ in range(random_depth)) for _ in range(n_random)]
            idx = 0
            for seq in seqs:
                for honest in (False, True):
                    # replenish mature coins as needed
                    if len(env.coins) < 5:
                        env.refresh_coins(env.mine(5))
                    try:
                        res = explore(env, seq, honest, idx)
                    except RuntimeError as err:  # wallet exhaustion
                        env.refresh_coins(env.mine(110))
                        res = explore(env, seq, honest, idx)
                    idx += 1
                    results.append(res)
                    if res['violations']:
                        print('VIOLATION', seq, honest, res['violations'], flush=True)
                if len(results) % 100 == 0:
                    print(f'{len(results)} sequences, {time.time() - t0:.0f}s', flush=True)
        finally:
            node.stop()
        viol = [r for r in results if r['violations']]
        summary = {'sequences': len(results), 'exhaustive_depth': depth, 'random_sequences': n_random * 2,
                   'random_depth': random_depth, 'actions': ACTIONS, 'delay': DELAY,
                   'violations': len(viol), 'violation_types': sorted({v['type'] for r in viol for v in r['violations']}),
                   'steps_executed': sum(len(r['trace']) for r in results),
                   'recoveries_confirmed': sum(1 for r in results if r['trace'] and r['trace'][-1]['R_conf']),
                   'settlements_confirmed': sum(1 for r in results if r['trace'] and r['trace'][-1]['S_conf']),
                   'elapsed_s': round(time.time() - t0, 1),
                   'binary_sha256': sha(binary.read_bytes()).hex()}
        write_json(out / 'phase5-statemachine.json', {'summary': summary, 'violating': viol[:100],
                                                      'sample': results[:50]})
        print(summary)


if __name__ == '__main__':
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('binary', type=Path)
    ap.add_argument('--depth', type=int, default=4)
    ap.add_argument('--random', type=int, default=150)
    ap.add_argument('--random-depth', type=int, default=7)
    ap.add_argument('--out', type=Path, required=True)
    a = ap.parse_args()
    run(a.binary, a.depth, a.random, a.random_depth, a.out)
