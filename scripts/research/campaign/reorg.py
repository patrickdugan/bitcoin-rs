#!/usr/bin/env python3
"""Phase 6 (and the network half of phase 3): multi-node propagation,
conflicting chains, reorganizations and UTXO rollback around funded
MULADDMOD dispute claims.

Nodes:
  A, B  bitcoin-rs with experimental-muladdmod-regtest (upgraded)
  C     Bitcoin Core 31.1 (unupgraded: 0xf0 = OP_SUCCESS240)       [optional]
  D     bitcoin-rs built without the feature (unupgraded)           [optional]

Every step appends a trace record (heights, tips, UTXO-set hash, claim
outpoint status, mempool membership) so counterexamples are replayable.

Usage: reorg.py --exp <bitcoin-rs-exp> [--core <bitcoind>] [--off <bitcoin-rs-off>] --out <dir>
"""
from __future__ import annotations

import argparse
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from btc import NUMS_X, TapTree, Tx, TxIn, TxOut, block_bytes, push, sha
from contract import Claim, spend_claim
from env import Env, Wallet, write_json
from node import Node, RpcError

AMOUNT = 100_000


class Net:
    def __init__(self, nodes: dict, wallet: Wallet, out: Path):
        self.nodes = nodes
        self.wallet = wallet
        self.trace = []
        self.checks = []
        self.out = out
        self.tracked = {}   # label -> (txid, vout)
        self.txs = {}       # label -> txid

    def connect(self, a: str, b: str):
        na, nb = self.nodes[a], self.nodes[b]
        target = f'127.0.0.1:{nb.p2p_port}'
        ok, res = na.try_rpc('addnode', target, 'onetry')
        if not ok:
            ok, res = na.try_rpc('addnode', target, 'add')
        return ok, res

    def peers(self, name):
        ok, res = self.nodes[name].try_rpc('getpeerinfo')
        return len(res) if ok else -1

    def reconnect(self, extra_pairs=()):
        """Re-enable networking, clear loopback bans left by invalid-block punishment, reconnect."""
        for n in self.nodes.values():
            n.try_rpc('setnetworkactive', True)
            n.try_rpc('clearbanned')
        for other in self.nodes:
            if other != 'A':
                self.connect(other, 'A')
                self.connect('A', other)
        for a, b in extra_pairs:
            self.connect(a, b)
            self.connect(b, a)

    def sync(self, names, timeout=90):
        deadline = time.monotonic() + timeout
        last_dial = 0.0
        while time.monotonic() < deadline:
            tips = {n: self.nodes[n].tip() for n in names}
            if len(set(tips.values())) == 1:
                return tips
            now = time.monotonic()
            if now - last_dial >= 5.0:
                last_dial = now
                for a in names:
                    for b in names:
                        if a != b:
                            self.connect(a, b)
            time.sleep(0.3)
        raise TimeoutError(f'sync {names}: {tips}')

    def wait_tip(self, name, tip, timeout=90):
        return self.nodes[name].wait_for(lambda: self.nodes[name].tip() == tip, timeout, f'tip {tip}')

    def state(self, name):
        n = self.nodes[name]
        s = {'height': n.height(), 'tip': n.tip()}
        ok, info = n.try_rpc('gettxoutsetinfo')
        if ok:
            s['utxo_hash'] = info.get('hash_serialized_3') or info.get('hash_serialized_2') or info.get('muhash')
            s['utxo_count'] = info.get('txouts')
        s['claims'] = {k: n.rpc('gettxout', t, v) is not None for k, (t, v) in self.tracked.items()}
        pool = n.mempool()
        s['mempool'] = sorted(k for k, t in self.txs.items() if t in pool)
        s['confirmed'] = {}
        for k, t in self.txs.items():
            ok, raw = n.try_rpc('getrawtransaction', t, True)
            s['confirmed'][k] = bool(ok and raw.get('confirmations'))
        return s

    def snap(self, step, names=None, **extra):
        names = names or [k for k in self.nodes]
        rec = {'step': step, 'time': time.time(), **extra, 'nodes': {}}
        for n in names:
            try:
                rec['nodes'][n] = self.state(n)
            except Exception as err:  # keep the trace even when a node is down
                rec['nodes'][n] = {'error': repr(err)}
        self.trace.append(rec)
        print(f'--- {step}: ' + ', '.join(f'{n}@{rec["nodes"][n].get("height")}' for n in names), flush=True)
        return rec

    def check(self, name, cond, **detail):
        self.checks.append({'name': name, 'passed': bool(cond), **detail})
        print(f'[{"PASS" if cond else "FAIL"}] {name} {detail if not cond else ""}', flush=True)
        return cond


def submit_block(node: Node, wallet: Wallet, txs, prev=None):
    prev = prev or node.tip()
    hdr = node.rpc('getblockheader', prev)
    raw, bh = block_bytes(prev, hdr['height'] + 1, txs, max(hdr['time'] + 1, int(time.time())), wallet.spk)
    res = node.rpc('submitblock', raw.hex())
    return bh, res


def run(exp: Path, core: Path | None, off: Path | None, out: Path):
    out.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='muladdmod-reorg-') as tmp:
        root = Path(tmp)
        nodes = {'A': Node(exp, root, 'A'), 'B': Node(exp, root, 'B')}
        if core:
            nodes['C'] = Node(core, root, 'C', kind='core')
        if off:
            nodes['D'] = Node(off, root, 'D')
        wallet = Wallet()
        net = Net(nodes, wallet, out)
        try:
            for n in nodes.values():
                n.start()
            A, B = nodes['A'], nodes['B']
            envA = Env(A, wallet)
            for other in nodes:
                if other != 'A':
                    net.connect(other, 'A')
            A.wait_for(lambda: net.peers('A') >= len(nodes) - 1, 60, 'peers')
            net.check('peers_connected', all(net.peers(n) >= 1 for n in nodes), peers={n: net.peers(n) for n in nodes})
            envA.bootstrap()
            net.sync(list(nodes))
            net.snap('bootstrapped')
            # ---------------------------------------------------------------- fund claims
            claims = {f'F{i}': Claim(sha(b'reorg-claim' + bytes([i])), 7, 11, 3, 13, 17) for i in range(1, 5)}
            claims['H'] = Claim(sha(b'reorg-honest'), 7, 11, 3, 12, 17)
            fund = envA.funding_tx([(AMOUNT, c.spk()) for c in claims.values()])
            A.rpc('sendrawtransaction', fund.hex())
            net.txs['funding'] = fund.txid()
            net.check('funding_propagates_to_B', B.wait_for(lambda: fund.txid() in B.mempool(), 60, 'fund relay'))
            fb = envA.mine(1)[0]
            net.sync(list(nodes))
            fund_h = A.height()
            for i, k in enumerate(claims):
                net.tracked[k] = (fund.txid(), i)
            net.snap('claims_funded', funding_height=fund_h)

            def rec(k, **kw):
                return spend_claim(claims[k], fund.txid(), list(claims).index(k), AMOUNT, True, **kw)

            def setl(k, **kw):
                return spend_claim(claims[k], fund.txid(), list(claims).index(k), AMOUNT, False, **kw)

            # ---------------------------------------------------------------- propagation of a recovery
            r1 = rec('F1')
            net.txs['F1_recovery'] = r1.txid()
            A.rpc('sendrawtransaction', r1.hex())
            net.check('recovery_relays_A_to_B', B.wait_for(lambda: r1.txid() in B.mempool(), 60, 'recovery relay'))
            if 'D' in nodes:
                time.sleep(3)
                net.check('unupgraded_bitcoin_rs_rejects_recovery_by_policy', r1.txid() not in nodes['D'].mempool(),
                          note='DISCOURAGE_OP_SUCCESS keeps 0xf0 spends out of unupgraded mempools')
            # ---------------------------------------------------------------- experiment 1: confirmed recovery reorged out
            for n in nodes.values():
                n.rpc('setnetworkactive', False)
            time.sleep(1)
            ba = envA.mine(1)[0]                                # A confirms the recovery at fund_h+1
            net.check('A_confirms_recovery', r1.txid() in A.rpc('getblock', ba)['tx'])
            # B (an operator-controlled minority/majority) builds a longer chain without the recovery
            B.rpc('generateblock', wallet.address, [])          # fund_h+1 (empty: recovery excluded)
            while B.height() + 1 < fund_h + claims['F1'].delay:
                B.rpc('generateblock', wallet.address, [])
            s1 = setl('F1', fee=5000)
            net.txs['F1_settlement'] = s1.txid()
            B.rpc('generateblock', wallet.address, [s1.hex()])  # settlement at maturity height on B
            B.rpc('generateblock', wallet.address, [])
            net.snap('partitioned_conflict', ['A', 'B'])
            for n in nodes.values():
                n.rpc('setnetworkactive', True)
            for other in nodes:
                if other != 'A':
                    net.connect(other, 'A')
            tips = net.sync(['A', 'B'], 120)
            st = net.snap('after_reorg_1', ['A', 'B'])
            a = st['nodes']['A']
            net.check('reorg1_A_adopts_longer_chain', a['tip'] == st['nodes']['B']['tip'], depth=a['height'] - fund_h)
            net.check('reorg1_recovery_rolled_back', not a['confirmed'].get('F1_recovery'))
            net.check('reorg1_settlement_confirmed', a['confirmed'].get('F1_settlement'))
            net.check('reorg1_recovery_evicted_from_mempool', 'F1_recovery' not in a['mempool'])
            net.check('reorg1_claim_spent_exactly_once', not a['claims']['F1'])
            net.check('reorg1_utxo_sets_equal', a.get('utxo_hash') == st['nodes']['B'].get('utxo_hash'))
            ok, res = A.try_rpc('sendrawtransaction', r1.hex())
            net.check('reorg1_recovery_cannot_reenter', not ok, reason=res)
            # ---------------------------------------------------------------- experiment 2: settlement reorged out by recovery chain
            r2 = rec('F2'); s2 = setl('F2', fee=5000)
            net.txs['F2_recovery'] = r2.txid(); net.txs['F2_settlement'] = s2.txid()
            for n in nodes.values():
                n.rpc('setnetworkactive', False)
            time.sleep(1)
            B.rpc('generateblock', wallet.address, [s2.hex()])  # F2 matured already: operator settles on B
            A.rpc('generateblock', wallet.address, [r2.hex()])  # challenger's recovery on A
            A.rpc('generateblock', wallet.address, [])
            A.rpc('generateblock', wallet.address, [])
            for n in nodes.values():
                n.rpc('setnetworkactive', True)
            for other in nodes:
                if other != 'A':
                    net.connect(other, 'A')
            net.sync(['A', 'B'], 120)
            st = net.snap('after_reorg_2', ['A', 'B'])
            b = st['nodes']['B']
            net.check('reorg2_B_rolls_back_settlement', not b['confirmed'].get('F2_settlement'))
            net.check('reorg2_recovery_confirmed_on_B', b['confirmed'].get('F2_recovery'))
            net.check('reorg2_settlement_not_in_mempool', 'F2_settlement' not in b['mempool'])
            net.check('reorg2_utxo_sets_equal', b.get('utxo_hash') == st['nodes']['A'].get('utxo_hash'))
            # ---------------------------------------------------------------- experiment 3: funding block reorged out (CSV restarts)
            c3 = Claim(sha(b'reorg-csv-restart'), 7, 11, 3, 13, 17, delay=4)
            f3 = envA.funding_tx([(AMOUNT, c3.spk())])
            net.txs['F3fund'] = f3.txid(); net.tracked['C3'] = (f3.txid(), 0)
            A.rpc('sendrawtransaction', f3.hex())
            B.wait_for(lambda: f3.txid() in B.mempool(), 60, 'f3 relay')
            for n in nodes.values():
                n.rpc('setnetworkactive', False)
            time.sleep(1)
            fork_base = A.tip()
            A.rpc('generateblock', wallet.address, [f3.hex()])  # funding at h0+1 on A
            h_fund_a = A.height()
            for _ in range(c3.delay - 1):
                A.rpc('generateblock', wallet.address, [])
            s3 = spend_claim(c3, f3.txid(), 0, AMOUNT, False)
            net.txs['C3_settlement'] = s3.txid()
            okA = A.rpc('testmempoolaccept', [s3.hex()])[0]['allowed']
            net.check('reorg3_settlement_mature_on_A', okA)
            # B builds a longer chain where the funding confirms LATER
            for _ in range(3):
                B.rpc('generateblock', wallet.address, [])
            B.rpc('generateblock', wallet.address, [f3.hex()])
            h_fund_b = B.height()
            B.rpc('generateblock', wallet.address, [])   # B is now longer, but the new funding is immature
            for n in nodes.values():
                n.rpc('setnetworkactive', True)
            for other in nodes:
                if other != 'A':
                    net.connect(other, 'A')
            net.sync(['A', 'B'], 120)
            st = net.snap('after_reorg_3', ['A', 'B'], funding_height_A=h_fund_a, funding_height_B=h_fund_b)
            dry = A.rpc('testmempoolaccept', [s3.hex()])[0]
            net.check('reorg3_csv_restarts_from_new_funding_height', not dry['allowed'], dry=dry,
                      note='the settlement that was mature on the abandoned branch is non-final again')
            env_rec = spend_claim(c3, f3.txid(), 0, AMOUNT, True)
            net.check('reorg3_recovery_still_available', A.rpc('testmempoolaccept', [env_rec.hex()])[0]['allowed'])
            # ---------------------------------------------------------------- experiment 4: restart / crash both nodes
            before = net.snap('before_restart', ['A', 'B'])
            A.stop(); B.crash()
            A.start(); B.start()
            after = net.snap('after_restart', ['A', 'B'])
            for n in ('A', 'B'):
                net.check(f'restart_{n}_preserves_tip', before['nodes'][n]['tip'] == after['nodes'][n]['tip'])
                net.check(f'restart_{n}_preserves_utxo', before['nodes'][n].get('utxo_hash') == after['nodes'][n].get('utxo_hash'))
                net.check(f'restart_{n}_preserves_claims', before['nodes'][n]['claims'] == after['nodes'][n]['claims'])
            net.reconnect([('B', o) for o in nodes if o not in ('A', 'B')])
            # mine through on A after restart and confirm B follows
            envA.mine(2)
            net.sync(['A', 'B'], 120)
            net.check('post_restart_propagation', True)
            # ---------------------------------------------------------------- experiment 5: unupgraded observers (soft fork)
            if 'C' in nodes or 'D' in nodes:
                observers = [n for n in ('C', 'D') if n in nodes]
                net.sync(['A', 'B'] + observers, 180)
                net.check('observers_follow_upgraded_chain', True, observers=observers)
                # an OP_SUCCESS240 output whose arithmetic is FALSE: anyone-can-spend for old rules,
                # invalid under the experimental rules
                leaf = push(b'\x07') + push(b'\x0b') + push(b'\x03') + push(b'\x11') + b'\xf0' + push(b'\x0d') + b'\x87'
                tree = TapTree(NUMS_X, [(leaf, 0xc0)])
                f5 = envA.funding_tx([(AMOUNT, tree.spk()), (AMOUNT, tree.spk())])
                envA.node.rpc('generateblock', wallet.address, [f5.hex()])
                net.sync(['A', 'B'] + observers, 120)
                bad = Tx([TxIn(f5.txid(), 0, b'', 0xffffffff, [leaf, tree.control(0)])], [TxOut(AMOUNT - 3000, wallet.spk)])
                net.txs['false_arith_spend'] = bad.txid()
                miner = observers[0]
                for n in nodes.values():
                    n.rpc('setnetworkactive', False)
                time.sleep(1)
                ok, res = nodes[miner].try_rpc('generateblock', wallet.address, [bad.hex()])
                net.check('unupgraded_miner_builds_block_with_false_arithmetic', ok, result=str(res)[:200])
                split_tip = nodes[miner].tip()
                for n in nodes.values():
                    n.rpc('setnetworkactive', True)
                for other in nodes:
                    if other != 'A':
                        net.connect(other, 'A')
                for o in observers:
                    if o != miner:
                        net.connect(o, miner)
                        net.wait_tip(o, split_tip, 60)
                net.connect('A', miner)
                net.connect('B', miner)
                time.sleep(6)
                st = net.snap('split', list(nodes))
                net.check('upgraded_A_rejects_false_arithmetic_block', st['nodes']['A']['tip'] != split_tip)
                net.check('upgraded_B_rejects_false_arithmetic_block', st['nodes']['B']['tip'] != split_tip)
                for o in observers:
                    if o != miner:
                        net.check(f'unupgraded_{o}_accepts_false_arithmetic_block', st['nodes'][o]['tip'] == split_tip)
                # upgraded majority extends: observers must reorg back onto the upgraded chain
                envA.mine(3)
                net.reconnect([(o, 'B') for o in observers])
                net.sync(['A', 'B'] + observers, 180)
                st = net.snap('split_resolved', list(nodes))
                for o in observers:
                    net.check(f'{o}_reorgs_to_upgraded_chain', st['nodes'][o]['tip'] == st['nodes']['A']['tip'])
                    net.check(f'{o}_false_spend_rolled_back', not st['nodes'][o]['confirmed'].get('false_arith_spend'))
                # a VALID arithmetic spend is accepted by every rule set
                good_leaf = push(b'\x07') + push(b'\x0b') + push(b'\x03') + push(b'\x11') + b'\xf0' + push(b'\x0c') + b'\x87'
                gtree = TapTree(NUMS_X, [(good_leaf, 0xc0)])
                f6 = envA.funding_tx([(AMOUNT, gtree.spk())])
                A.rpc('generateblock', wallet.address, [f6.hex()])
                good = Tx([TxIn(f6.txid(), 0, b'', 0xffffffff, [good_leaf, gtree.control(0)])], [TxOut(AMOUNT - 3000, wallet.spk)])
                net.txs['true_arith_spend'] = good.txid()
                A.rpc('generateblock', wallet.address, [good.hex()])
                net.sync(['A', 'B'] + observers, 180)
                st = net.snap('valid_arith_everywhere', list(nodes))
                for o in ['B'] + observers:
                    net.check(f'{o}_accepts_valid_arithmetic_block', st['nodes'][o]['confirmed'].get('true_arith_spend'))
        finally:
            for n in nodes.values():
                try:
                    n.stop()
                except Exception:
                    pass
            for k, n in nodes.items():
                if n.log_path.exists():
                    (out / f'phase6-node-{k}.log').write_bytes(n.log_path.read_bytes()[-2_000_000:])
            report = {'checks': net.checks, 'passed': sum(c['passed'] for c in net.checks),
                      'failed': [c['name'] for c in net.checks if not c['passed']], 'trace': net.trace,
                      'binaries': {k: str(v.binary) for k, v in nodes.items()},
                      'binary_sha256': {k: sha(v.binary.read_bytes()).hex() for k, v in nodes.items()}}
            write_json(out / 'phase6-reorg.json', report)
            print({'passed': report['passed'], 'failed': report['failed']})


if __name__ == '__main__':
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--exp', type=Path, required=True)
    ap.add_argument('--core', type=Path)
    ap.add_argument('--off', type=Path)
    ap.add_argument('--out', type=Path, required=True)
    a = ap.parse_args()
    run(a.exp, a.core, a.off, a.out)
