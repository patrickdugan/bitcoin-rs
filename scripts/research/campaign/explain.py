#!/usr/bin/env python3
"""Attach the precise consensus rule to every phase-2 attempt.

The node's mempool path reports a generic `script-verify-flag-failed`; this
replays each claim-spending transaction through the native interpreter
(script_oracle example) under consensus and standard flags and through the
independent Python reference, then classifies the responsible rule.

Usage: explain.py --oracle <script_oracle> --in phase2-attacks.json
"""
from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path

CONSENSUS = 'P2SH,DERSIG,CHECKLOCKTIMEVERIFY,CHECKSEQUENCEVERIFY,WITNESS,NULLDUMMY,TAPROOT,EXPERIMENTAL_MULADDMOD'
STANDARD = CONSENSUS + (',STRICTENC,LOW_S,MINIMALDATA,DISCOURAGE_UPGRADABLE_NOPS,CLEANSTACK,MINIMALIF,NULLFAIL,'
                        'WITNESS_PUBKEYTYPE,CONST_SCRIPTCODE,DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM,'
                        'DISCOURAGE_UPGRADABLE_TAPROOT_VERSION,DISCOURAGE_OP_SUCCESS,DISCOURAGE_UPGRADABLE_PUBKEYTYPE')


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--oracle', type=Path, required=True)
    ap.add_argument('--in', dest='inp', type=Path, required=True)
    a = ap.parse_args()
    report = json.loads(a.inp.read_text())
    p = subprocess.Popen([str(a.oracle)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1)

    def ask(flags, txhex, spent):
        prev = ' '.join(f'{v} {s}' for v, s in spent)
        p.stdin.write(f'{flags} 0 {txhex} {len(spent)} {prev}\n'); p.stdin.flush()
        return p.stdout.readline().strip()

    rules = {}
    agree = disagree = 0
    for r in report['results']:
        if 'claim_tx_hex' not in r:
            continue
        cons = ask(CONSENSUS, r['claim_tx_hex'], r['spent'])
        std = ask(STANDARD, r['claim_tx_hex'], r['spent'])
        r['native_consensus'] = cons
        r['native_standard'] = std
        ref = r.get('reference_interpreter')
        ref_ok = ref == 'OK'
        if ref_ok == (cons == 'OK'):
            agree += 1
        else:
            disagree += 1
            r['reference_vs_native_disagreement'] = True
        if r['accepted']:
            rule = 'accepted'
        elif cons != 'OK':
            rule = 'SCRIPT_ERR_' + cons.replace('ERR ', '')
        elif std != 'OK':
            rule = 'policy SCRIPT_ERR_' + std.replace('ERR ', '')
        else:
            msg = r.get('reason')
            msg = msg.get('message') if isinstance(msg, dict) else msg
            rule = f'non-script: {msg}'
        r['responsible_rule'] = rule
        rules[rule] = rules.get(rule, 0) + 1
    p.stdin.close(); p.wait()
    report['rule_histogram'] = dict(sorted(rules.items(), key=lambda kv: -kv[1]))
    report['reference_vs_native'] = {'agree': agree, 'disagree': disagree}
    a.inp.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report['rule_histogram'], indent=2))
    print(report['reference_vs_native'])


if __name__ == '__main__':
    main()
