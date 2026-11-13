#!/usr/bin/env python3
"""Phase 5: source mutation testing for the MULADDMOD implementation.

Applies one mutant at a time to the WSL build clone, runs the arithmetic and
interpreter test lanes, and records whether the suite kills the mutant.
Restores the original file after each mutant (also on failure).

Usage: mutation.py --repo <bitcoin-rs> --out <dir> [--target-dir <dir>]
"""
from __future__ import annotations

import argparse
import json
import subprocess
import time
from pathlib import Path

MUTANTS = [
    # (id, file, original, replacement, description)
    ('M01', 'crates/script/src/muladdmod.rs', 'pub(crate) const COST: i64 = 50;', 'pub(crate) const COST: i64 = 49;', 'charge 49 units'),
    ('M02', 'crates/script/src/muladdmod.rs', 'pub(crate) const COST: i64 = 50;', 'pub(crate) const COST: i64 = 0;', 'charge nothing'),
    ('M03', 'crates/script/src/muladdmod.rs', '|| (width == 1 && m[0] < 2)', '', 'accept modulus 0/1'),
    ('M04', 'crates/script/src/muladdmod.rs', '|| m.last() == Some(&0)', '', 'accept non-minimal modulus'),
    ('M05', 'crates/script/src/muladdmod.rs', '.any(|x| x.len() != width || compare(x, m) != Ordering::Less)',
     '.any(|x| x.len() != width || compare(x, m) == Ordering::Greater)', 'accept operand equal to modulus'),
    ('M06', 'crates/script/src/muladdmod.rs', '    if compare(&result, modulus) != Ordering::Less {',
     '    if compare(&result, modulus) == Ordering::Greater {', 'skip reduction when sum == m'),
    ('M07', 'crates/script/src/muladdmod.rs', 'for bit in (0..8).rev()', 'for bit in (1..8).rev()', 'drop lowest bit of each byte'),
    ('M08', 'crates/script/src/muladdmod.rs', '    result = add_reduce(&result, &addend, &modulus);\n', '', 'ignore addend c'),
    ('M09', 'crates/script/src/muladdmod.rs', 'const MAX_WIDTH: usize = 32;', 'const MAX_WIDTH: usize = 31;', 'reject 32-byte moduli'),
    ('M10', 'crates/script/src/muladdmod.rs', 'let sum = u16::from(a[i]) + u16::from(b[i]) + carry;',
     'let sum = u16::from(a[i]) + u16::from(b[i]);', 'drop carry propagation'),
    ('M11', 'crates/script/src/eval.rs', 'if sigversion == SigVersion::Tapscript && flags.muladdmod_enabled() =>',
     'if flags.muladdmod_enabled() =>', 'execute in legacy / witness v0'),
    ('M12', 'crates/script/src/eval.rs', 'if is_op_success(op) && !(op == OP_MULADDMOD_EXPERIMENTAL && flags.muladdmod_enabled()) {',
     'if is_op_success(op) {', 'activated opcode still OP_SUCCESS'),
    ('M13', 'crates/script/src/eval.rs', '            if stack.len() < 4 {\n                return Err(invalid_stack());\n            }\n            let left',
     '            if stack.len() < 3 {\n                return Err(invalid_stack());\n            }\n            let left', 'underflow check off by one'),
    ('M14', 'crates/script/src/eval.rs', "                &item_bytes(stack.peek_at(3).map_err(|_| invalid_stack())?),\n                &item_bytes(stack.peek_at(2).map_err(|_| invalid_stack())?),",
     "                &item_bytes(stack.peek_at(2).map_err(|_| invalid_stack())?),\n                &item_bytes(stack.peek_at(3).map_err(|_| invalid_stack())?),", 'swap a and b (equivalent: multiplication commutes)'),
    ('M15', 'crates/script/src/eval.rs', "                &item_bytes(stack.peek_at(2).map_err(|_| invalid_stack())?),\n                &item_bytes(stack.peek_at(1).map_err(|_| invalid_stack())?),",
     "                &item_bytes(stack.peek_at(1).map_err(|_| invalid_stack())?),\n                &item_bytes(stack.peek_at(2).map_err(|_| invalid_stack())?),", 'swap b and c'),
    ('M16', 'crates/script/src/eval.rs',
     '            *left = left\n                .checked_sub(crate::muladdmod::COST)\n                .ok_or(ScriptError::Invalid {\n                    code: ScriptErrCode::TapscriptValidationWeight,\n                })?;\n            if *left < 0 {',
     '            *left = left\n                .checked_sub(crate::muladdmod::COST)\n                .ok_or(ScriptError::Invalid {\n                    code: ScriptErrCode::TapscriptValidationWeight,\n                })?;\n            if *left < -1 {',
     'budget allows one unit of overdraft'),
    ('M17', 'crates/script/src/eval.rs', '            for _ in 0..4 {\n                stack.pop()', '            for _ in 0..3 {\n                stack.pop()', 'leave one operand on the stack'),
    ('M18', 'crates/script/src/interpreter.rs', '    if flags.contains(VerifyFlags::EXPERIMENTAL_MULADDMOD) && !flags.muladdmod_enabled() {\n        return Err(invalid(ScriptErrCode::ExperimentalDisabled));\n    }\n',
     '', 'flag silently ignored in unsupported builds'),
]

LANES = [
    ['cargo', 'test', '--locked', '-p', 'bitcoin-rs-script', '--features', 'experimental-muladdmod'],
    ['cargo', 'test', '--locked', '-p', 'bitcoin-rs-script'],
]


def run_lanes(repo: Path, env: dict, log):
    for lane in LANES:
        t = time.time()
        p = subprocess.run(lane, cwd=repo, env=env, capture_output=True, text=True)
        log.write(f'$ {" ".join(lane)} -> {p.returncode} ({time.time() - t:.0f}s)\n')
        log.write(p.stdout[-6000:] + p.stderr[-6000:] + '\n')
        if p.returncode != 0:
            failed = [l for l in (p.stdout + p.stderr).splitlines() if l.startswith('test ') and 'FAILED' in l]
            compile_error = 'error[' in p.stderr or 'could not compile' in p.stderr
            return False, {'lane': ' '.join(lane[3:]), 'failed_tests': failed[:20], 'compile_error': compile_error}
    return True, {}


def main():
    import os
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--repo', type=Path, required=True)
    ap.add_argument('--out', type=Path, required=True)
    ap.add_argument('--target-dir', type=Path)
    a = ap.parse_args()
    env = dict(os.environ)
    if a.target_dir:
        env['CARGO_TARGET_DIR'] = str(a.target_dir)
    a.out.mkdir(parents=True, exist_ok=True)
    results = []
    with (a.out / 'phase5-mutation.log').open('w') as log:
        log.write('=== baseline\n')
        ok, info = run_lanes(a.repo, env, log)
        if not ok:
            raise SystemExit(f'baseline failed: {info}')
        for mid, rel, orig, repl, desc in MUTANTS:
            path = a.repo / rel
            text = path.read_text()
            count = text.count(orig)
            if count != 1:
                results.append({'id': mid, 'file': rel, 'description': desc, 'status': 'not-applied', 'matches': count})
                print(mid, 'NOT APPLIED', count, flush=True)
                continue
            path.write_text(text.replace(orig, repl))
            try:
                log.write(f'=== {mid} {desc}\n')
                t = time.time()
                survived, info = run_lanes(a.repo, env, log)
                status = 'survived' if survived else ('killed-compile' if info.get('compile_error') else 'killed')
                results.append({'id': mid, 'file': rel, 'description': desc, 'status': status,
                                'seconds': round(time.time() - t), **info})
                print(mid, status, desc, info.get('failed_tests', [])[:3], flush=True)
            finally:
                path.write_text(text)
    killed = sum(r['status'].startswith('killed') for r in results)
    applied = sum(r['status'] != 'not-applied' for r in results)
    summary = {'mutants': len(MUTANTS), 'applied': applied, 'killed': killed,
               'survived': [r['id'] for r in results if r['status'] == 'survived'],
               'score': round(killed / applied, 3) if applied else None}
    (a.out / 'phase5-mutation.json').write_text(json.dumps({'summary': summary, 'results': results}, indent=2) + '\n')
    print(summary)


if __name__ == '__main__':
    main()
