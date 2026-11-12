#!/usr/bin/env python3
"""Run bounded Keyless CHECKSIG staging checks and preserve their evidence."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import signal
import subprocess
import sys
import time


class EvidenceError(RuntimeError):
    pass


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(chunk)
    return value.hexdigest()


def require(condition: bool, message: str):
    if not condition:
        raise EvidenceError(message)


def validate_tests(text: str, kind: str) -> dict:
    text = re.sub(r'\x1b\[[0-9;]*m', '', text)
    if kind == 'python':
        rows = re.findall(r'^Ran (\d+) tests? in ', text, re.MULTILINE)
        require(len(rows) == 1 and int(rows[0]) > 0,
                'Python suite must report a positive executed-test count')
        require(text.rstrip().splitlines()[-1] == 'OK',
                'Python suite must finish successfully without skipped tests')
        return {'passed': int(rows[0]), 'failed': 0, 'ignored': 0}
    require(kind == 'rust', 'unknown test evidence format')
    rows = re.findall(r'test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored;', text)
    require(bool(rows), 'Rust suite has no completed test summary')
    require(all(row[0] == 'ok' and int(row[2]) == 0 and int(row[3]) == 0 for row in rows),
            'Rust suite contains failed or ignored tests')
    passed = sum(int(row[1]) for row in rows)
    require(passed > 0 and re.search(r'^error(?:\[[^\]]+\])?:', text, re.MULTILINE) is None,
            'Rust suite must execute tests and compile successfully')
    return {'passed': passed, 'failed': 0, 'ignored': 0}


def validate_fixture(name: str, report: dict, binary_sha256: str) -> dict:
    require(name == 'keyless-regtest', 'unknown fixture')
    require(isinstance(report, dict) and report.get('status') == 'passed',
            'fixture did not complete successfully')
    require(report.get('binary_sha256') == binary_sha256, 'fixture used a different executable')
    require(report.get('network') == 'regtest', 'fixture did not observe regtest')
    require(type(report.get('peer_count')) is int and report['peer_count'] == 0,
            'fixture must observe zero connected peers')
    require(report.get('restart_preserved_outputs') is True, 'restart evidence is missing')
    require(report.get('both_alternatives_eligible') is True, 'recipient alternatives were not tested')
    for field, value in (('funding_height', 102), ('payout_height', 103),
                         ('funding_sats', 100_000), ('payout_sats', 98_000), ('fee_sats', 2_000)):
        require(report.get(field) == value, f'{field} differs')
    require(bool(re.fullmatch(r'[0-9a-f]{64}', report.get('funding_txid', ''))),
            'funding transaction identity is missing')
    payouts = report.get('payouts')
    require(isinstance(payouts, list) and len(payouts) == 2, 'both payouts must be confirmed')
    for index, payout in enumerate(payouts):
        require(isinstance(payout, dict) and payout.get('funding_vout') == index
                and payout.get('recipient_index') == index and payout.get('amount_sats') == 98_000,
                'payout context differs')
        require(bool(re.fullmatch(r'[0-9a-f]{64}', payout.get('txid', '')))
                and bool(re.fullmatch(r'[0-9a-f]{64}', payout.get('block', ''))),
                'payout transaction or block identity is missing')
        require(bool(re.fullmatch(r'5120[0-9a-f]{64}', payout.get('script_pubkey', ''))),
                'recipient output must be P2TR')
    require(payouts[0]['txid'] != payouts[1]['txid'], 'payouts must spend distinct reserves')
    expected_cases = {
        'unauthorized_recipient', 'unauthorized_membership', 'allowed_recipient_without_new_opening',
        'payout_minus_one_fee_increase', 'payout_plus_one_fee_decrease', 'extra_output',
        'other_funded_outpoint_stale_commitment', 'wrong_prevout_amount', 'wrong_prevout_script',
        'added_input_stale_commitment', 'sequence_stale_commitment', 'version_stale_commitment',
        'locktime_stale_commitment', 'wrong_membership_sibling', 'wrong_membership_direction',
        'nonminimal_membership_direction', 'short_transcript_prefix', 'long_transcript_prefix',
        'short_transcript_suffix', 'long_transcript_suffix', 'wrong_key_version', 'wrong_codesep',
        'oversized_witness_element', 'changed_tapleaf', 'changed_control_parity',
        'changed_control_internal_key', 'annex_with_stale_commitment',
        'annex_excluded_by_policy_width', 'already_spent_input',
    }
    rejected = report.get('rejected')
    require(isinstance(rejected, dict) and set(rejected) == expected_cases
            and report.get('rejection_count') == 29, 'rejection cases are missing or unexpected')
    require(report.get('invalid_block_preserved_height') is True, 'invalid block changed the chain')
    require(report.get('script_signatures') == 0, 'fixture must use no script signatures')
    policy_cases = {'oversized_witness_element', 'annex_with_stale_commitment',
                    'annex_excluded_by_policy_width'}
    require(report.get('policy_rejection_cases') == sorted(policy_cases),
            'policy rejection classification differs')
    consensus = report.get('consensus_rejections')
    require(isinstance(consensus, dict) and set(consensus) == policy_cases,
            'policy rejection needs independent block evidence')
    for item in consensus.values():
        require(isinstance(item, dict) and item.get('height_before') == 102
                and item.get('height_after') == 102, 'invalid block changed height')
        failure = item.get('error')
        require(isinstance(failure, dict) and failure.get('code') == -25
                and 'block-script-verify-flag-failed' in str(failure.get('message', '')),
                'missing block Script failure for policy-rejected witness')
    for name, case in rejected.items():
        if name == 'already_spent_input':
            reason, code = 'missing-inputs', -25
        elif name in policy_cases:
            reason, code = 'bad-witness-nonstandard', -26
        else:
            reason, code = 'script-verify-flag-failed', -26
        require(isinstance(case, dict) and isinstance(case.get('dry_run'), dict)
                and case['dry_run'].get('allowed') is False
                and case['dry_run'].get('reject-reason') == reason,
                'expected Script dry-run rejection is missing')
        require(isinstance(case.get('admission'), dict) and case['admission'].get('code') == code,
                'expected Script broadcast rejection is missing')
    block = report.get('invalid_block_attempt')
    require(isinstance(block, dict) and block.get('code') == -25
            and 'block-script-verify-flag-failed' in str(block.get('message', '')),
            'invalid-block Script rejection is missing')
    return {'rejection_count': len(rejected), 'confirmed_payouts': 2,
            'restart_preserved_outputs': True, 'network': 'regtest', 'peer_count': 0}


def stop_group(process: subprocess.Popen):
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        pass
    finally:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=3)


def run_command(command: list[str], cwd: Path, log: Path, timeout: float, env: dict) -> dict:
    started = time.monotonic()
    result = {'status': 'failed', 'exit_code': None}
    process = None
    with log.open('x', encoding='utf-8') as stream:
        try:
            process = subprocess.Popen(command, cwd=cwd, env=env, stdout=stream,
                                       stderr=subprocess.STDOUT, start_new_session=True)
            result['exit_code'] = process.wait(timeout=timeout)
            result['status'] = 'passed' if result['exit_code'] == 0 else 'failed'
        except subprocess.TimeoutExpired:
            result.update(status='timed_out', error=f'command exceeded {timeout:g} seconds')
        except KeyboardInterrupt:
            result.update(status='interrupted', error='staging interrupted')
        except OSError as error:
            result['error'] = str(error)
        finally:
            if process is not None:
                stop_group(process)
                result['exit_code'] = process.returncode
    result['duration_seconds'] = round(time.monotonic() - started, 3)
    result['log_sha256'] = digest(log)
    return result


def git(repo: Path, *args: str) -> bytes:
    result = subprocess.run(['git', *args], cwd=repo, capture_output=True, timeout=30, check=True)
    return result.stdout


def source_state(repo: Path) -> dict:
    changed = git(repo, 'status', '--porcelain=v1', '-z', '--untracked-files=all')
    untracked = git(repo, 'ls-files', '--others', '--exclude-standard', '-z').split(b'\0')
    files = []
    for raw in untracked:
        if raw:
            path = os.fsdecode(raw)
            item = repo / path
            value = hashlib.sha256(os.readlink(item).encode()).hexdigest() if item.is_symlink() else digest(item)
            files.append({'path': path, 'sha256': value})
    return {'revision': git(repo, 'rev-parse', 'HEAD').decode().strip(),
            'dirty': bool(changed), 'status_sha256': hashlib.sha256(changed).hexdigest(),
            'diff_sha256': hashlib.sha256(git(repo, 'diff', '--binary', 'HEAD')).hexdigest(),
            'untracked_files': files}


def write_report(path: Path, report: dict):
    temporary = path.with_suffix('.tmp')
    temporary.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    temporary.replace(path)


def plan(profile: str, output: Path, binary: Path, jobs: int, prebuilt: bool) -> list[dict]:
    steps = []

    def add(name, command, kind='command'):
        steps.append({'name': name, 'command': command, 'kind': kind, 'status': 'pending',
                      'log': f'{name}.log'})

    if profile in ('offline', 'full'):
        add('offline', [sys.executable, '-m', 'unittest', 'discover', '-s', 'scripts/tests',
                        '-p', 'test_keyless*.py', '-v'], 'python')
    if profile in ('semantics', 'full') or (profile == 'regtest' and not prebuilt):
        add('rustc-version', ['rustc', '--version'])
        add('cargo-version', ['cargo', '--version'])
    if profile in ('semantics', 'full'):
        experiments = 'experimental-keyless-checksig-regtest,experimental-op-cat-regtest'
        suites = [
            ('sighash', ['-p', 'bitcoin-rs-primitives', 'sighash']),
            ('flag-off', ['-p', 'bitcoin-rs-script']),
            ('txcommit-only', ['-p', 'bitcoin-rs-script', '--features', 'experimental-keyless-checksig']),
            ('cat-only', ['-p', 'bitcoin-rs-script', '--features', 'experimental-op-cat']),
            ('script', ['-p', 'bitcoin-rs-script', '--features', 'experimental-keyless-checksig,experimental-op-cat']),
            ('consensus-flag-off', ['-p', 'bitcoin-rs-consensus', '--no-default-features', 'keyless_and_cat']),
            ('consensus', ['-p', 'bitcoin-rs-consensus', '--features', experiments]),
            ('mempool', ['-p', 'bitcoin-rs-mempool', '--features', experiments, 'keyless']),
            ('node', ['-p', 'bitcoin-rs-node', '--no-default-features', '--features',
                      'fjall,' + experiments, 'keyless']),
            ('sync', ['-p', 'bitcoin-rs-chainstate', '--no-default-features', '--features',
                      'fjall,bitcoin-rs-consensus/experimental-keyless-checksig-regtest,bitcoin-rs-consensus/experimental-op-cat-regtest',
                      'a_window_with_an_invalid_middle_block_commits_only_the_valid_prefix']),
            ('sync-dispositions', ['-p', 'bitcoin-rs-chainstate', '--no-default-features', '--features',
                      'fjall,bitcoin-rs-consensus/experimental-keyless-checksig-regtest,bitcoin-rs-consensus/experimental-op-cat-regtest',
                      'apply_errors_classify_into_their_documented_dispositions']),
            ('sync-publication', ['-p', 'bitcoin-rs-node', '--no-default-features', '--features',
                      'fjall,' + experiments, '--test', 'suite',
                      'tick_recovers_rejected_frontier_without_publishing_unapplied_blocks']),
        ]
        for name, args in suites:
            add(name, ['cargo', 'test', '--locked', '--jobs', str(jobs), *args], 'rust')
    if profile in ('regtest', 'full'):
        if not prebuilt:
            add('build', ['cargo', 'build', '--locked', '--jobs', str(jobs), '--profile', 'quickstart',
                          '--target-dir', str(binary.parents[1]), '-p', 'bitcoin-rs',
                          '--no-default-features', '--features',
                          'fjall,experimental-keyless-checksig-regtest,experimental-op-cat-regtest'])
        add('binary-version', [str(binary), '--version'])
        add('keyless-regtest', [sys.executable, 'scripts/research/keyless_checksig_rpc.py', str(binary),
                               '--report', str(output / 'keyless-regtest.json')], 'fixture')
    return steps


def positive(value: str) -> int:
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError('must be positive')
    return number


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile', choices=('offline', 'semantics', 'regtest', 'full'), default='full')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--binary', type=Path)
    parser.add_argument('--binary-sha256')
    parser.add_argument('--binary-source')
    parser.add_argument('--timeout', type=positive, default=600, help='seconds per Python or RPC command')
    parser.add_argument('--build-timeout', type=positive, default=1800, help='seconds per Cargo command')
    parser.add_argument('--jobs', type=positive, default=2)
    parser.add_argument('--allow-dirty', action='store_true')
    args = parser.parse_args(argv)
    def interrupted(signum, frame):
        raise KeyboardInterrupt(f'interrupted by signal {signum}')

    prior_handler = signal.signal(signal.SIGTERM, interrupted)
    repo = Path(__file__).resolve().parents[2]
    output = args.output.resolve()
    try:
        output.mkdir(parents=True, exist_ok=False)
    except OSError as error:
        print(f'cannot create a fresh output directory: {error}', file=sys.stderr)
        signal.signal(signal.SIGTERM, prior_handler)
        return 2
    report = {'schema_version': 1, 'status': 'running', 'profile': args.profile,
              'started_at': datetime.now(timezone.utc).isoformat(), 'steps': [],
              'host': {'platform': platform.platform(), 'python': platform.python_version()},
              'scope': 'experimental native regtest staging; evidence applies to the selected profile'}
    path = output / 'report.json'
    write_report(path, report)
    try:
        require(__debug__, 'run staging with Python assertions enabled')
        require(os.name == 'posix', 'staging process cleanup requires Linux, WSL2, or another POSIX host')
        if output.is_relative_to(repo):
            ignored = subprocess.run(['git', 'check-ignore', '-q', str(output)], cwd=repo, timeout=30)
            require(ignored.returncode == 0, 'output within the checkout must be ignored by Git; use target/')
        report['source'] = source_state(repo)
        require(args.allow_dirty or not report['source']['dirty'],
                'checkout has uncommitted changes; commit them or pass --allow-dirty to record them')
        if args.binary:
            require(args.profile in ('regtest', 'full'), 'prebuilt binaries require a regtest or full profile')
            require(bool(re.fullmatch(r'[0-9a-fA-F]{64}', args.binary_sha256 or '')),
                    '--binary requires a 64-digit --binary-sha256')
            require(bool(re.fullmatch(r'[0-9a-fA-F]{40}', args.binary_source or '')),
                    '--binary requires a full 40-digit --binary-source revision')
            binary = args.binary.resolve(strict=True)
            binary_hash = digest(binary)
            require(binary_hash == args.binary_sha256.lower(), 'prebuilt binary SHA256 mismatch')
            report['binary'] = {'path': str(binary), 'sha256': binary_hash,
                                'source_revision': args.binary_source.lower(), 'provenance': 'prebuilt-declared'}
        else:
            require(args.binary_sha256 is None and args.binary_source is None,
                    '--binary-sha256 and --binary-source require --binary')
            binary = repo / 'target' / 'quickstart' / 'bitcoin-rs'
        report['steps'] = plan(args.profile, output, binary, args.jobs, args.binary is not None)
        env = dict(os.environ, RUST_TEST_THREADS=str(args.jobs), CARGO_TERM_COLOR='never')
        for step in report['steps']:
            require(source_state(repo) == report['source'], 'source changed during staging')
            if step['kind'] == 'fixture' or step['name'] == 'binary-version':
                require(digest(binary) == report['binary']['sha256'], 'binary changed during staging')
            step['status'] = 'running'
            write_report(path, report)
            print(f"[{step['name']}] running", flush=True)
            timeout = args.build_timeout if step['command'][0] == 'cargo' else args.timeout
            step['timeout_seconds'] = timeout
            step.update(run_command(step['command'], repo, output / step['log'], timeout, env))
            require(step['status'] == 'passed', f"{step['name']}: {step.get('error', 'command failed')}")
            try:
                if step['kind'] in ('python', 'rust'):
                    step['evidence'] = validate_tests((output / step['log']).read_text(), step['kind'])
                elif step['kind'] == 'fixture':
                    receipt = output / f"{step['name']}.json"
                    step['evidence'] = validate_fixture(step['name'], json.loads(receipt.read_text()),
                                                       report['binary']['sha256'])
                    step['receipt'] = receipt.name
                    step['receipt_sha256'] = digest(receipt)
                elif step['name'] == 'build':
                    report['binary'] = {'path': str(binary), 'sha256': digest(binary),
                                        'source_revision': report['source']['revision'],
                                        'source_dirty': report['source']['dirty'], 'provenance': 'locally-built'}
                elif step['name'] in ('rustc-version', 'cargo-version', 'binary-version'):
                    report.setdefault('versions', {})[step['name']] = (output / step['log']).read_text().strip()
            except (EvidenceError, OSError, ValueError, TypeError) as error:
                step.update(status='failed', error=str(error))
                raise EvidenceError(f"{step['name']}: {error}") from error
            print(f"[{step['name']}] passed", flush=True)
            write_report(path, report)
        require(source_state(repo) == report['source'], 'source changed during staging')
        if 'binary' in report:
            require(digest(binary) == report['binary']['sha256'], 'binary changed during staging')
        report['status'] = 'passed'
    except (EvidenceError, OSError, ValueError, subprocess.SubprocessError, KeyboardInterrupt) as error:
        report.update(status='failed', error=str(error) or 'staging interrupted')
    finally:
        for step in report['steps']:
            if step['status'] == 'pending':
                step.update(status='skipped', reason='earlier stage failed')
            elif step['status'] == 'running':
                step.update(status='failed', error=report.get('error', 'staging interrupted'))
        report['finished_at'] = datetime.now(timezone.utc).isoformat()
        write_report(path, report)
        signal.signal(signal.SIGTERM, prior_handler)
    print(f"{report['status']}: {path}", flush=True)
    return 0 if report['status'] == 'passed' else 1


if __name__ == '__main__':
    sys.exit(main())
