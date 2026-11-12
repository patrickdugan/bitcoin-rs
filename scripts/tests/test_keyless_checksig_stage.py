import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest

RESEARCH = Path(__file__).resolve().parents[1] / 'research'
sys.path.insert(0, str(RESEARCH))
import keyless_checksig_stage as stage


PIN = 'a7' * 32
SOURCE = 'b9' * 20






def live_process(pid):
    try:
        state = Path(f'/proc/{pid}/stat').read_text().split(') ', 1)[1].split()[0]
    except FileNotFoundError:
        return False
    return state not in ('Z', 'X')


def stopped_after_signal(pid):
    deadline = time.monotonic() + 1
    while live_process(pid) and time.monotonic() < deadline:
        time.sleep(0.01)
    return not live_process(pid)


class TestEvidenceTests(unittest.TestCase):
    def test_accepts_completed_python_singular_and_plural_runs(self):
        for count, noun in ((1, 'test'), (9, 'tests')):
            with self.subTest(count=count):
                text = f'Ran {count} {noun} in 0.017s\n\nOK\n'
                self.assertEqual(stage.validate_tests(text, 'python')['passed'], count)

    def test_counts_rust_tests_across_binaries_and_empty_doctests(self):
        text = (
            'test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 7 filtered out; finished in 0.01s\n'
            'test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n'
            'test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n'
        )
        self.assertEqual(stage.validate_tests(text, 'rust')['passed'], 5)

    def test_python_requires_an_executed_successful_suite(self):
        cases = [
            '', 'OK\n', 'Ran 0 tests in 0.000s\n\nOK\n',
            'Ran 2 tests in 0.017s\n',
            'Ran 2 tests in 0.017s\n\nFAILED (failures=1)\n',
            'Ran 2 tests in 0.017s\n\nOK (skipped=1)\n',
            'Ran 2 tests in 0.017s\n\nOK (expected failures=1)\n',
            'Ran 2 tests in 0.017s\n\nOK (unexpected successes=1)\n',
            'Ran 1 test in 0.01s\n\nFAILED (errors=1)\nRan 1 test in 0.01s\n\nOK\n',
        ]
        for text in cases:
            with self.subTest(text=text), self.assertRaises(stage.EvidenceError):
                stage.validate_tests(text, 'python')

    def test_rust_success_line_cannot_hide_failures_or_compiler_errors(self):
        success = 'test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.1s\n'
        cases = [
            '', 'running 4 tests\n',
            'test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 9 filtered out; finished in 0.0s\n',
            'test result: ok. 4 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.1s\n',
            'test result: FAILED. 1 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.1s\n' + success,
            success + 'error: could not compile `other-crate` (lib) due to 1 previous error\n',
            success + 'error: test failed, to rerun pass `-p example --lib`\n',
        ]
        for text in cases:
            with self.subTest(text=text), self.assertRaises(stage.EvidenceError):
                stage.validate_tests(text, 'rust')

    def test_unknown_evidence_format_fails_closed(self):
        with self.assertRaises(stage.EvidenceError):
            stage.validate_tests('all passed', 'unknown')




class CommandLifecycleTests(unittest.TestCase):
    def test_exit_status_controls_success_and_output_is_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for code in (0, 23):
                with self.subTest(code=code):
                    log = root / f'command-{code}.log'
                    result = stage.run_command(
                        [sys.executable, '-c',
                         f'import sys; print("success-looking stdout"); '
                         f'print("stderr evidence", file=sys.stderr); sys.exit({code})'],
                        root, log, 5, os.environ.copy())
                    self.assertEqual(result['exit_code'], code)
                    self.assertEqual(result['status'], 'passed' if code == 0 else 'failed')
                    self.assertGreaterEqual(result['duration_seconds'], 0)
                    self.assertIn('success-looking stdout', log.read_text())
                    self.assertIn('stderr evidence', log.read_text())

    def test_command_arguments_are_passed_without_shell_interpretation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            payload = '$(touch should-not-exist); * `touch another-file`'
            log = root / 'literal.log'
            result = stage.run_command(
                [sys.executable, '-c', 'import sys; print(sys.argv[1])', payload],
                root, log, 5, os.environ.copy())
            self.assertEqual(result['status'], 'passed')
            self.assertIn(payload, log.read_text())
            self.assertFalse((root / 'should-not-exist').exists())
            self.assertFalse((root / 'another-file').exists())

    @unittest.skipUnless(sys.platform.startswith('linux'), 'Linux process group lifecycle')
    def test_timeout_terminates_a_descendant_that_ignores_sigterm(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pid_file = root / 'descendant.pid'
            child_code = (
                'import os,signal,sys,time\n'
                'from pathlib import Path\n'
                'signal.signal(signal.SIGTERM, signal.SIG_IGN)\n'
                'Path(sys.argv[1]).write_text(str(os.getpid()))\n'
                'time.sleep(60)\n'
            )
            parent_code = (
                'import subprocess,sys,time\n'
                'subprocess.Popen([sys.executable,"-c",sys.argv[1],sys.argv[2]])\n'
                'time.sleep(60)\n'
            )
            pid = None
            try:
                result = stage.run_command(
                    [sys.executable, '-c', parent_code, child_code, str(pid_file)],
                    root, root / 'timeout.log', 1, os.environ.copy())
                self.assertEqual(result['status'], 'timed_out')
                self.assertTrue(pid_file.exists(), 'descendant must start before timeout')
                pid = int(pid_file.read_text())
                self.assertTrue(stopped_after_signal(pid), 'timed-out command left a descendant running')
            finally:
                if pid is None and pid_file.exists():
                    pid = int(pid_file.read_text())
                if pid is not None and live_process(pid):
                    os.kill(pid, signal.SIGKILL)

    @unittest.skipUnless(sys.platform.startswith('linux'), 'Linux interrupt lifecycle')
    def test_interrupt_records_failure_and_reaps_the_child(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pid_file = root / 'child.pid'
            result_file = root / 'interrupted.json'
            child_code = (
                'import os,sys,time\n'
                'from pathlib import Path\n'
                'Path(sys.argv[1]).write_text(str(os.getpid()))\n'
                'time.sleep(60)\n'
            )
            wrapper = (
                'import json,os,signal,sys,threading\n'
                'from pathlib import Path\n'
                'sys.path.insert(0,sys.argv[1])\n'
                'import keyless_checksig_stage\n'
                'root=Path(sys.argv[2])\n'
                'timer=threading.Timer(1,lambda: os.kill(os.getpid(),signal.SIGINT))\n'
                'timer.start()\n'
                'result=keyless_checksig_stage.run_command('
                '[sys.executable,"-c",sys.argv[3],str(root/"child.pid")],'
                'root,root/"interrupt.log",20,os.environ.copy())\n'
                'timer.join()\n'
                '(root/"interrupted.json").write_text(json.dumps(result))\n'
            )
            pid = None
            try:
                completed = subprocess.run(
                    [sys.executable, '-c', wrapper, str(RESEARCH), str(root), child_code],
                    capture_output=True, text=True, timeout=10, check=False)
                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertEqual(json.loads(result_file.read_text())['status'], 'interrupted')
                pid = int(pid_file.read_text())
                self.assertTrue(stopped_after_signal(pid), 'interrupted command left a child running')
            finally:
                if pid is None and pid_file.exists():
                    pid = int(pid_file.read_text())
                if pid is not None and live_process(pid):
                    os.kill(pid, signal.SIGKILL)


class CliPreflightTests(unittest.TestCase):
    def invoke(self, arguments, optimized=False):
        command = [sys.executable]
        if optimized:
            command.append('-O')
        return subprocess.run(
            command + [str(RESEARCH / 'keyless_checksig_stage.py')] + arguments,
            capture_output=True, text=True, timeout=10, check=False)

    def test_optimized_python_is_refused_before_running_any_stage(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'run'
            completed = self.invoke(
                ['--profile', 'regtest', '--output', str(output)],
                optimized=True)
            self.assertNotEqual(completed.returncode, 0)
            report = json.loads((output / 'report.json').read_text())
            self.assertEqual(report['status'], 'failed')
            self.assertEqual(report['steps'], [])

    def test_existing_output_is_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = root / 'report.json'
            report.write_text('{"prior_evidence": true}\n')
            completed = self.invoke(['--profile', 'regtest', '--output', str(root)])
            self.assertNotEqual(completed.returncode, 0)
            self.assertEqual(report.read_text(), '{"prior_evidence": true}\n')

    def test_external_binary_requires_both_identity_pins(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for index, pins in enumerate(([], ['--binary-sha256', PIN], ['--binary-source', SOURCE])):
                with self.subTest(pins=pins):
                    completed = self.invoke([
                        '--profile', 'regtest', '--output', str(root / f'run-{index}'),
                        '--binary', sys.executable, '--allow-dirty',
                    ] + pins)
                    self.assertNotEqual(completed.returncode, 0)
                    report = json.loads((root / f'run-{index}' / 'report.json').read_text())
                    self.assertEqual(report['status'], 'failed')
                    self.assertEqual(report['steps'], [])
                    self.assertIn('--binary requires', report['error'])

    def test_wrong_binary_digest_is_recorded_before_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / 'unapproved-node'
            marker = root / 'binary-executed'
            binary.write_text(
                f'#!{sys.executable}\nfrom pathlib import Path\n'
                f'Path({str(marker)!r}).write_text("executed")\n')
            binary.chmod(0o755)
            self.assertNotEqual(hashlib.sha256(binary.read_bytes()).hexdigest(), PIN)
            completed = self.invoke([
                '--profile', 'regtest', '--output', str(root / 'run'),
                '--binary', str(binary), '--binary-sha256', PIN,
                '--binary-source', SOURCE, '--allow-dirty',
            ])
            self.assertNotEqual(completed.returncode, 0)
            self.assertFalse(marker.exists())
            report = json.loads((root / 'run' / 'report.json').read_text())
            self.assertEqual(report['status'], 'failed')
            self.assertEqual(report['steps'], [])
            self.assertIn('SHA256 mismatch', report['error'])

    def test_dirty_checkout_is_rejected_by_default(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = root / 'repository'
            runner = repository / 'scripts' / 'research' / 'keyless_checksig_stage.py'
            runner.parent.mkdir(parents=True)
            runner.write_bytes((RESEARCH / 'keyless_checksig_stage.py').read_bytes())
            commands = [
                ['git', 'init', '--quiet'],
                ['git', 'add', '.'],
                ['git', '-c', 'user.name=Staging test', '-c', 'user.email=staging@example.invalid',
                 'commit', '--quiet', '-m', 'Fixture'],
            ]
            for command in commands:
                subprocess.run(command, cwd=repository, capture_output=True, timeout=10, check=True)
            (repository / 'uncommitted.txt').write_text('changed source\n')
            output = root / 'output'
            completed = subprocess.run(
                [sys.executable, str(runner), '--profile', 'regtest', '--output', str(output)],
                capture_output=True, text=True, timeout=10, check=False)
            self.assertNotEqual(completed.returncode, 0)
            report = json.loads((output / 'report.json').read_text())
            self.assertEqual(report['status'], 'failed')
            self.assertIs(report['source']['dirty'], True)
            self.assertEqual(report['steps'], [])
            self.assertIn('uncommitted changes', report['error'])


def funded_receipt():
    names = """
    unauthorized_recipient unauthorized_membership allowed_recipient_without_new_opening
    payout_minus_one_fee_increase payout_plus_one_fee_decrease extra_output
    other_funded_outpoint_stale_commitment wrong_prevout_amount wrong_prevout_script
    added_input_stale_commitment sequence_stale_commitment version_stale_commitment
    locktime_stale_commitment wrong_membership_sibling wrong_membership_direction
    nonminimal_membership_direction short_transcript_prefix long_transcript_prefix
    short_transcript_suffix long_transcript_suffix wrong_key_version wrong_codesep
    oversized_witness_element changed_tapleaf changed_control_parity
    changed_control_internal_key annex_with_stale_commitment
    annex_excluded_by_policy_width already_spent_input
    """.split()
    policy = ['annex_excluded_by_policy_width', 'annex_with_stale_commitment', 'oversized_witness_element']
    rejected = {}
    for name in names:
        reason, code = 'script-verify-flag-failed', -26
        if name in policy:
            reason = 'bad-witness-nonstandard'
        if name == 'already_spent_input':
            reason, code = 'missing-inputs', -25
        rejected[name] = {'dry_run': {'allowed': False, 'reject-reason': reason},
                          'admission': {'code': code}}
    failure = {'code': -25, 'message': 'TestBlockValidity failed: block-script-verify-flag-failed'}
    return {
        'status': 'passed', 'binary_sha256': PIN, 'network': 'regtest', 'peer_count': 0,
        'restart_preserved_outputs': True, 'both_alternatives_eligible': True,
        'funding_height': 102, 'payout_height': 103, 'funding_sats': 100000,
        'payout_sats': 98000, 'fee_sats': 2000, 'funding_txid': '01' * 32,
        'payouts': [{'funding_vout': i, 'recipient_index': i, 'amount_sats': 98000,
                    'txid': ('02' if i == 0 else '03') * 32, 'block': '04' * 32,
                    'script_pubkey': '5120' + ('05' if i == 0 else '06') * 32}
                   for i in range(2)],
        'rejected': rejected, 'rejection_count': 29, 'script_signatures': 0,
        'invalid_block_preserved_height': True, 'invalid_block_attempt': failure,
        'policy_rejection_cases': policy,
        'consensus_rejections': {name: {'error': failure, 'height_before': 102, 'height_after': 102}
                                for name in policy},
    }


class ReceiptEvidenceTests(unittest.TestCase):
    def test_complete_funded_receipt_passes(self):
        result = stage.validate_fixture('keyless-regtest', funded_receipt(), PIN)
        self.assertEqual(result['confirmed_payouts'], 2)
        self.assertEqual(result['rejection_count'], 29)

    def test_identity_network_and_value_claims_require_evidence(self):
        for key, value in (('binary_sha256', 'ff' * 32), ('network', 'mainnet'), ('peer_count', 1),
                           ('funding_txid', ''), ('funding_height', 101), ('payout_height', 102),
                           ('payout_sats', 97999), ('fee_sats', 2001),
                           ('restart_preserved_outputs', False), ('both_alternatives_eligible', False)):
            receipt = funded_receipt()
            receipt[key] = value
            with self.subTest(key=key), self.assertRaises(stage.EvidenceError):
                stage.validate_fixture('keyless-regtest', receipt, PIN)

    def test_policy_rejection_alone_cannot_establish_consensus_rejection(self):
        for error in ({'code': -32601, 'message': 'Method not found'},
                      {'code': -25, 'message': 'unrelated RPC failure'}):
            receipt = funded_receipt()
            receipt['consensus_rejections']['oversized_witness_element']['error'] = error
            with self.subTest(error=error), self.assertRaises(stage.EvidenceError):
                stage.validate_fixture('keyless-regtest', receipt, PIN)
        receipt = funded_receipt()
        del receipt['consensus_rejections']['annex_with_stale_commitment']
        with self.assertRaises(stage.EvidenceError):
            stage.validate_fixture('keyless-regtest', receipt, PIN)

    def test_each_attack_requires_the_expected_rejection_boundary(self):
        for name in ('unauthorized_recipient', 'already_spent_input', 'annex_with_stale_commitment'):
            receipt = funded_receipt()
            receipt['rejected'][name]['admission']['code'] = -32601
            with self.subTest(name=name), self.assertRaises(stage.EvidenceError):
                stage.validate_fixture('keyless-regtest', receipt, PIN)
        receipt = funded_receipt()
        del receipt['rejected']['wrong_prevout_script']
        with self.assertRaises(stage.EvidenceError):
            stage.validate_fixture('keyless-regtest', receipt, PIN)

    def test_invalid_block_must_preserve_height_and_reach_script(self):
        receipt = funded_receipt()
        receipt['consensus_rejections']['annex_with_stale_commitment']['height_after'] = 103
        with self.assertRaises(stage.EvidenceError):
            stage.validate_fixture('keyless-regtest', receipt, PIN)
        receipt = funded_receipt()
        receipt['invalid_block_attempt'] = {'code': -32601, 'message': 'Method not found'}
        with self.assertRaises(stage.EvidenceError):
            stage.validate_fixture('keyless-regtest', receipt, PIN)

    def test_success_word_requires_a_completed_funded_receipt(self):
        with self.assertRaises(stage.EvidenceError):
            stage.validate_fixture('keyless-regtest', {'status': 'passed'}, PIN)


if __name__ == '__main__':
    unittest.main()
