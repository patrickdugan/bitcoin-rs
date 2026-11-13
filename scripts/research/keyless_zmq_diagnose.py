"""Collect a bounded native crash trace without changing the failing CI gate."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    report = {'kind': 'diagnostic_not_a_validation_gate', 'validation_pass': False,
              'status': 'collecting', 'started_at': datetime.now(timezone.utc).isoformat(),
              'platform': platform.platform(), 'attempts': []}

    def save():
        (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')

    def command(name, argv, timeout):
        log = output / (name + '.log')
        process = subprocess.Popen(argv, cwd=root, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, start_new_session=True)
        try:
            data, _ = process.communicate(timeout=timeout)
            status = {'exit_code': process.returncode, 'timed_out': False}
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            data, _ = process.communicate()
            status = {'exit_code': None, 'timed_out': True}
        log.write_bytes(data)
        status.update(command=argv, log=log.name, log_sha256=hashlib.sha256(data).hexdigest())
        return status, data.decode(errors='replace')

    report['source'] = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root).decode().strip()
    report['rustc'], _ = command('rustc', ['rustc', '-Vv'], 15)
    report['gdb_available'] = shutil.which('gdb')
    save()
    if not report['gdb_available']:
        report['status'] = 'blocked_gdb_not_installed'
        save()
        return
    report['gdb'], _ = command('gdb-version', ['gdb', '--version'], 15)
    build, messages = command('build', [
        'cargo', 'test', '--locked', '--jobs', '2', '-p', 'bitcoin-rs-node',
        '--no-default-features', '--features', 'fjall,zmq', '--lib', '--no-run',
        '--message-format=json'], 180)
    report['build'] = build
    if build['exit_code'] != 0:
        report['status'] = 'blocked_build_failed_or_timed_out'
        save()
        return
    executables = []
    for line in messages.splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if (item.get('reason') == 'compiler-artifact'
                and item.get('target', {}).get('name') == 'bitcoin_rs_node'
                and item.get('profile', {}).get('test') and item.get('executable')):
            executables.append(Path(item['executable']))
    if len(executables) != 1:
        report['status'] = 'blocked_ambiguous_test_executable'
        save()
        return
    executable = executables[0]
    report['binary_sha256'] = hashlib.sha256(executable.read_bytes()).hexdigest()
    shutil.copyfile(executable, output / 'node-unit-tests')
    case = 'state::tests::construction::zmq_publisher_handle_reports_active_metadata'
    report['test_case'] = case
    for index in range(1, 7):
        result, trace = command('gdb-' + str(index), [
            'gdb', '--batch', '--quiet',
            '-ex', 'set pagination off', '-ex', 'set confirm off',
            '-ex', 'set print thread-events off', '-ex', 'set disable-randomization off',
            '-ex', 'run', '-ex', 'thread apply all bt 40',
            '-ex', 'info registers', '-ex', 'info sharedlibrary',
            '--args', str(executable), '--exact', case, '--nocapture'], 35)
        result['inferior_sigsegv'] = bool(re.search(r'(received signal|terminated with signal) SIGSEGV', trace))
        report['attempts'].append(result)
        save()
        if result['inferior_sigsegv'] or result['timed_out']:
            break
    report['status'] = 'collected'
    report['crash_observed'] = any(item['inferior_sigsegv'] for item in report['attempts'])
    report['finished_at'] = datetime.now(timezone.utc).isoformat()
    save()
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
