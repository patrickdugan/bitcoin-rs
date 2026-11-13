"""Check the vendored command queue against its declared C++ alignment."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
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
    report = {'status': 'running', 'started_at': datetime.now(timezone.utc).isoformat(),
              'source': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root).decode().strip(),
              'steps': []}

    def run(name, argv, expected, timeout=180):
        log = output / (name + '.log')
        process = subprocess.Popen(argv, cwd=root, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, start_new_session=True)
        try:
            data, _ = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            data, _ = process.communicate()
        log.write_bytes(data)
        report['steps'].append({'name': name, 'command': argv, 'exit_code': process.returncode,
                                'expected_exit_code': expected, 'log': log.name,
                                'log_sha256': hashlib.sha256(data).hexdigest()})
        (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
        if process.returncode != expected:
            raise RuntimeError(f'{name}: expected exit {expected}, got {process.returncode}')
        return data.decode()

    messages = run('build', ['cargo', 'test', '--locked', '--jobs', '2', '-p', 'bitcoin-rs-node',
                            '--no-default-features', '--features', 'fjall,zmq', '--lib', '--no-run',
                            '--message-format=json'], 0)
    artifacts = []
    for line in messages.splitlines():
        try:
            artifacts.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    vendored = next(item for item in artifacts if item.get('target', {}).get('name') == 'zeromq_src')
    vendor = Path(vendored['manifest_path']).parent / 'vendor'
    sysbuild = next(item for item in artifacts if item.get('reason') == 'build-script-executed'
                    and 'zmq-sys@' in item.get('package_id', ''))
    archives = sorted({Path(path.removeprefix('native=')) / 'libzmq.a'
                       for path in sysbuild['linked_paths'] if path.startswith('native=')})
    assert len(archives) == 1 and archives[0].is_file()
    compiler = shutil.which('c++')
    assert compiler
    report['vendor_package'] = vendored['package_id']
    report['archive_sha256'] = hashlib.sha256(archives[0].read_bytes()).hexdigest()
    executable = next(Path(item['executable']) for item in artifacts
                      if item.get('target', {}).get('name') == 'bitcoin_rs_node'
                      and item.get('profile', {}).get('test') and item.get('executable'))
    report['node_test_binary_sha256'] = hashlib.sha256(executable.read_bytes()).hexdigest()
    shutil.copyfile(executable, output / 'node-unit-tests')
    for name, flags, expected in [
            ('malloc-baseline', ['-UHAVE_POSIX_MEMALIGN', '-DZMQ_CACHELINE_SIZE=64'], 1),
            ('aligned', ['-DHAVE_POSIX_MEMALIGN=1', '-DZMQ_CACHELINE_SIZE=64'], 0)]:
        program = output / name
        run('compile-' + name, [compiler, '-std=c++11', '-O0', '-pthread',
                               '-I' + str(vendor / 'src'), '-I' + str(vendor / 'include'),
                               '-I' + sysbuild['out_dir'], *flags,
                               str(root / 'scripts/research/keyless_zmq_alignment.cpp'),
                               str(archives[0]), '-o', str(program)], 0, 30)
        observed = json.loads(run(name, [str(program)], expected, 15))
        assert observed['required_alignment'] == 64
        assert observed['aligned'] is (expected == 0)
        assert len(observed['observed']) == 8
        report[name] = observed
    report['status'] = 'passed'
    report['finished_at'] = datetime.now(timezone.utc).isoformat()
    (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
