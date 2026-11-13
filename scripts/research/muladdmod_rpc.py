#!/usr/bin/env python3
"""Exercise experimental arithmetic on a fresh, isolated regtest node."""
import argparse
import base64
from decimal import Decimal
import hashlib
import json
from pathlib import Path
import signal
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def sha(data):
    return hashlib.sha256(data).digest()


def tagged(tag, data):
    prefix = sha(tag.encode())
    return sha(prefix + prefix + data)


def add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    x, y = a
    u, v = b
    if x == u and (y + v) % P == 0:
        return None
    slope = ((3 * x * x) * pow(2 * y, -1, P) if a == b
             else (v - y) * pow(u - x, -1, P)) % P
    q = (slope * slope - x - u) % P
    return q, (slope * (x - q) - y) % P


def mul(k, point):
    result = None
    while k:
        if k & 1:
            result = add(result, point)
        point = add(point, point)
        k >>= 1
    return result


def compact(n):
    if n < 253:
        return bytes([n])
    if n <= 65535:
        return b'\xfd' + n.to_bytes(2, 'little')
    raise ValueError('fixture length exceeds uint16')


def variable(data):
    return compact(len(data)) + data


def bech32m(program):
    hrp = 'bcrt'
    expanded = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    acc = bits = 0
    values = [1]
    for byte in program:
        acc = (acc << 8) | byte
        bits += 8
        while bits >= 5:
            bits -= 5
            values.append((acc >> bits) & 31)
    if bits:
        values.append((acc << (5 - bits)) & 31)
    generators = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    check = 1
    for v in expanded + values + [0] * 6:
        high = check >> 25
        check = ((check & 0x1FFFFFF) << 5) ^ v
        for i, g in enumerate(generators):
            if high >> i & 1:
                check ^= g
    check ^= 0x2BC830A3
    alphabet = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'
    checksum = [(check >> (5 * (5 - i))) & 31 for i in range(6)]
    return hrp + '1' + ''.join(alphabet[v] for v in values + checksum)


def fixture():
    script = bytes.fromhex('0111f05c87')
    internal = G[0].to_bytes(32, 'big')
    root = tagged('TapLeaf', b'\xc0' + variable(script))
    tweak = int.from_bytes(tagged('TapTweak', internal + root), 'big')
    if tweak >= N:
        raise ValueError('invalid Taproot tweak')
    output = add(G, mul(tweak, G))
    if output is None:
        raise ValueError('infinite Taproot output')
    key = output[0].to_bytes(32, 'big')
    control = bytes([0xC0 | (output[1] & 1)]) + internal
    return script, control, b'\x51\x20' + key, bech32m(key)


def transaction(txid, vout, value, script, control, a):
    vin = bytes.fromhex(txid)[::-1] + vout.to_bytes(4, 'little') + b'\0' + b'\xff' * 4
    payout = bytes.fromhex('0014' + '42' * 20)
    vout_bytes = (value - 10000).to_bytes(8, 'little') + variable(payout)
    body = compact(1) + vin + compact(1) + vout_bytes
    version = (2).to_bytes(4, 'little')
    lock = bytes(4)
    witness = [a, bytes([11]), bytes([3]), script, control]
    encoded = compact(len(witness)) + b''.join(variable(v) for v in witness)
    raw = version + b'\0\1' + body + encoded + lock
    expected = sha(sha(version + body + lock))[::-1].hex()
    return raw.hex(), expected


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


class RpcError(RuntimeError):
    def __init__(self, method, error):
        super().__init__(f'{method}: {error}')
        self.error = error


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    rpc_port, p2p_port = free_port(), free_port()
    while rpc_port == p2p_port:
        p2p_port = free_port()
    password = 'muladdmod-local-fixture'
    credentials = base64.b64encode(('research:' + password).encode()).decode()
    url = f'http://127.0.0.1:{rpc_port}/'

    def rpc(method, params=None):
        data = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params or []}).encode()
        request = urllib.request.Request(url, data, headers={'Content-Type': 'application/json',
                                                'Authorization': 'Basic ' + credentials})
        try:
            response = urllib.request.urlopen(request, timeout=60)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            body = json.load(response)
        if body.get('error'):
            raise RpcError(method, body['error'])
        return body['result']

    report = {'binary_sha256': sha(binary.read_bytes()).hex(), 'status': 'running'}
    process = None
    with tempfile.TemporaryDirectory(prefix='muladdmod-regtest-') as directory:
        root = Path(directory)
        log_path = root / 'node.log'
        command = [str(binary), '--network', 'regtest', '--validation-engine', 'native',
                   '--storage-backend', 'fjall', '--data-dir', str(root / 'data'),
                   '--p2p-listen', f'127.0.0.1:{p2p_port}', '--rpc-bind', f'127.0.0.1:{rpc_port}',
                   '--dns-seeds-enabled=false', '--rpc-user', 'research', '--rpc-password', password]
        with log_path.open('wb') as log:
            def start():
                proc = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT)
                deadline = time.monotonic() + 90
                try:
                    while time.monotonic() < deadline:
                        if proc.poll() is not None:
                            raise RuntimeError('node exited during startup')
                        try:
                            info = rpc('getblockchaininfo')
                            assert info['chain'] == 'regtest', info
                            return proc, info
                        except (OSError, RpcError):
                            time.sleep(0.2)
                    raise TimeoutError('RPC did not become ready')
                except BaseException:
                    proc.terminate()
                    proc.wait(timeout=30)
                    raise

            def stop(proc):
                proc.send_signal(signal.SIGTERM)
                proc.wait(timeout=30)

            try:
                process, initial = start()
                assert initial['blocks'] == 0, initial
                script, control, spk, address = fixture()
                blocks = rpc('generatetoaddress', [101, address])
                assert len(blocks) == 101
                coinbase = rpc('getblock', [blocks[0], 2])['tx'][0]
                output = next(v for v in coinbase['vout'] if v['scriptPubKey']['hex'] == spk.hex())
                value = int(Decimal(str(output['value'])) * 100_000_000)
                good, txid = transaction(coinbase['txid'], output['n'], value, script, control, bytes([7]))
                bad, bad_txid = transaction(coinbase['txid'], output['n'], value, script, control, bytes([8]))
                malformed, _ = transaction(coinbase['txid'], output['n'], value, script, control, bytes([17]))
                assert bad_txid == txid
                accepted = rpc('testmempoolaccept', [[good]])[0]
                assert accepted['allowed'] is True, accepted
                rejected = []
                for raw in [bad, malformed]:
                    result = rpc('testmempoolaccept', [[raw]])[0]
                    assert result['allowed'] is False, result
                    try:
                        rpc('sendrawtransaction', [raw])
                    except RpcError as error:
                        rejected.append({'dry_run': result, 'admission': error.error})
                    else:
                        raise AssertionError('invalid arithmetic entered mempool')
                try:
                    rpc('generateblock', [address, [bad]])
                except RpcError as error:
                    report['invalid_block_attempt'] = error.error
                else:
                    raise AssertionError('invalid arithmetic block was accepted')
                assert rpc('getblockcount') == 101
                assert rpc('sendrawtransaction', [good]) == txid
                confirmed = rpc('generatetoaddress', [1, address])[0]
                assert txid in rpc('getblock', [confirmed])['tx']
                assert rpc('gettxout', [coinbase['txid'], output['n']]) is None
                assert rpc('gettxout', [txid, 0]) is not None
                stop(process)
                process = None
                process, recovered = start()
                assert recovered['blocks'] == 102, recovered
                assert rpc('gettxout', [coinbase['txid'], output['n']]) is None
                assert rpc('gettxout', [txid, 0]) is not None
                report.update(status='passed', confirmed_height=102, txid=txid, block=confirmed,
                              script=script.hex(), address=address, rejection_cases=rejected,
                              restart_preserved_outputs=True)
            finally:
                if process is not None and process.poll() is None:
                    stop(process)
                args.report.parent.mkdir(parents=True, exist_ok=True)
                args.report.write_text(json.dumps(report, indent=2) + '\n')
                args.report.with_suffix('.node.log').write_bytes(log_path.read_bytes())
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
