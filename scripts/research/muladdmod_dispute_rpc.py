#!/usr/bin/env python3
"""Exercise a fixed, canonical arithmetic claim on an isolated regtest node.

All signing secrets are public test constants. Never use this signer with funds.
"""
from __future__ import annotations

import argparse
import base64
from dataclasses import dataclass, replace
from decimal import Decimal
import json
from pathlib import Path
import signal
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

from muladdmod_rpc import G, N, P, RpcError, add, bech32m, compact, free_port, mul, sha, tagged, variable

NUMS_X = bytes.fromhex('50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0')
RECOVERY_SECRET = 3
OPERATOR_SECRET = 5
DELAY = 6
START_HEIGHT = 432
AMOUNT = 100_000
FEE = 2_000


def public_key(secret: int) -> bytes:
    if not 1 <= secret < N:
        raise ValueError('invalid fixture secret')
    point = mul(secret, G)
    return point[0].to_bytes(32, 'big')


def sign(message: bytes, secret: int, aux: bytes = bytes(32)) -> bytes:
    """BIP340 test-only signing; affine Python operations are variable-time."""
    if len(message) != 32 or len(aux) != 32 or not 1 <= secret < N:
        raise ValueError('invalid signer input')
    point = mul(secret, G)
    d = N - secret if point[1] & 1 else secret
    key = point[0].to_bytes(32, 'big')
    masked = bytes(a ^ b for a, b in zip(d.to_bytes(32, 'big'), tagged('BIP0340/aux', aux)))
    k0 = int.from_bytes(tagged('BIP0340/nonce', masked + key + message), 'big') % N
    if not k0:
        raise ValueError('zero nonce')
    r = mul(k0, G)
    k = N - k0 if r[1] & 1 else k0
    encoded_r = r[0].to_bytes(32, 'big')
    e = int.from_bytes(tagged('BIP0340/challenge', encoded_r + key + message), 'big') % N
    return encoded_r + ((k + e * d) % N).to_bytes(32, 'big')


def push(data: bytes) -> bytes:
    if not data:
        return b'\x00'
    if len(data) == 1 and 1 <= data[0] <= 16:
        return bytes([0x50 + data[0]])
    if data == b'\x81':
        return b'\x4f'
    if len(data) <= 75:
        return bytes([len(data)]) + data
    raise ValueError('fixture literal too large')


def script_number(value: int) -> bytes:
    if value < 0:
        raise ValueError('negative fixture number')
    raw = value.to_bytes((value.bit_length() + 7) // 8, 'little')
    return raw + b'\x00' if raw and raw[-1] & 0x80 else raw


@dataclass(frozen=True)
class Leaf:
    script: bytes

    @property
    def digest(self) -> bytes:
        return tagged('TapLeaf', b'\xc0' + variable(self.script))

    def output(self) -> tuple[bytes, bytes]:
        x = int.from_bytes(NUMS_X, 'big')
        y = pow((x*x*x + 7) % P, (P + 1) // 4, P)
        if y*y % P != (x*x*x + 7) % P:
            raise ValueError('invalid NUMS point')
        internal = (x, P-y if y & 1 else y)
        tweak = int.from_bytes(tagged('TapTweak', NUMS_X + self.digest), 'big')
        if tweak >= N:
            raise ValueError('invalid Taproot tweak')
        output = add(internal, mul(tweak, G))
        if output is None:
            raise ValueError('infinite output')
        spk = b'\x51\x20' + output[0].to_bytes(32, 'big')
        control = bytes([0xc0 | (output[1] & 1)]) + NUMS_X
        return spk, control


@dataclass(frozen=True)
class Claim:
    instance: bytes
    a: int
    b: int
    c: int
    claimed: int
    modulus: int
    delay: int = DELAY

    def __post_init__(self):
        if len(self.instance) != 32 or not 2 <= self.modulus < 2**256:
            raise ValueError('invalid claim context')
        if any(not 0 <= v < self.modulus for v in (self.a, self.b, self.c, self.claimed)):
            raise ValueError('claim admission requires canonical residues')
        if not 1 <= self.delay <= 65535:
            raise ValueError('invalid block delay')

    def values(self) -> list[bytes]:
        w = (self.modulus.bit_length() + 7) // 8
        return [v.to_bytes(w, 'little') for v in (self.a, self.b, self.c, self.claimed)]

    def leaf(self) -> Leaf:
        script = push(self.instance) + b'\x75\x63' + push(public_key(RECOVERY_SECRET)) + b'\xad'
        for value in reversed(self.values()[1:]):
            script += b'\x76\xa8' + push(sha(value)) + b'\x88\x6b'
        script += b'\x76\xa8' + push(sha(self.values()[0])) + b'\x88'
        modulus = self.modulus.to_bytes((self.modulus.bit_length() + 7) // 8, 'little')
        script += b'\x6c\x6c' + push(modulus) + b'\xf0\x6c\x87\x91\x67'
        script += push(script_number(self.delay)) + b'\xb2\x75'
        script += push(public_key(OPERATOR_SECRET)) + b'\xac\x68'
        return Leaf(script)


def txout(value: int, script: bytes) -> bytes:
    if not 0 <= value <= 21_000_000 * 100_000_000:
        raise ValueError('invalid output amount')
    return value.to_bytes(8, 'little') + variable(script)


@dataclass(frozen=True)
class Spend:
    txid: str
    index: int
    amount: int
    prev_script: bytes
    outputs: tuple[tuple[int, bytes], ...]
    sequence: int = 0xffffffff

    def outpoint(self) -> bytes:
        return bytes.fromhex(self.txid)[::-1] + self.index.to_bytes(4, 'little')

    def outputs_bytes(self) -> bytes:
        return b''.join(txout(value, script) for value, script in self.outputs)

    def serialize(self, witness: list[bytes]) -> tuple[str, str]:
        vin = self.outpoint() + b'\x00' + self.sequence.to_bytes(4, 'little')
        body = b'\x01' + vin + compact(len(self.outputs)) + self.outputs_bytes()
        version, lock = (2).to_bytes(4, 'little'), bytes(4)
        w = compact(len(witness)) + b''.join(variable(v) for v in witness)
        raw = version + b'\x00\x01' + body + w + lock
        return raw.hex(), sha(sha(version + body + lock))[::-1].hex()

    def sighash(self, leaf: Leaf) -> bytes:
        message = b'\x00' + (2).to_bytes(4, 'little') + bytes(4)
        message += sha(self.outpoint()) + sha(self.amount.to_bytes(8, 'little'))
        message += sha(variable(self.prev_script)) + sha(self.sequence.to_bytes(4, 'little'))
        message += sha(self.outputs_bytes()) + b'\x02' + bytes(4)
        extension = leaf.digest + b'\x00' + b'\xff'*4
        return tagged('TapSighash', b'\x00' + message + extension)


def claim_spend(funding: str, index: int, claim: Claim, recover: bool):
    leaf = claim.leaf()
    spk, control = leaf.output()
    secret = RECOVERY_SECRET if recover else OPERATOR_SECRET
    recipient = b'\x51\x20' + public_key(secret)
    spend = Spend(funding, index, AMOUNT, spk, ((AMOUNT-FEE, recipient),),
                  0xffffffff if recover else claim.delay)
    signature = sign(spend.sighash(leaf), secret)
    witness = claim.values() + [signature, b'\x01'] if recover else [signature, b'']
    return spend, witness + [leaf.script, control]


class Node:
    def __init__(self, binary: Path, root: Path):
        self.root, self.binary = root, binary
        self.rpc_port, self.p2p_port = free_port(), free_port()
        while self.p2p_port == self.rpc_port:
            self.p2p_port = free_port()
        self.process = None
        self.log = (root / 'node.log').open('ab')

    def rpc(self, method, params=None):
        auth = base64.b64encode(b'research:local-dispute-test').decode()
        request = urllib.request.Request(f'http://127.0.0.1:{self.rpc_port}/',
                    json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method,
                                'params': params or []}).encode(),
                    headers={'Content-Type': 'application/json', 'Authorization': 'Basic '+auth})
        try:
            response = urllib.request.urlopen(request, timeout=60)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            result = json.load(response)
        if result.get('error'):
            raise RpcError(method, result['error'])
        return result['result']

    def start(self):
        self.process = subprocess.Popen([str(self.binary), '--network', 'regtest',
            '--validation-engine', 'native', '--storage-backend', 'fjall',
            '--data-dir', str(self.root / 'data'), '--p2p-listen', f'127.0.0.1:{self.p2p_port}',
            '--rpc-bind', f'127.0.0.1:{self.rpc_port}', '--dns-seeds-enabled=false',
            '--rpc-user', 'research', '--rpc-password', 'local-dispute-test'],
            stdout=self.log, stderr=subprocess.STDOUT)
        deadline = time.monotonic()+90
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError('node exited during startup')
            try:
                info = self.rpc('getblockchaininfo')
                assert info['chain'] == 'regtest', info
                return info
            except (OSError, RpcError):
                time.sleep(0.2)
        raise TimeoutError('RPC startup')

    def stop(self):
        if self.process is not None and self.process.poll() is None:
            self.process.send_signal(signal.SIGTERM)
            try:
                self.process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=10)
        self.process = None


def run(binary: Path, report_path: Path, modulus: int = 17):
    binary = binary.resolve(strict=True)
    report = {'status': 'running', 'binary_sha256': sha(binary.read_bytes()).hex(),
              'modulus': str(modulus), 'rejected': {}}
    with tempfile.TemporaryDirectory(prefix='muladdmod-dispute-') as directory:
        root = Path(directory)
        node = Node(binary, root)
        rpc = node.rpc
        try:
            assert node.start()['blocks'] == 0
            initial_leaf = Leaf(b'\x51')
            initial_spk, initial_control = initial_leaf.output()
            address = bech32m(initial_spk[2:])
            blocks = rpc('generatetoaddress', [START_HEIGHT, address])
            coinbase = rpc('getblock', [blocks[0], 2])['tx'][0]
            source = next(v for v in coinbase['vout'] if v['scriptPubKey']['hex'] == initial_spk.hex())
            value = int(Decimal(str(source['value'])) * 100_000_000)
            a, b, c = (7, 11, 3) if modulus == 17 else (modulus-1, modulus-1, modulus-1)
            correct = (a*b+c) % modulus
            claims = [Claim(sha(b'claim'+bytes([i])), a,b,c,
                            correct if i == 1 else (correct+1) % modulus, modulus)
                      for i in range(3)]
            outputs = tuple((AMOUNT, claim.leaf().output()[0]) for claim in claims)
            funding = Spend(coinbase['txid'], source['n'], value, initial_spk,
                            outputs+((value-3*AMOUNT-FEE, initial_spk),))
            funding_hex, funding_id = funding.serialize([initial_leaf.script, initial_control])
            assert rpc('sendrawtransaction', [funding_hex]) == funding_id
            funding_block = rpc('generatetoaddress', [1, address])[0]
            assert funding_id in rpc('getblock', [funding_block])['tx']
            assert rpc('getblockcount') == START_HEIGHT+1
            recovery, witness = claim_spend(funding_id, 0, claims[0], True)
            good_hex, recovery_id = recovery.serialize(witness)
            assert rpc('testmempoolaccept', [[good_hex]])[0]['allowed'] is True

            def reject(name, raw):
                dry = rpc('testmempoolaccept', [[raw]])[0]
                assert dry['allowed'] is False, (name, dry)
                try:
                    rpc('sendrawtransaction', [raw])
                except RpcError as error:
                    report['rejected'][name] = {'dry_run': dry, 'admission': error.error}
                else:
                    raise AssertionError(name+' entered mempool')

            for i, name in enumerate(('operand_a', 'operand_b', 'operand_c', 'claimed_result')):
                altered = witness.copy()
                n = int.from_bytes(altered[i], 'little')
                altered[i] = ((n+1) % modulus).to_bytes(len(altered[i]), 'little')
                reject(name, recovery.serialize(altered)[0])
            altered = witness.copy()
            altered[0], altered[1] = altered[1], altered[0]
            if a != b:
                reject('operand_slot_swap', recovery.serialize(altered)[0])
            altered = witness.copy()
            altered[0] += b'\x00'
            reject('noncanonical_width', recovery.serialize(altered)[0])
            altered = witness.copy()
            altered[4] = bytes([altered[4][0] ^ 1])+altered[4][1:]
            reject('signature', recovery.serialize(altered)[0])
            altered = witness.copy()
            altered[4] = sign(recovery.sighash(claims[0].leaf()), OPERATOR_SECRET)
            reject('wrong_recovery_key', recovery.serialize(altered)[0])
            altered = witness.copy()
            altered[5] = b'\x02'
            reject('nonminimal_branch_selector', recovery.serialize(altered)[0])
            altered = witness.copy()
            altered[4] = b''
            reject('empty_recovery_signature', recovery.serialize(altered)[0])
            changed_modulus = replace(claims[0], modulus=modulus+2).leaf()
            altered = witness.copy()
            altered[-2] = changed_modulus.script
            altered[4] = sign(recovery.sighash(changed_modulus), RECOVERY_SECRET)
            reject('unpinned_modulus_script', recovery.serialize(altered)[0])
            redirected = Spend(recovery.txid, recovery.index, recovery.amount, recovery.prev_script,
                               ((AMOUNT-FEE, b'\x51\x20'+public_key(OPERATOR_SECRET)),))
            reject('redirected_output', redirected.serialize(witness)[0])
            other, other_witness = claim_spend(funding_id, 2, claims[2], True)
            other_witness[4] = witness[4]
            reject('cross_instance_signature', other.serialize(other_witness)[0])
            reject('cross_instance_script', other.serialize(witness)[0])
            honest, honest_witness = claim_spend(funding_id, 1, claims[1], True)
            honest_raw = honest.serialize(honest_witness)[0]
            reject('honest_claim_recovery', honest_raw)
            try:
                rpc('generateblock', [address, [honest_raw]])
            except RpcError as error:
                report['invalid_block'] = error.error
            else:
                raise AssertionError('honest claim was confiscated in a block')
            assert rpc('getblockcount') == START_HEIGHT+1
            settlement, settle_witness = claim_spend(funding_id, 1, claims[1], False)
            settle_hex, settle_id = settlement.serialize(settle_witness)
            reject('premature_settlement', settle_hex)
            disabled_delay = replace(settlement, sequence=0xffffffff)
            altered = settle_witness.copy()
            altered[0] = sign(disabled_delay.sighash(claims[1].leaf()), OPERATOR_SECRET)
            reject('disabled_sequence_lock', disabled_delay.serialize(altered)[0])
            assert rpc('sendrawtransaction', [good_hex]) == recovery_id
            block = rpc('generatetoaddress', [1, address])[0]
            assert recovery_id in rpc('getblock', [block])['tx']
            assert rpc('gettxout', [funding_id, 0]) is None
            recovered = rpc('gettxout', [recovery_id, 0])
            assert recovered['scriptPubKey']['hex'] == recovery.outputs[0][1].hex()
            assert int(Decimal(str(recovered['value']))*100_000_000) == AMOUNT-FEE
            rpc('generatetoaddress', [DELAY-2, address])
            assert rpc('getblockcount') == START_HEIGHT+DELAY
            assert rpc('testmempoolaccept', [[settle_hex]])[0]['allowed'] is True
            assert rpc('sendrawtransaction', [settle_hex]) == settle_id
            block = rpc('generatetoaddress', [1, address])[0]
            assert settle_id in rpc('getblock', [block])['tx']
            double, double_witness = claim_spend(funding_id, 0, claims[0], False)
            reject('settlement_after_recovery', double.serialize(double_witness)[0])
            node.stop()
            assert node.start()['blocks'] == START_HEIGHT+DELAY+1
            assert rpc('gettxout', [funding_id, 0]) is None
            assert rpc('gettxout', [funding_id, 1]) is None
            assert rpc('gettxout', [funding_id, 2]) is not None
            assert rpc('gettxout', [recovery_id, 0])['scriptPubKey']['hex'] == recovery.outputs[0][1].hex()
            assert rpc('gettxout', [settle_id, 0])['scriptPubKey']['hex'] == settlement.outputs[0][1].hex()
            late_recovery, late_proof = claim_spend(funding_id, 2, claims[2], True)
            late_settlement, late_authorization = claim_spend(funding_id, 2, claims[2], False)
            late_raw, late_id = late_settlement.serialize(late_authorization)
            late_recovery_raw = late_recovery.serialize(late_proof)[0]
            assert rpc('testmempoolaccept', [[late_raw]])[0]['allowed'] is True
            assert rpc('testmempoolaccept', [[late_recovery_raw]])[0]['allowed'] is True
            assert rpc('sendrawtransaction', [late_raw]) == late_id
            missed = rpc('generatetoaddress', [1, address])[0]
            assert late_id in rpc('getblock', [missed])['tx']
            reject('recovery_after_missed_window', late_recovery_raw)
            report['missed_window'] = {'both_paths_eligible': True, 'settlement_height': rpc('getblockcount'),
                                       'false_claim_settlement': late_id}
            report.update(status='passed', funding=funding_id, recovery=recovery_id, settlement=settle_id,
                          funding_height=START_HEIGHT+1, recovery_height=START_HEIGHT+2,
                          settlement_height=START_HEIGHT+DELAY+1,
                          rejection_count=len(report['rejected']), restart_preserved_outputs=True,
                          script_bytes=len(claims[0].leaf().script), recovered_sats=AMOUNT-FEE,
                          nums_internal_key=NUMS_X.hex())
        finally:
            node.stop()
            node.log.close()
            report_path.parent.mkdir(parents=True, exist_ok=True)
            report_path.write_text(json.dumps(report, indent=2)+'\n')
            report_path.with_suffix('.node.log').write_bytes((root/'node.log').read_bytes())
    print(json.dumps(report, indent=2))
    return report


if __name__ == '__main__':
    if not __debug__:
        raise RuntimeError('run the fixture with Python assertions enabled')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--wide', action='store_true')
    args = parser.parse_args()
    run(args.binary, args.report, 2**255-19 if args.wide else 17)
