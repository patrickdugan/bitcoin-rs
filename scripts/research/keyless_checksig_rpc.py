#!/usr/bin/env python3
"""Fund and spend a two-recipient TXCOMMIT policy on isolated regtest.

The policy follows Spiral BIPSpace/Keyless-CHECKSIG/reference.py at
cfafbec4ae072b859f0140b2487baac14fac3a44, with fixed transcript widths and
a BIP341 NUMS P2TR output. The test creates no signatures. P2TR retains its
key path under the usual no-known-discrete-log assumption for the NUMS point.
"""
from __future__ import annotations

import argparse
import base64
from dataclasses import dataclass, replace
from decimal import Decimal
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import tempfile
import time
import urllib.error
import urllib.request


P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
NUMS_X = bytes.fromhex('50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0')
RECIPIENTS = (
    bytes.fromhex('79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'),
    bytes.fromhex('c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5'),
)
AMOUNT = 100_000
FEE = 2_000
PAYOUT = AMOUNT - FEE
MAX_MONEY = 21_000_000 * 100_000_000
PREFIX_BYTES = 138
SUFFIX_BYTES = 42
POLICY_REJECTIONS = frozenset(('oversized_witness_element', 'annex_with_stale_commitment',
                               'annex_excluded_by_policy_width'))


def sha(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


TXCOMMIT_KEY = b'\x02' + sha(b'BIPSpace/Keyless-CHECKSIG/TXCOMMIT-draft')


def tagged(tag: str, data: bytes) -> bytes:
    prefix = sha(tag.encode('ascii'))
    return sha(prefix + prefix + data)


def require(condition: bool, message: str):
    if not condition:
        raise ValueError(message)


def require_assertions():
    if not __debug__:
        raise RuntimeError('run the fixture with Python assertions enabled')


def compact(value: int) -> bytes:
    require(0 <= value < 2**64, 'invalid CompactSize value')
    if value < 253:
        return bytes([value])
    if value <= 0xffff:
        return b'\xfd' + struct.pack('<H', value)
    if value <= 0xffffffff:
        return b'\xfe' + struct.pack('<I', value)
    return b'\xff' + struct.pack('<Q', value)


def variable(data: bytes) -> bytes:
    return compact(len(data)) + data


def point_add(left, right):
    if left is None:
        return right
    if right is None:
        return left
    x, y = left
    u, v = right
    if x == u and (y + v) % P == 0:
        return None
    slope = (3*x*x * pow(2*y, -1, P) if left == right
             else (v-y) * pow(u-x, -1, P)) % P
    result_x = (slope*slope - x - u) % P
    return result_x, (slope*(x-result_x) - y) % P


def point_mul(scalar, point):
    require(0 <= scalar < N, 'invalid point scalar')
    result = None
    while scalar:
        if scalar & 1:
            result = point_add(result, point)
        point = point_add(point, point)
        scalar >>= 1
    return result


def lift_x(encoded: bytes):
    require(len(encoded) == 32, 'invalid x-only key width')
    x = int.from_bytes(encoded, 'big')
    require(x < P, 'invalid x-only key coordinate')
    y = pow((x*x*x + 7) % P, (P+1)//4, P)
    require(y*y % P == (x*x*x + 7) % P, 'x-only key is not on curve')
    return x, P-y if y & 1 else y


def tweaked_key(internal: bytes, root: bytes = b'') -> tuple[bytes, int]:
    require(len(root) in (0, 32), 'invalid Taproot root width')
    tweak = int.from_bytes(tagged('TapTweak', internal + root), 'big')
    require(tweak < N, 'invalid Taproot tweak')
    point = point_add(lift_x(internal), point_mul(tweak, G))
    require(point is not None, 'infinite Taproot output')
    return point[0].to_bytes(32, 'big'), point[1] & 1


def tapleaf(script: bytes) -> bytes:
    return tagged('TapLeaf', b'\xc0' + variable(script))


@dataclass(frozen=True)
class Leaf:
    script: bytes

    def output(self) -> tuple[bytes, bytes]:
        key, parity = tweaked_key(NUMS_X, tapleaf(self.script))
        return b'\x51\x20' + key, bytes([0xc0 | parity]) + NUMS_X


def address(program: bytes) -> str:
    require(len(program) == 32, 'expected 32-byte witness program')
    hrp = 'bcrt'
    data = [1]
    buffer = bits = 0
    for byte in program:
        buffer = (buffer << 8) | byte
        bits += 8
        while bits >= 5:
            bits -= 5
            data.append((buffer >> bits) & 31)
    if bits:
        data.append((buffer << (5-bits)) & 31)
    check = 1
    expanded = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    generators = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    for value in expanded + data + [0]*6:
        top = check >> 25
        check = ((check & 0x1ffffff) << 5) ^ value
        for bit, generator in enumerate(generators):
            if top >> bit & 1:
                check ^= generator
    check ^= 0x2bc830a3
    alphabet = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'
    tail = [(check >> (5*(5-i))) & 31 for i in range(6)]
    return hrp + '1' + ''.join(alphabet[value] for value in data + tail)


@dataclass(frozen=True)
class Input:
    txid: bytes
    index: int
    amount: int
    script: bytes
    sequence: int = 0xfffffffd

    def outpoint(self) -> bytes:
        require(len(self.txid) == 32 and 0 <= self.index <= 0xffffffff, 'invalid outpoint')
        return self.txid + struct.pack('<I', self.index)


@dataclass(frozen=True)
class Output:
    amount: int
    script: bytes

    def serialize(self) -> bytes:
        require(0 <= self.amount <= MAX_MONEY, 'invalid output value')
        return struct.pack('<Q', self.amount) + variable(self.script)


@dataclass(frozen=True)
class Tx:
    inputs: tuple[Input, ...]
    outputs: tuple[Output, ...]
    version: int = 2
    locktime: int = 0

    def body(self) -> bytes:
        vins = b''.join(item.outpoint() + b'\x00' + struct.pack('<I', item.sequence)
                        for item in self.inputs)
        return compact(len(self.inputs)) + vins + compact(len(self.outputs)) + b''.join(
            item.serialize() for item in self.outputs)

    def serialize(self, witnesses: list[list[bytes]]) -> tuple[str, str]:
        require(len(witnesses) == len(self.inputs), 'one witness required per input')
        version, locktime = struct.pack('<i', self.version), struct.pack('<I', self.locktime)
        body = self.body()
        witness = b''.join(compact(len(items)) + b''.join(variable(item) for item in items)
                           for items in witnesses)
        raw = version + b'\x00\x01' + body + witness + locktime
        txid = sha(sha(version + body + locktime))[::-1].hex()
        return raw.hex(), txid


def sigmsg(tx: Tx, index: int, *, hash_type: int = 0, ext_flag: int = 1,
           leaf: bytes | None = None, key_version: int = 2,
           codesep: int = 0xffffffff, annex: bytes | None = None) -> bytes:
    require(hash_type in (0, 1, 2, 3, 0x81, 0x82, 0x83), 'invalid hash type')
    require(0 <= index < len(tx.inputs), 'invalid input index')
    require(ext_flag in (0, 1), 'unsupported extension flag')
    require(all(0 <= item.amount <= MAX_MONEY for item in tx.inputs), 'invalid input value')
    mode, anyone = hash_type & 3, bool(hash_type & 0x80)
    parts = [bytes([0, hash_type]), struct.pack('<iI', tx.version, tx.locktime)]
    if not anyone:
        parts.extend((sha(b''.join(item.outpoint() for item in tx.inputs)),
                      sha(b''.join(struct.pack('<Q', item.amount) for item in tx.inputs)),
                      sha(b''.join(variable(item.script) for item in tx.inputs)),
                      sha(b''.join(struct.pack('<I', item.sequence) for item in tx.inputs))))
    if mode in (0, 1):
        parts.append(sha(b''.join(item.serialize() for item in tx.outputs)))
    parts.append(bytes([2*ext_flag + (annex is not None)]))
    if anyone:
        item = tx.inputs[index]
        parts.extend((item.outpoint(), struct.pack('<Q', item.amount), variable(item.script),
                      struct.pack('<I', item.sequence)))
    else:
        parts.append(struct.pack('<I', index))
    if annex is not None:
        require(annex.startswith(b'\x50'), 'invalid annex prefix')
        parts.append(sha(variable(annex)))
    if mode == 3:
        require(index < len(tx.outputs), 'SIGHASH_SINGLE has no corresponding output')
        parts.append(sha(tx.outputs[index].serialize()))
    if ext_flag == 1:
        require(leaf is not None and len(leaf) == 32, 'invalid tapleaf hash')
        require(0 <= key_version <= 255 and 0 <= codesep <= 0xffffffff,
                'invalid tapscript extension')
        parts.extend((leaf, bytes([key_version]), struct.pack('<I', codesep)))
    return b''.join(parts)


def sighash(tx: Tx, index: int, **options) -> bytes:
    return tagged('TapSighash', sigmsg(tx, index, **options))


def push(data: bytes) -> bytes:
    if not data:
        return b'\x00'
    if len(data) == 1 and 1 <= data[0] <= 16:
        return bytes([0x50 + data[0]])
    if data == b'\x81':
        return b'\x4f'
    require(len(data) <= 75, 'policy push exceeds direct push width')
    return bytes([len(data)]) + data


def script_number(value: int) -> bytes:
    require(value >= 0, 'negative policy number')
    raw = value.to_bytes((value.bit_length()+7)//8, 'little')
    return raw + b'\x00' if raw and raw[-1] & 0x80 else raw


def policy_script(amount: int = PAYOUT) -> bytes:
    require(0 <= amount <= MAX_MONEY, 'invalid policy amount')
    root = sha(sha(RECIPIENTS[0]) + sha(RECIPIENTS[1]))
    tag = sha(b'TapSighash')
    return b''.join((
        b'\x6b\x6b\x76\xa8\x6c\x6c\x63\x7c\x68\x7e\xa8',
        push(root), b'\x88\x6b\x6b\x7e\x6c\x6c\x7b\x82',
        push(script_number(PREFIX_BYTES)), b'\x88\x6b\x7c\x82',
        push(script_number(SUFFIX_BYTES)), b'\x88\x6b',
        push(b'\x51\x20'), b'\x7c\x7e',
        push(struct.pack('<Q', amount) + b'\x22'), b'\x7c\x7e\xa8',
        b'\x6c\x6c\x7b\x7b\x7e\x7e', push(tag + tag), b'\x7c\x7e\xa8',
        push(TXCOMMIT_KEY), b'\xad\x51',
    ))


def policy_spend(funding: str, vout: int, recipient: int, *, amount: int = AMOUNT):
    require(recipient in (0, 1), 'invalid recipient index')
    leaf = Leaf(policy_script())
    spent_script, control = leaf.output()
    tx = Tx((Input(bytes.fromhex(funding)[::-1], vout, amount, spent_script),),
            (Output(PAYOUT, b'\x51\x20' + RECIPIENTS[recipient]),))
    return tx, policy_witness(tx, leaf, control, recipient)


def policy_witness(tx: Tx, leaf: Leaf, control: bytes, recipient: int,
                   *, annex: bytes | None = None) -> list[bytes]:
    require(recipient in (0, 1), 'invalid recipient index')
    message = sigmsg(tx, 0, leaf=tapleaf(leaf.script), annex=annex)
    require(len(message) == 212 + (32 if annex is not None else 0), 'unexpected transcript width')
    return [message[:74], message[74:138], message[170:], RECIPIENTS[recipient],
            sha(RECIPIENTS[1-recipient]), b'\x01' if recipient else b'', leaf.script, control]


def fixture_environment() -> dict[str, str]:
    return {key: value for key, value in os.environ.items() if not key.startswith('BITCOIN_RS_')}


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


class RpcError(RuntimeError):
    def __init__(self, method: str, error):
        super().__init__(f'{method}: {error}')
        self.error = error


class Node:
    def __init__(self, binary: Path, root: Path):
        self.binary = binary
        self.root = root
        self.rpc_port, self.p2p_port = free_port(), free_port()
        while self.rpc_port == self.p2p_port:
            self.p2p_port = free_port()
        self.password = os.urandom(24).hex()
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        self.process = None
        self.exit_codes = []
        self.log = (root / 'node.log').open('ab')

    def rpc(self, method, params=None):
        credentials = base64.b64encode(('research:' + self.password).encode()).decode()
        payload = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method,
                              'params': params or []}).encode()
        request = urllib.request.Request(f'http://127.0.0.1:{self.rpc_port}/', payload,
                  headers={'Content-Type': 'application/json', 'Authorization': 'Basic '+credentials})
        try:
            response = self.opener.open(request, timeout=60)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            result = json.load(response)
        if result.get('error'):
            raise RpcError(method, result['error'])
        return result['result']

    def start(self):
        require(self.process is None, 'node already started')
        command = [str(self.binary), '--network', 'regtest', '--validation-engine', 'native',
                   '--validation-mode', 'full', '--storage-backend', 'fjall',
                   '--data-dir', str(self.root / 'data'), '--p2p-listen', f'127.0.0.1:{self.p2p_port}',
                   '--rpc-bind', f'127.0.0.1:{self.rpc_port}', '--dns-seeds-enabled=false',
                   '--rpc-user', 'research', '--rpc-password', self.password]
        self.process = subprocess.Popen(command, env=fixture_environment(), cwd=self.root,
                                        stdout=self.log, stderr=subprocess.STDOUT)
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            require(self.process.poll() is None, 'node exited during startup')
            try:
                info = self.rpc('getblockchaininfo')
                require(info['chain'] == 'regtest', 'fixture requires regtest')
                require(self.rpc('getconnectioncount') == 0, 'fixture node has a peer')
                return info
            except (OSError, RpcError):
                time.sleep(0.2)
        raise TimeoutError('regtest RPC startup timed out')

    def stop(self):
        process = self.process
        if self.process is not None and self.process.poll() is None:
            self.process.send_signal(signal.SIGTERM)
            try:
                self.process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=10)
        self.process = None
        if process is not None:
            self.exit_codes.append(process.returncode)
            require(process.returncode == 0, f'node exited with status {process.returncode}')


def satoshis(value) -> int:
    result = Decimal(str(value)) * 100_000_000
    require(result == result.to_integral_value(), 'fractional satoshi from RPC')
    return int(result)


def run(binary: Path, report_path: Path):
    require_assertions()
    binary = binary.resolve(strict=True)
    require(binary.is_file() and os.access(binary, os.X_OK), 'node binary is not executable')
    report = {'schema_version': 1, 'status': 'running',
              'binary_sha256': sha(binary.read_bytes()).hex(), 'network': 'regtest',
              'txcommit_key': TXCOMMIT_KEY.hex(), 'key_version': 2,
              'nums_internal_key': NUMS_X.hex(), 'rejected': {}, 'consensus_rejections': {},
              'scope': 'Funded two-recipient policy in NUMS P2TR with TXCOMMIT and companion CAT; '
                       'no reserve script signatures; no P2MR, general proof verifier, or bridge claim.'}
    report_path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='keyless-checksig-regtest-') as directory:
        root = Path(directory)
        node = Node(binary, root)
        rpc = node.rpc
        try:
            require(node.start()['blocks'] == 0, 'fixture requires a fresh chain')
            initial_leaf = Leaf(b'\x51')
            initial_spk, initial_control = initial_leaf.output()
            mining_address = address(initial_spk[2:])
            blocks = rpc('generatetoaddress', [101, mining_address])
            require(len(blocks) == 101, 'coinbase maturity blocks missing')
            coinbase = rpc('getblock', [blocks[0], 2])['tx'][0]
            source = next(item for item in coinbase['vout']
                          if item['scriptPubKey']['hex'] == initial_spk.hex())
            source_amount = satoshis(source['value'])
            leaf = Leaf(policy_script())
            policy_spk, control = leaf.output()
            funding = Tx((Input(bytes.fromhex(coinbase['txid'])[::-1], source['n'],
                                source_amount, initial_spk),),
                         (Output(AMOUNT, policy_spk), Output(AMOUNT, policy_spk),
                          Output(AMOUNT, policy_spk), Output(AMOUNT, initial_spk),
                          Output(source_amount-4*AMOUNT-FEE, initial_spk)))
            funding_raw, funding_id = funding.serialize([[initial_leaf.script, initial_control]])
            require(rpc('sendrawtransaction', [funding_raw]) == funding_id, 'funding txid mismatch')
            funding_block = rpc('generatetoaddress', [1, mining_address])[0]
            require(funding_id in rpc('getblock', [funding_block])['tx'], 'funding did not confirm')
            require(rpc('getblockcount') == 102, 'unexpected funding height')
            report.update(funding_txid=funding_id, funding_height=102, funding_sats=AMOUNT,
                          payout_sats=PAYOUT, fee_sats=FEE, script_hex=leaf.script.hex(),
                          control_hex=control.hex(), script_bytes=len(leaf.script))
            first, witness = policy_spend(funding_id, 0, 0)
            first_raw, first_id = first.serialize([witness])
            alternative, alternative_witness = policy_spend(funding_id, 0, 1)
            alternative_raw, _ = alternative.serialize([alternative_witness])
            first_admission = rpc('testmempoolaccept', [[first_raw]])[0]
            report['alternative_admission'] = [first_admission]
            require(first_admission['allowed'] is True, 'first permitted recipient rejected')
            second_admission = rpc('testmempoolaccept', [[alternative_raw]])[0]
            report['alternative_admission'].append(second_admission)
            require(second_admission['allowed'] is True,
                    'second permitted recipient rejected for the same reserve')
            report['both_alternatives_eligible'] = True

            def reject(name: str, tx: Tx, items: list[bytes], others=None):
                raw, _ = tx.serialize([items] + (others or []))
                dry = rpc('testmempoolaccept', [[raw]])[0]
                require(dry['allowed'] is False, name + ' passed testmempoolaccept')
                try:
                    rpc('sendrawtransaction', [raw])
                except RpcError as error:
                    report['rejected'][name] = {'dry_run': dry, 'admission': error.error}
                else:
                    raise ValueError(name + ' entered the mempool')
                if name in POLICY_REJECTIONS:
                    height = rpc('getblockcount')
                    try:
                        rpc('generateblock', [mining_address, [raw]])
                    except RpcError as error:
                        unchanged = rpc('getblockcount')
                        require(unchanged == height, name + ' changed chain height')
                        report['consensus_rejections'][name] = {
                            'error': error.error, 'height_before': height, 'height_after': unchanged}
                    else:
                        raise ValueError(name + ' entered a block')
                return raw

            wrong_recipient = replace(first, outputs=(Output(PAYOUT, b'\x51\x20'+NUMS_X),))
            reject('unauthorized_recipient', wrong_recipient, witness)
            unknown_witness = witness.copy()
            unknown_witness[3] = NUMS_X
            reject('unauthorized_membership', wrong_recipient, unknown_witness)
            reject('allowed_recipient_without_new_opening', alternative, witness)
            lower = replace(first, outputs=(replace(first.outputs[0], amount=PAYOUT-1),))
            invalid_raw = reject('payout_minus_one_fee_increase', lower,
                                 policy_witness(lower, leaf, control, 0))
            higher = replace(first, outputs=(replace(first.outputs[0], amount=PAYOUT+1),))
            reject('payout_plus_one_fee_decrease', higher, policy_witness(higher, leaf, control, 0))
            extra = replace(first, outputs=first.outputs+(Output(0, b'\x6a'),))
            reject('extra_output', extra, policy_witness(extra, leaf, control, 0))
            other, other_witness = policy_spend(funding_id, 1, 1)
            same_recipient_other_outpoint, _ = policy_spend(funding_id, 1, 0)
            reject('other_funded_outpoint_stale_commitment', same_recipient_other_outpoint, witness)
            wrong_value = replace(first, inputs=(replace(first.inputs[0], amount=AMOUNT+1),))
            reject('wrong_prevout_amount', first, policy_witness(wrong_value, leaf, control, 0))
            wrong_spk = replace(first, inputs=(replace(first.inputs[0], script=initial_spk),))
            reject('wrong_prevout_script', first, policy_witness(wrong_spk, leaf, control, 0))
            extra_input = Input(bytes.fromhex(funding_id)[::-1], 3, AMOUNT, initial_spk)
            reject('added_input_stale_commitment', replace(first, inputs=first.inputs+(extra_input,)),
                   witness, [[initial_leaf.script, initial_control]])
            reject('sequence_stale_commitment',
                   replace(first, inputs=(replace(first.inputs[0], sequence=0xfffffffe),)), witness)
            reject('version_stale_commitment', replace(first, version=1), witness)
            reject('locktime_stale_commitment', replace(first, locktime=1), witness)
            for name, position, value in (
                ('wrong_membership_sibling', 4, bytes(32)),
                ('wrong_membership_direction', 5, b'\x01'),
                ('nonminimal_membership_direction', 5, b'\x02'),
                ('short_transcript_prefix', 0, witness[0][1:]),
                ('long_transcript_prefix', 0, witness[0]+b'\x00'),
                ('short_transcript_suffix', 2, witness[2][1:]),
                ('long_transcript_suffix', 2, witness[2]+b'\x00'),
                ('wrong_key_version', 2, witness[2][:-5]+b'\x00'+witness[2][-4:]),
                ('wrong_codesep', 2, witness[2][:-4]+bytes(4)),
                ('oversized_witness_element', 0, bytes(521)),
                ('changed_tapleaf', -2, witness[-2][:-1]+b'\x00'),
                ('changed_control_parity', -1, bytes([control[0]^1])+control[1:]),
                ('changed_control_internal_key', -1, control[:1]+RECIPIENTS[0]),
            ):
                changed = witness.copy()
                changed[position] = value
                reject(name, first, changed)
            annex = b'\x50keyless-annex'
            reject('annex_with_stale_commitment', first, witness+[annex])
            reject('annex_excluded_by_policy_width', first,
                   policy_witness(first, leaf, control, 0, annex=annex)+[annex])
            try:
                rpc('generateblock', [mining_address, [invalid_raw]])
            except RpcError as error:
                report['invalid_block_attempt'] = error.error
            else:
                raise ValueError('invalid payout block accepted')
            require(rpc('getblockcount') == 102, 'invalid block changed chain height')
            report['invalid_block_preserved_height'] = True
            require(rpc('getconnectioncount') == 0, 'fixture node connected to a peer')
            other_raw, other_id = other.serialize([other_witness])
            require(rpc('testmempoolaccept', [[other_raw]])[0]['allowed'] is True,
                    'new commitment for second reserve rejected')
            require(rpc('sendrawtransaction', [first_raw]) == first_id, 'first payout txid mismatch')
            require(rpc('sendrawtransaction', [other_raw]) == other_id, 'second payout txid mismatch')
            payout_block = rpc('generatetoaddress', [1, mining_address])[0]
            confirmed = rpc('getblock', [payout_block])['tx']
            payouts = []
            for index, (tx, txid) in enumerate(((first, first_id), (other, other_id))):
                require(txid in confirmed, 'payout did not confirm')
                require(rpc('gettxout', [funding_id, index]) is None, 'reserve input is unspent')
                actual = rpc('gettxout', [txid, 0])
                require(actual is not None and satoshis(actual['value']) == PAYOUT,
                        'incorrect confirmed payout amount')
                require(actual['scriptPubKey']['hex'] == tx.outputs[0].script.hex(),
                        'incorrect confirmed recipient')
                payouts.append({'funding_vout': index, 'recipient_index': index, 'txid': txid,
                                'amount_sats': PAYOUT, 'script_pubkey': tx.outputs[0].script.hex(),
                                'block': payout_block})
            require(rpc('getblockcount') == 103, 'unexpected payout height')
            reject('already_spent_input', alternative, alternative_witness)
            node.stop()
            require(node.start()['blocks'] == 103, 'restart lost confirmed height')
            for index, payout in enumerate(payouts):
                require(rpc('gettxout', [funding_id, index]) is None, 'restart restored spent reserve')
                actual = rpc('gettxout', [payout['txid'], 0])
                require(actual is not None and satoshis(actual['value']) == PAYOUT,
                        'restart lost payout value')
                require(actual['scriptPubKey']['hex'] == payout['script_pubkey'],
                        'restart changed payout recipient')
            require(rpc('gettxout', [funding_id, 2]) is not None, 'restart lost unspent reserve')
            peers = rpc('getconnectioncount')
            require(peers == 0, 'fixture node has a peer after restart')
            report.update(status='passed', peer_count=peers, funding_txid=funding_id,
                          funding_height=102, payout_height=103, funding_sats=AMOUNT,
                          payout_sats=PAYOUT, fee_sats=FEE, payouts=payouts,
                          script_hex=leaf.script.hex(), control_hex=control.hex(),
                          script_bytes=len(leaf.script), rejection_count=len(report['rejected']),
                          restart_preserved_outputs=True, script_signatures=0,
                          policy_rejection_cases=sorted(POLICY_REJECTIONS))
        except BaseException as error:
            report.update(status='failed', error=f'{type(error).__name__}: {error}')
            raise
        finally:
            try:
                node.stop()
            except BaseException as error:
                report.update(status='failed', error=f'{type(error).__name__}: {error}')
                raise
            finally:
                node.log.close()
                report['node_exit_codes'] = node.exit_codes
                report_path.write_text(json.dumps(report, indent=2)+'\n')
                report_path.with_suffix('.node.log').write_bytes((root/'node.log').read_bytes())
    print(json.dumps(report, indent=2))
    return report


def main():
    require_assertions()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    run(args.binary, args.report)


if __name__ == '__main__':
    main()
