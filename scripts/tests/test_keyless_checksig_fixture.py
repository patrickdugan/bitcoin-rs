"""Independent Script execution and official BIP341 checks for the regtest fixture.

Official vectors reuse crates/primitives/tests/vectors/bip341-wallet-test-vectors.json,
whose source is bitcoin/bips bip-0341/wallet-test-vectors.json.
"""
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/research'))
import keyless_checksig_rpc as fixture


def load_official_transaction(raw_hex, utxos):
    data = bytes.fromhex(raw_hex)
    position = 0

    def read(size):
        nonlocal position
        result = data[position:position+size]
        position += size
        if len(result) != size:
            raise ValueError('truncated external transaction')
        return result

    def integer():
        first = read(1)[0]
        return first if first < 253 else int.from_bytes(read({253: 2, 254: 4, 255: 8}[first]), 'little')

    version = int.from_bytes(read(4), 'little', signed=True)
    inputs = []
    for i in range(integer()):
        txid, vout = read(32), int.from_bytes(read(4), 'little')
        read(integer())
        sequence = int.from_bytes(read(4), 'little')
        inputs.append(fixture.Input(txid, vout, utxos[i]['amountSats'],
                                    bytes.fromhex(utxos[i]['scriptPubKey']), sequence))
    outputs = []
    for _ in range(integer()):
        amount = int.from_bytes(read(8), 'little')
        outputs.append(fixture.Output(amount, read(integer())))
    locktime = int.from_bytes(read(4), 'little')
    if position != len(data):
        raise ValueError('external transaction has trailing data')
    return fixture.Tx(tuple(inputs), tuple(outputs), version, locktime)


class ScriptFailure(ValueError):
    pass


def script_integer(value):
    if value == 0:
        return b''
    raw = value.to_bytes((value.bit_length()+7)//8, 'little')
    return raw + b'\x00' if raw[-1] & 0x80 else raw


def execute_policy(script, witness, actual_digest):
    stack, alt, conditions = list(witness), [], []
    if any(len(item) > 520 for item in stack):
        raise ScriptFailure('initial element limit')

    def pop():
        if not stack:
            raise ScriptFailure('stack underflow')
        return stack.pop()

    position = 0
    while position < len(script):
        opcode = script[position]
        position += 1
        literal = None
        if 1 <= opcode <= 75:
            literal = script[position:position+opcode]
            position += opcode
            if len(literal) != opcode:
                raise ScriptFailure('truncated push')
        enabled = all(conditions)
        if opcode == 0x63:
            value = pop() if enabled else b''
            if value not in (b'', b'\x01'):
                raise ScriptFailure('MINIMALIF')
            conditions.append(enabled and value == b'\x01')
            continue
        if opcode == 0x68:
            if not conditions:
                raise ScriptFailure('unbalanced ENDIF')
            conditions.pop()
            continue
        if not enabled:
            continue
        if literal is not None:
            stack.append(literal)
        elif opcode == 0:
            stack.append(b'')
        elif 0x51 <= opcode <= 0x60:
            stack.append(bytes([opcode-0x50]))
        elif opcode == 0x6b:
            alt.append(pop())
        elif opcode == 0x6c:
            if not alt:
                raise ScriptFailure('altstack underflow')
            stack.append(alt.pop())
        elif opcode == 0x76:
            value = pop()
            stack.extend((value, value))
        elif opcode == 0x7b:
            if len(stack) < 3:
                raise ScriptFailure('ROT underflow')
            stack.append(stack.pop(-3))
        elif opcode == 0x7c:
            right, left = pop(), pop()
            stack.extend((right, left))
        elif opcode == 0x7e:
            right, left = pop(), pop()
            stack.append(left+right)
        elif opcode == 0x82:
            if not stack:
                raise ScriptFailure('SIZE underflow')
            stack.append(script_integer(len(stack[-1])))
        elif opcode == 0x88:
            if pop() != pop():
                raise ScriptFailure('EQUALVERIFY')
        elif opcode == 0xa8:
            stack.append(hashlib.sha256(pop()).digest())
        elif opcode == 0xad:
            key, candidate = pop(), pop()
            expected_key = b'\x02'+hashlib.sha256(b'BIPSpace/Keyless-CHECKSIG/TXCOMMIT-draft').digest()
            if key != expected_key or len(candidate) != 32 or candidate != actual_digest:
                raise ScriptFailure('TXCOMMIT')
        else:
            raise ScriptFailure(f'unsupported fixture opcode {opcode}')
        if len(stack)+len(alt) > 1000 or any(len(item) > 520 for item in stack+alt):
            raise ScriptFailure('stack limit')
    if stack != [b'\x01'] or alt or conditions:
        raise ScriptFailure('cleanstack')
    return True


class OfficialBIP341Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vectors = json.loads((ROOT / 'crates/primitives/tests/vectors/'
                                 'bip341-wallet-test-vectors.json').read_text())

    def test_all_official_keypath_sighash_modes(self):
        for group in self.vectors['keyPathSpending']:
            given = group['given']
            tx = load_official_transaction(given['rawUnsignedTx'], given['utxosSpent'])
            for case in group['inputSpending']:
                values = case['given']
                index, mode = values['txinIndex'], values['hashType']
                with self.subTest(index=index, hash_type=mode):
                    actual = fixture.sigmsg(tx, index, hash_type=mode, ext_flag=0)
                    self.assertEqual(actual.hex(), case['intermediary']['sigMsg'])
                    self.assertEqual(fixture.sighash(tx, index, hash_type=mode, ext_flag=0).hex(),
                                     case['intermediary']['sigHash'])

    def test_all_official_taproot_output_tweaks(self):
        for case in self.vectors['scriptPubKey']:
            internal = bytes.fromhex(case['given']['internalPubkey'])
            root = bytes.fromhex(case['intermediary']['merkleRoot'] or '')
            with self.subTest(internal=internal.hex()):
                key, _ = fixture.tweaked_key(internal, root)
                self.assertEqual((b'\x51\x20'+key).hex(), case['expected']['scriptPubKey'])


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.tx, self.witness = fixture.policy_spend('01'*32, 0, 0)
        self.leaf = fixture.Leaf(self.witness[-2])
        self.control = self.witness[-1]

    def execute(self, tx=None, witness=None, annex=None):
        tx = self.tx if tx is None else tx
        witness = self.witness if witness is None else witness
        digest = fixture.sighash(tx, 0, leaf=fixture.tapleaf(self.leaf.script), annex=annex)
        return execute_policy(self.leaf.script, witness[:-2], digest)

    def test_both_recipient_openings_authorize_the_same_funded_outpoint(self):
        self.assertTrue(self.execute())
        self.assertLessEqual(max(len(item) for item in self.witness[:-2]), 80)
        other, witness = fixture.policy_spend('01'*32, 0, 1)
        self.assertEqual(self.tx.inputs, other.inputs)
        self.assertNotEqual(self.tx.outputs, other.outputs)
        self.assertTrue(self.execute(other, witness))
        with self.assertRaises(ScriptFailure):
            self.execute(other)

    def test_payout_amount_and_complete_output_vector_are_constrained(self):
        for outputs in (
            (fixture.Output(97999, self.tx.outputs[0].script),),
            (fixture.Output(98001, self.tx.outputs[0].script),),
            self.tx.outputs+(fixture.Output(0, b'\x6a'),),
            (fixture.Output(98000, b'\x51\x20'+fixture.NUMS_X),),
        ):
            tx = replace(self.tx, outputs=outputs)
            witness = fixture.policy_witness(tx, self.leaf, self.control, 0)
            with self.subTest(outputs=outputs), self.assertRaises(ScriptFailure):
                self.execute(tx, witness)

    def test_unlisted_key_cannot_supply_a_membership_opening(self):
        tx = replace(self.tx, outputs=(fixture.Output(98000, b'\x51\x20'+fixture.NUMS_X),))
        witness = fixture.policy_witness(tx, self.leaf, self.control, 0)
        witness[3] = fixture.NUMS_X
        with self.assertRaises(ScriptFailure):
            self.execute(tx, witness)

    def test_new_context_requires_new_commitment_and_can_be_rebuilt_publicly(self):
        input_changes = ({'txid': bytes.fromhex('02'*32)}, {'index': 1},
                         {'amount': 100001}, {'sequence': 0xfffffffe})
        transactions = [replace(self.tx, inputs=(replace(self.tx.inputs[0], **change),))
                        for change in input_changes]
        transactions += [replace(self.tx, version=3), replace(self.tx, locktime=1)]
        for tx in transactions:
            with self.subTest(tx=tx):
                with self.assertRaises(ScriptFailure):
                    self.execute(tx)
                rebuilt = fixture.policy_witness(tx, self.leaf, self.control, 0)
                self.assertTrue(self.execute(tx, rebuilt))

    def test_context_widths_are_checked_before_digest_comparison(self):
        for position in (0, 1, 2):
            for value in (b'', self.witness[position][1:], self.witness[position]+b'\x00'):
                changed = self.witness.copy()
                changed[position] = value
                with self.subTest(position=position, length=len(value)):
                    with self.assertRaisesRegex(ScriptFailure, 'EQUALVERIFY'):
                        self.execute(witness=changed)

    def test_membership_path_and_minimalif_cannot_be_substituted(self):
        for position, value in ((4, bytes(32)), (5, b'\x01'), (5, b'\x02'), (5, b'\x80')):
            changed = self.witness.copy()
            changed[position] = value
            with self.subTest(position=position, value=value), self.assertRaises(ScriptFailure):
                self.execute(witness=changed)

    def test_scriptpath_transcript_uses_exact_fields_and_domains(self):
        message = fixture.sigmsg(self.tx, 0, leaf=fixture.tapleaf(self.leaf.script))
        self.assertEqual(len(message), 212)
        self.assertEqual(message[:10], b'\x00\x00\x02\x00\x00\x00'+bytes(4))
        self.assertEqual(message[138:170], hashlib.sha256(self.tx.outputs[0].serialize()).digest())
        self.assertEqual(message[170:175], b'\x02'+bytes(4))
        self.assertEqual(message[-5:], b'\x02\xff\xff\xff\xff')
        for options in ({'key_version': 0}, {'key_version': 1}, {'codesep': 0}):
            changed = fixture.sigmsg(self.tx, 0, leaf=fixture.tapleaf(self.leaf.script), **options)
            witness = self.witness.copy()
            witness[2] = changed[170:]
            with self.subTest(options=options), self.assertRaises(ScriptFailure):
                self.execute(witness=witness)

    def test_annex_commitment_is_supported_but_policy_requires_no_annex(self):
        annex = b'\x50bound-annex'
        message = fixture.sigmsg(self.tx, 0, leaf=fixture.tapleaf(self.leaf.script), annex=annex)
        self.assertEqual(len(message), 244)
        self.assertEqual(message[170], 3)
        self.assertEqual(message[175:207], hashlib.sha256(bytes([len(annex)])+annex).digest())
        with self.assertRaises(ScriptFailure):
            self.execute(annex=annex)
        witness = fixture.policy_witness(self.tx, self.leaf, self.control, 0, annex=annex)
        with self.assertRaisesRegex(ScriptFailure, 'EQUALVERIFY'):
            self.execute(witness=witness, annex=annex)

    def test_transaction_identifier_excludes_witness(self):
        left, txid = self.tx.serialize([self.witness])
        changed = self.witness.copy()
        changed[0] = bytes(74)
        right, alternate_id = self.tx.serialize([changed])
        self.assertNotEqual(left, right)
        self.assertEqual(txid, alternate_id)

    def test_invalid_sighash_context_refuses(self):
        for options in ({'hash_type': 0x40}, {'ext_flag': 2}, {'annex': b'\x51'},
                        {'key_version': 256}, {'codesep': 2**32}):
            with self.subTest(options=options), self.assertRaises(ValueError):
                fixture.sigmsg(self.tx, 0, leaf=fixture.tapleaf(self.leaf.script), **options)
        with self.assertRaises(ValueError):
            fixture.sigmsg(self.tx, 1, leaf=fixture.tapleaf(self.leaf.script))


class FixtureRuntimeTests(unittest.TestCase):
    def test_node_shutdown_requires_zero_exit_status(self):
        for status in (0, 7):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as directory:
                node = fixture.Node(Path(sys.executable), Path(directory))
                node.process = subprocess.Popen([sys.executable, '-c', f'raise SystemExit({status})'])
                node.process.wait(timeout=10)
                try:
                    if status:
                        with self.assertRaises(ValueError):
                            node.stop()
                    else:
                        node.stop()
                    self.assertIsNone(node.process)
                finally:
                    node.stop()
                    node.log.close()

    def test_optimized_python_refuses_before_starting_a_node(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / 'receipt.json'
            result = subprocess.run([sys.executable, '-O', str(Path(fixture.__file__)),
                                     '/no/such/node', '--report', str(report)],
                                    text=True, capture_output=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('assertions enabled', result.stderr)
            self.assertFalse(report.exists())

    def test_node_child_gets_explicit_isolated_full_validation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / 'fake-node'
            source = textwrap.dedent('''\
                import json, os, signal, sys
                from http.server import BaseHTTPRequestHandler, HTTPServer
                from pathlib import Path
                args = sys.argv[1:]
                opts = {}
                i = 0
                while i < len(args):
                    if '=' in args[i]:
                        key, value = args[i].split('=', 1)
                        opts[key] = value
                        i += 1
                    else:
                        opts[args[i]] = args[i+1]
                        i += 2
                Path('observed.json').write_text(json.dumps({'options': opts,
                    'environment': {key: value for key, value in os.environ.items()
                                    if key.startswith('BITCOIN_RS_')}}))
                class Handler(BaseHTTPRequestHandler):
                    def log_message(self, *args):
                        pass
                    def do_POST(self):
                        body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                        result = {'chain': 'regtest', 'blocks': 0} if body['method'] == 'getblockchaininfo' else 0
                        data = json.dumps({'result': result, 'error': None, 'id': 1}).encode()
                        self.send_response(200)
                        self.send_header('Content-Length', str(len(data)))
                        self.end_headers()
                        self.wfile.write(data)
                host, port = opts['--rpc-bind'].split(':')
                signal.signal(signal.SIGTERM, lambda signum, frame: sys.exit(0))
                HTTPServer((host, int(port)), Handler).serve_forever()
                ''')
            binary.write_text('#!'+sys.executable+'\n'+source)
            binary.chmod(0o700)
            hostile = {'BITCOIN_RS_NETWORK': 'mainnet', 'BITCOIN_RS_CONNECT': '203.0.113.1:8333',
                       'BITCOIN_RS_VALIDATION_MODE': 'assume-valid',
                       'HTTP_PROXY': 'http://127.0.0.1:1', 'http_proxy': 'http://127.0.0.1:1',
                       'NO_PROXY': '', 'no_proxy': ''}
            with patch.dict(os.environ, hostile):
                node = fixture.Node(binary, root)
                try:
                    self.assertEqual(node.start()['blocks'], 0)
                    observed = json.loads((root/'observed.json').read_text())
                    self.assertEqual(observed['environment'], {})
                    options = observed['options']
                    self.assertEqual(options['--network'], 'regtest')
                    self.assertEqual(options['--validation-mode'], 'full')
                    self.assertEqual(options['--validation-engine'], 'native')
                    self.assertEqual(options['--storage-backend'], 'fjall')
                    self.assertEqual(options['--dns-seeds-enabled'], 'false')
                    self.assertEqual(options['--rpc-bind'].split(':')[0], '127.0.0.1')
                    self.assertEqual(options['--p2p-listen'].split(':')[0], '127.0.0.1')
                    self.assertEqual(options['--data-dir'], str(root/'data'))
                finally:
                    node.stop()
                    node.log.close()


if __name__ == '__main__':
    unittest.main()
