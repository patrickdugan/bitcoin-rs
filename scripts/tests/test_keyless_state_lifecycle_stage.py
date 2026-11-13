import copy
import hashlib
from pathlib import Path
import struct
import sys
import unittest

RESEARCH = Path(__file__).resolve().parents[1] / 'research'
sys.path.insert(0, str(RESEARCH))
import keyless_checksig_rpc as wire
import keyless_checksig_stage as stage
import keyless_checksig_testnet4 as block_wire
import keyless_state_machine as machine


PIN = 'a7' * 32
PROGRAM = hashlib.sha256(b'BIPSpace/Keyless-CHECKSIG/F17/full-trace/v1').digest()


def hash256(value):
    return hashlib.sha256(hashlib.sha256(value).digest()).digest()


def compact(value):
    if value < 253:
        return bytes([value])
    if value <= 0xffff:
        return b'\xfd' + struct.pack('<H', value)
    return b'\xfe' + struct.pack('<I', value)


def terminal_commitment(state):
    tag = hashlib.sha256(b'BIPSpace/Keyless-CHECKSIG/F17/state/v1').digest()
    return hashlib.sha256(tag + tag + PROGRAM + bytes(4) + bytes([state])).digest()


def number(value):
    return bytes([value]) if value else b''


def build_block(raw, txid, previous, height, payout_script, timestamp=None):
    transaction = bytes.fromhex(raw)
    reserved = bytes(32)
    witness_root = hash256(bytes(32) + hash256(transaction))
    commitment = b'\x6a\x24\xaa\x21\xa9\xed' + hash256(witness_root + reserved)
    script_sig = b'\x01' + bytes([height])
    inputs = b'\x01' + bytes(32) + b'\xff' * 4 + compact(len(script_sig)) + script_sig + b'\xff' * 4
    outputs = (b'\x02' + struct.pack('<Q', 5_000_002_000) + compact(len(payout_script)) + payout_script
               + bytes(8) + compact(len(commitment)) + commitment)
    stripped = struct.pack('<I', 2) + inputs + outputs + bytes(4)
    coinbase = struct.pack('<I', 2) + b'\x00\x01' + inputs + outputs + b'\x01\x20' + reserved + bytes(4)
    coinbase_id = hash256(stripped)[::-1].hex()
    merkle = hash256(hash256(stripped) + bytes.fromhex(txid)[::-1])
    prefix = (struct.pack('<I', 0x20000000) + bytes.fromhex(previous)[::-1] + merkle
              + struct.pack('<II', 1_700_000_000 + height if timestamp is None else timestamp, 0x207fffff))
    target = 0x7fffff << (8 * 29)
    for nonce in range(1000):
        header = prefix + struct.pack('<I', nonce)
        digest = hash256(header)
        if int.from_bytes(digest, 'little') <= target:
            block_raw = header + b'\x02' + coinbase + transaction
            return {'hash': digest[::-1].hex(), 'hex': block_raw.hex(), 'height': height,
                    'previous': previous, 'txids': [coinbase_id, txid],
                    'coinbase_txid': coinbase_id, 'coinbase_raw': coinbase.hex()}
    raise AssertionError('regtest reference block was not solved')


def describe_input(item):
    return {'txid': item.txid[::-1].hex(), 'vout': item.index, 'amount_sats': item.amount,
            'script_pubkey': item.script.hex(), 'sequence': item.sequence}


def describe_outputs(outputs, roles=None):
    result = [{'amount_sats': item.amount, 'script_pubkey': item.script.hex()} for item in outputs]
    if roles is not None:
        for value, role in zip(result, roles):
            value['role'] = role
    return result


def reference_transactions():
    compiled = machine.compile_machine()
    leaves = {3: compiled.leaf, 9: compiled.branch(9).successor.leaf,
              12: compiled.branch(12).successor.leaf}
    keys = {old: leaf.output() for old, leaf in leaves.items()}
    bare_leaf = wire.Leaf(b'\x51')
    bare_spk, bare_control = bare_leaf.output()
    funding = wire.Tx((wire.Input(bytes.fromhex('11' * 32), 0, 5_000_000_000, bare_spk),),
                      (wire.Output(100_000, keys[3][0]), wire.Output(4_999_898_000, bare_spk)))

    def pack(tx, witness, **fields):
        raw, txid = tx.serialize([witness])
        return {'tx': tx, 'witness': witness, 'raw_tx': raw, 'txid': txid,
                'wtxid': hash256(bytes.fromhex(raw))[::-1].hex(), **fields}

    result = {'funding': pack(funding, [bare_leaf.script, bare_control])}
    amounts = {3: 100_000, 9: 89_000, 12: 86_000}
    for name, old, delta, source, vout, value, final, recipient, path, index in (
        ('a_parent', 3, 2, 'funding', 0, 9_000, 9, 0, (2, 2), 0),
        ('a_child', 9, 2, 'a_parent', 1, 87_000, 15, 0, (2, 2), 1),
        ('b_parent', 3, 3, 'funding', 0, 12_000, 12, 1, (3, 2), 0),
        ('b_child', 12, 2, 'b_parent', 1, 84_000, 1, 1, (3, 2), 1),
    ):
        rows = tuple((old + i * delta) % 17 for i in range(4))
        if rows[-1] != final:
            raise AssertionError('the reference trace and independently specified result disagree')
        source_id = result[source]['txid']
        item = wire.Input(bytes.fromhex(source_id)[::-1], vout, amounts[old], keys[old][0])
        payout = wire.Output(value, b'\x51\x20' + wire.RECIPIENTS[recipient])
        second = (wire.Output({9: 89_000, 12: 86_000}[final], keys[final][0]) if index == 0
                  else wire.Output(0, b'\x6a\x20' + terminal_commitment(final)))
        tx = wire.Tx((item,), (payout, second))
        script = leaves[old].script
        witness = [PROGRAM, item.txid + struct.pack('<I', item.index), item.script[2:],
                   wire.tapleaf(script), number(delta), *(number(row) for row in rows),
                   script, keys[old][1]]
        result[name] = pack(tx, witness, old_state=old, new_state=final, trace=list(rows),
                            delta=delta, path=list(path), stage=index)
    return result, bare_spk


def virtual_size(item):
    return ((len(item['tx'].body()) + 8) * 3 + len(bytes.fromhex(item['raw_tx'])) + 3) // 4


def admission_row(item):
    size = virtual_size(item)
    return {'allowed': True, 'txid': item['txid'], 'wtxid': item['wtxid'], 'vsize': size,
            'fees': {'base': 0.00002, 'effective-feerate': int(2_000_000 / size) / 100_000_000,
                     'effective-includes': [item['wtxid']]}}


def block_record(item, previous, height, payout_script, timestamp=None):
    block = build_block(item['raw_tx'], item['txid'], previous, height, payout_script, timestamp)
    return {'hash': block['hash'], 'raw_block': block['hex'], 'previous': previous,
            'height': height, 'txids': block['txids'],
            'coinbase': {'txid': block['coinbase_txid'], 'vout': 0,
                         'amount_sats': 5_000_002_000, 'script_pubkey': payout_script.hex()}}


def complete_receipt():
    txs, bare_spk = reference_transactions()
    blocks = {'funding': block_record(txs['funding'], '22' * 32, 102, bare_spk)}
    for name, previous, height, recipient in (
        ('a_parent', 'funding', 103, 0), ('a_child', 'a_parent', 104, 0),
        ('b_parent', 'funding', 103, 1), ('b_child', 'b_parent', 104, 1),
    ):
        blocks[name] = block_record(txs[name], blocks[previous]['hash'], height,
                                    b'\x51\x20' + wire.RECIPIENTS[recipient])
    funding = txs['funding']
    report = {'schema_version': 1, 'fixture': 'keyless-state-lifecycle', 'status': 'passed',
              'binary_sha256': PIN, 'network': 'regtest', 'program_id': PROGRAM.hex(),
              'started_at': '2026-01-01T00:00:00+00:00',
              'finished_at': '2026-01-01T00:01:00+00:00',
              'scope': 'Controlled invalidation and branch rebuilding on isolated native regtest.',
              'funding': {'raw_tx': funding['raw_tx'], 'txid': funding['txid'],
                  'wtxid': funding['wtxid'], 'input': describe_input(funding['tx'].inputs[0]),
                  'witness_hex': [value.hex() for value in funding['witness']],
                  'outputs': describe_outputs(funding['tx'].outputs, ('root', 'change')),
                  'fee_sats': 2_000, 'admission': admission_row(funding),
                  'block': blocks['funding']['hash'], 'height': 102},
              'transactions': {}, 'blocks': blocks, 'candidate_b': copy.deepcopy(blocks['b_parent']),
              'admissions': {}, 'rejected': {}, 'snapshots': {}, 'operations': {},
              'restart_checks': [], 'coinbase_checks': {}, 'script_signatures': 0,
              'final_height': 104, 'final_tip': blocks['b_child']['hash'], 'final_state': 1,
              'active_family': 'b', 'confirmed_transitions': 4, 'rewind_depth': 2,
              'peer_count': 0, 'rejection_count': 5, 'restart_preserved_state': True,
              'node_exit_codes': [0, 0, 0, 0], 'clean_shutdowns': True}
    for name in ('a_parent', 'a_child', 'b_parent', 'b_child'):
        item = txs[name]
        terminal = name.endswith('child')
        report['transactions'][name] = {
            key: copy.deepcopy(item[key])
            for key in ('path', 'stage', 'old_state', 'new_state', 'trace', 'delta',
                        'raw_tx', 'txid', 'wtxid')}
        report['transactions'][name].update(
            program_id=PROGRAM.hex(), input=describe_input(item['tx'].inputs[0]),
            outputs=describe_outputs(item['tx'].outputs,
                                     ('payout', 'state_commitment' if terminal else 'successor')),
            fee_sats=2_000, witness_hex=[value.hex() for value in item['witness']],
            script_hex=item['witness'][-2].hex(), control_hex=item['witness'][-1].hex(),
            block=blocks[name]['hash'], confirmed_height=104 if terminal else 103,
            observed_input_sats=item['tx'].inputs[0].amount,
            observed_outputs=describe_outputs(item['tx'].outputs), observed_fee_sats=2_000)

    coin_specs = {
        'root': (100_000, funding['tx'].outputs[0].script),
        'change': (4_999_898_000, bare_spk),
        'a_payout': (9_000, b'\x51\x20' + wire.RECIPIENTS[0]),
        'a_successor': (89_000, txs['a_parent']['tx'].outputs[1].script),
        'a_terminal': (87_000, b'\x51\x20' + wire.RECIPIENTS[0]),
        'a_commitment': (0, b'\x6a\x20' + terminal_commitment(15)),
        'b_payout': (12_000, b'\x51\x20' + wire.RECIPIENTS[1]),
        'b_successor': (86_000, txs['b_parent']['tx'].outputs[1].script),
        'b_terminal': (84_000, b'\x51\x20' + wire.RECIPIENTS[1]),
        'b_commitment': (0, b'\x6a\x20' + terminal_commitment(1)),
    }
    funded = {'root': 102, 'change': 102}
    parent_a = {'change': 102, 'a_payout': 103, 'a_successor': 103}
    final_a = {'change': 102, 'a_payout': 103, 'a_terminal': 104}
    parent_b = {'change': 102, 'b_payout': 103, 'b_successor': 103}
    final_b = {'change': 102, 'b_payout': 103, 'b_terminal': 104}
    pending_parent_a = {'change': 102, 'a_payout': None, 'a_successor': None}
    pending_family_a = {'change': 102, 'a_payout': None, 'a_terminal': None, 'a_commitment': None}
    pending_child_a = {'change': 102, 'a_payout': 103, 'a_terminal': None, 'a_commitment': None}
    pending_child_b = {'change': 102, 'b_payout': 103, 'b_terminal': None, 'b_commitment': None}
    phases = (
        ('funded', 'funding', 102, 2, (), funded, funded),
        ('candidate_b_prepared', 'funding', 102, 2, (), funded, funded),
        ('a_parent_pending', 'funding', 102, 3, ('a_parent',), funded, pending_parent_a),
        ('a_family_pending', 'funding', 102, 4, ('a_parent', 'a_child'), funded, pending_family_a),
        ('a_parent_confirmed', 'a_parent', 103, 5, ('a_child',), parent_a, pending_child_a),
        ('a_family_confirmed', 'a_child', 104, 6, (), final_a, final_a),
        ('a_confirmed_restarted', 'a_child', 104, 0, (), final_a, final_a),
        ('rewound', 'funding', 102, 2, ('a_parent', 'a_child'), funded, pending_family_a),
        ('rewound_restarted', 'funding', 102, 2, ('a_parent', 'a_child'), funded, pending_family_a),
        ('b_parent_confirmed', 'b_parent', 103, 4, (), parent_b, parent_b),
        ('b_child_pending', 'b_parent', 103, 5, ('b_child',), parent_b, pending_child_b),
        ('b_family_confirmed', 'b_child', 104, 6, (), final_b, final_b),
        ('b_confirmed_restarted', 'b_child', 104, 0, (), final_b, final_b),
    )
    for name, block_name, height, sequence, pending, chain, overlay in phases:
        tip = blocks[block_name]['hash']
        snapshot = {'height': height, 'bestblock': tip, 'height_hash': tip, 'peer_count': 0,
                    'is_apply_halted': False, 'is_closed_for_recovery': False,
                    'mempool': {'txids': sorted(txs[key]['txid'] for key in pending),
                                'mempool_sequence': sequence}, 'entries': {}, 'coins': {}}
        for label, (amount, script) in coin_specs.items():
            snapshot['coins'][label] = {}
            for view, ledger in (('chain', chain), ('overlay', overlay)):
                snapshot['coins'][label][view] = (None if label not in ledger else
                    {'amount_sats': amount, 'script_pubkey': script.hex(),
                     'confirmations': 0 if ledger[label] is None else height - ledger[label] + 1,
                     'coinbase': False, 'bestblock': tip})
        for transaction in pending:
            item = txs[transaction]
            family, kind = transaction.split('_')
            parent, child = family + '_parent', family + '_child'
            ancestors = [transaction] + ([parent] if kind == 'child' and parent in pending else [])
            descendants = [transaction] + ([child] if kind == 'parent' and child in pending else [])
            snapshot['entries'][item['txid']] = {
                'depends': [txs[key]['txid'] for key in ancestors[1:]],
                'spentby': [txs[key]['txid'] for key in descendants[1:]],
                'ancestorcount': len(ancestors), 'descendantcount': len(descendants),
                'ancestorsize': sum(virtual_size(txs[key]) for key in ancestors),
                'descendantsize': sum(virtual_size(txs[key]) for key in descendants),
                'vsize': virtual_size(item), 'wtxid': item['wtxid'],
                'fees_sats': {'base': 2_000, 'modified': 2_000, 'chunk': 2_000,
                              'ancestor': 2_000 * len(ancestors),
                              'descendant': 2_000 * len(descendants)}}
        report['snapshots'][name] = snapshot

    def snapshot(name):
        return copy.deepcopy(report['snapshots'][name])

    for name, phase in (('b_parent', 'funded'), ('a_parent', 'candidate_b_prepared'),
                        ('a_child', 'a_parent_pending'), ('b_child', 'b_parent_confirmed')):
        record = {'transaction': name, 'dry_run': admission_row(txs[name]),
                  'before': snapshot(phase), 'after_preview': snapshot(phase)}
        if name != 'b_parent':
            record['submitted_txid'] = txs[name]['txid']
        report['admissions'][name] = record

    for name, transaction, boundary, phase, reason in (
        ('child_without_parent', 'a_child', 'missing_inputs', 'funded', 'missing-inputs'),
        ('equal_fee_parent', 'b_parent', 'replacement_fee', 'a_parent_pending', 'insufficient fee'),
        ('conflict_with_child', 'b_parent', 'replacement_fee', 'a_family_pending', 'insufficient fee'),
        ('replayed_old_state', 'b_child', 'script', 'b_parent_confirmed', 'script-verify-flag-failed'),
        ('stale_a_child', 'a_child', 'missing_inputs', 'b_family_confirmed', 'missing-inputs'),
    ):
        item = txs[transaction]
        witness = list(item['witness'])
        rows, delta = item['trace'], item['delta']
        if name == 'replayed_old_state':
            rows, delta = [9, 12, 15, 1], 3
            witness[4:9] = [number(delta)] + [number(row) for row in rows]
        raw, txid = item['tx'].serialize([witness])
        wtxid = hash256(bytes.fromhex(raw))[::-1].hex()
        record = {'transaction': transaction, 'boundary': boundary, 'raw_tx': raw,
                  'txid': txid, 'wtxid': wtxid, 'witness_hex': [value.hex() for value in witness],
                  'trace': list(rows), 'delta': delta, 'before': snapshot(phase),
                  'after': snapshot(phase), 'dry_run': {'allowed': False,
                      'reject-reason': reason, 'txid': txid, 'wtxid': wtxid}}
        if name != 'child_without_parent':
            code, message = {'replacement_fee': (-26, 'insufficient fee'),
                             'script': (-26, 'consensus-verification-failed'),
                             'missing_inputs': (-25, 'bad-txns-inputs-missingorspent')}[boundary]
            record['admission'] = {'code': code, 'message': message}
        if name in ('replayed_old_state', 'stale_a_child'):
            message = ('block-script-verify-flag-failed (script failed: NUMEQUALVERIFY)' if
                       name == 'replayed_old_state' else 'bad-txns-inputs-missingorspent')
            record['block_error'] = {'code': -25, 'message': 'TestBlockValidity failed: ' + message}
        report['rejected'][name] = record

    report['operations'] = {
        'stale_b_submit': {'raw_block': blocks['b_parent']['raw_block'],
                          'before': snapshot('a_confirmed_restarted'),
                          'result': 'inconclusive-not-best-prevblk',
                          'after': snapshot('a_confirmed_restarted')},
        'invalidate': {'block': blocks['a_parent']['hash'],
                       'before': snapshot('a_confirmed_restarted'), 'result': None,
                       'after': snapshot('rewound')},
        'submit_b': {'raw_block': blocks['b_parent']['raw_block'],
                     'before': snapshot('rewound_restarted'), 'result': None,
                     'after': snapshot('b_parent_confirmed')},
    }
    for before, after, block_name, height in (
        ('a_family_confirmed', 'a_confirmed_restarted', 'a_child', 104),
        ('rewound', 'rewound_restarted', 'funding', 102),
        ('b_family_confirmed', 'b_confirmed_restarted', 'b_child', 104),
    ):
        report['restart_checks'].append({'before': before, 'after': after, 'height': height,
                                         'bestblock': blocks[block_name]['hash'], 'preserved': True})
    for phase in ('rewound', 'rewound_restarted', 'b_family_confirmed', 'b_confirmed_restarted'):
        checks = {}
        for name in ('a_parent', 'a_child', 'b_parent') + (() if phase.startswith('rewound') else ('b_child',)):
            coin = None
            if phase.startswith('b_') and name.startswith('b_'):
                source = blocks[name]['coinbase']
                coin = {key: source[key] for key in ('amount_sats', 'script_pubkey')}
                coin.update(confirmations=2 if name == 'b_parent' else 1, coinbase=True,
                            bestblock=blocks['b_child']['hash'])
            checks[name] = {'chain': copy.deepcopy(coin), 'overlay': copy.deepcopy(coin)}
        report['coinbase_checks'][phase] = checks
    return report


class LifecycleReceiptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.receipt = complete_receipt()
        cls.transactions, cls.funding_script = reference_transactions()

    def validate(self, report):
        return stage.validate_fixture('state-lifecycle-regtest', report, PIN)

    def reject_change(self, path, value):
        report = copy.deepcopy(self.receipt)
        target = report
        for field in path[:-1]:
            target = target[field]
        target[path[-1]] = value
        with self.subTest(path=path, value=repr(value)[:80]), self.assertRaises(stage.EvidenceError):
            self.validate(report)

    def change_snapshot(self, report, name, path, value):
        changed = copy.deepcopy(report['snapshots'][name])
        target = changed
        for field in path[:-1]:
            target = target[field]
        target[path[-1]] = value
        report['snapshots'][name] = changed
        references = {
            'funded': (('admissions', 'b_parent', ('before', 'after_preview')),
                       ('rejected', 'child_without_parent', ('before', 'after'))),
            'candidate_b_prepared': (('admissions', 'a_parent', ('before', 'after_preview')),),
            'a_parent_pending': (('admissions', 'a_child', ('before', 'after_preview')),
                                 ('rejected', 'equal_fee_parent', ('before', 'after'))),
            'a_family_pending': (('rejected', 'conflict_with_child', ('before', 'after')),),
            'a_confirmed_restarted': (('operations', 'stale_b_submit', ('before', 'after')),
                                      ('operations', 'invalidate', ('before',))),
            'rewound': (('operations', 'invalidate', ('after',)),),
            'rewound_restarted': (('operations', 'submit_b', ('before',)),),
            'b_parent_confirmed': (('operations', 'submit_b', ('after',)),
                                   ('rejected', 'replayed_old_state', ('before', 'after')),
                                   ('admissions', 'b_child', ('before', 'after_preview'))),
            'b_family_confirmed': (('rejected', 'stale_a_child', ('before', 'after')),),
        }
        for section, label, fields in references.get(name, ()):
            for field in fields:
                report[section][label][field] = copy.deepcopy(changed)

    def reject_snapshot_change(self, name, path, value):
        report = copy.deepcopy(self.receipt)
        self.change_snapshot(report, name, path, value)
        with self.subTest(snapshot=name, path=path, value=repr(value)[:80]), self.assertRaises(stage.EvidenceError):
            self.validate(report)

    def rewrite_rejected_witness(self, report, name, witness):
        item = report['rejected'][name]
        tx = self.transactions[item['transaction']]['tx']
        raw, txid = tx.serialize([witness])
        wtxid = hash256(bytes.fromhex(raw))[::-1].hex()
        item.update(raw_tx=raw, txid=txid, wtxid=wtxid,
                    witness_hex=[part.hex() for part in witness])
        item['dry_run'].update(txid=txid, wtxid=wtxid)

    def test_complete_independent_receipt_is_accepted(self):
        result = self.validate(copy.deepcopy(self.receipt))
        self.assertEqual(result['confirmed_transitions'], 4)
        self.assertEqual(result['rejection_count'], 5)
        self.assertEqual(result['network'], 'regtest')
        self.assertTrue(result['restart_preserved_state'])

    def test_restart_reconstructs_sequence_while_preserving_state(self):
        report = copy.deepcopy(self.receipt)
        for name, sequence in (('a_confirmed_restarted', 40), ('rewound', 42),
                               ('rewound_restarted', 70), ('b_parent_confirmed', 72),
                               ('b_child_pending', 73), ('b_family_confirmed', 74),
                               ('b_confirmed_restarted', 90)):
            self.change_snapshot(report, name, ('mempool', 'mempool_sequence'), sequence)
        self.assertEqual(self.validate(report)['confirmed_transitions'], 4)

    def test_fixture_identity_and_completion_are_required(self):
        for field, value in (('schema_version', 2), ('fixture', 'keyless-state-machine'),
                             ('status', 'running'), ('binary_sha256', 'b8' * 32),
                             ('network', 'testnet4'), ('program_id', '00' * 32),
                             ('peer_count', 1), ('peer_count', False),
                             ('script_signatures', 1), ('final_height', 103),
                             ('final_state', 15), ('active_family', 'a'),
                             ('confirmed_transitions', 3), ('rewind_depth', 1),
                             ('rejection_count', 4), ('restart_preserved_state', False)):
            self.reject_change((field,), value)
        self.reject_change(('final_tip',), self.receipt['blocks']['a_child']['hash'])

    def test_missing_and_extra_lifecycle_evidence_is_rejected(self):
        for section, name in (('snapshots', 'candidate_b_prepared'), ('snapshots', 'rewound'),
                              ('transactions', 'b_child'), ('blocks', 'a_parent'),
                              ('admissions', 'b_parent'), ('rejected', 'conflict_with_child'),
                              ('operations', 'stale_b_submit'), ('coinbase_checks', 'rewound_restarted')):
            report = copy.deepcopy(self.receipt)
            del report[section][name]
            with self.subTest(section=section, missing=name), self.assertRaises(stage.EvidenceError):
                self.validate(report)
        for section in ('snapshots', 'transactions', 'blocks', 'admissions', 'rejected', 'operations'):
            self.reject_change((section, 'invented'), {})

    def test_malformed_nested_objects_have_evidence_errors(self):
        for path, value in ((('funding',), None), (('transactions', 'a_parent'), None),
                            (('blocks', 'funding', 'raw_block'), 'zz'),
                            (('blocks', 'b_child', 'raw_block'), '00'),
                            (('snapshots', 'rewound', 'coins'), None),
                            (('snapshots', 'a_parent_pending', 'mempool'), []),
                            (('admissions', 'b_parent', 'dry_run'), None),
                            (('rejected', 'replayed_old_state', 'witness_hex'), None),
                            (('operations', 'submit_b'), []), (('restart_checks',), None),
                            (('coinbase_checks', 'rewound'), []), (('node_exit_codes',), None)):
            self.reject_change(path, value)

    def test_same_height_fork_tip_and_recovery_flags_are_bound(self):
        for name, tip in (('a_parent_confirmed', self.receipt['blocks']['b_parent']['hash']),
                           ('b_family_confirmed', self.receipt['blocks']['a_child']['hash']),
                           ('rewound', '33' * 32)):
            for field in ('bestblock', 'height_hash'):
                self.reject_snapshot_change(name, (field,), tip)
        for field in ('is_apply_halted', 'is_closed_for_recovery'):
            self.reject_snapshot_change('rewound_restarted', (field,), True)
        self.reject_snapshot_change('a_parent_pending', ('peer_count',), 1)

    def test_rollback_restores_root_and_pending_family_masks_it(self):
        root = self.receipt['snapshots']['rewound']['coins']['root']['chain']
        for phase in ('rewound', 'rewound_restarted'):
            self.reject_snapshot_change(phase, ('coins', 'root', 'chain'), None)
            self.reject_snapshot_change(phase, ('coins', 'root', 'chain', 'amount_sats'), 98_000)
            self.reject_snapshot_change(phase, ('coins', 'root', 'overlay'), root)
            self.reject_snapshot_change(phase, ('coins', 'a_payout', 'overlay'), None)
            self.reject_snapshot_change(phase, ('coins', 'a_terminal', 'overlay'), None)

    def test_chain_and_overlay_coins_follow_each_applied_branch(self):
        ghost = self.receipt['snapshots']['a_family_confirmed']['coins']['a_terminal']['chain']
        for phase in ('b_parent_confirmed', 'b_family_confirmed', 'b_confirmed_restarted'):
            for view in ('chain', 'overlay'):
                self.reject_snapshot_change(phase, ('coins', 'a_terminal', view), ghost)
        for phase, label, amount in (('funded', 'root', 99_999),
                                      ('a_parent_confirmed', 'a_successor', 88_999),
                                      ('a_family_confirmed', 'a_terminal', 86_999),
                                      ('b_parent_confirmed', 'b_successor', 85_999),
                                      ('b_family_confirmed', 'b_terminal', 83_999)):
            self.reject_snapshot_change(phase, ('coins', label, 'chain', 'amount_sats'), amount)
        self.reject_snapshot_change('b_family_confirmed', ('coins', 'b_terminal', 'chain', 'confirmations'), 2)
        self.reject_snapshot_change('b_family_confirmed', ('coins', 'b_terminal', 'chain', 'coinbase'), True)
        self.reject_snapshot_change('a_parent_pending', ('coins', 'change', 'overlay'), None)

    def test_pending_commitment_visibility_matches_rpc_coin_views(self):
        for phase, label in (('a_family_pending', 'a_commitment'),
                             ('a_parent_confirmed', 'a_commitment'),
                             ('rewound', 'a_commitment'),
                             ('b_child_pending', 'b_commitment')):
            coin = self.receipt['snapshots'][phase]['coins'][label]['overlay']
            self.reject_snapshot_change(phase, ('coins', label, 'overlay'), None)
            self.reject_snapshot_change(phase, ('coins', label, 'chain'), coin)
        ghost = self.receipt['snapshots']['b_child_pending']['coins']['b_commitment']['overlay']
        self.reject_snapshot_change('b_family_confirmed', ('coins', 'b_commitment', 'overlay'), ghost)

    def test_mempool_membership_cannot_lose_or_retain_the_wrong_family(self):
        a_parent = self.receipt['transactions']['a_parent']['txid']
        a_child = self.receipt['transactions']['a_child']['txid']
        b_parent = self.receipt['transactions']['b_parent']['txid']
        for phase, ids in (('a_parent_pending', [b_parent]),
                            ('a_family_pending', [a_parent]), ('rewound', [a_child]),
                            ('rewound_restarted', []), ('b_parent_confirmed', [a_parent, a_child])):
            self.reject_snapshot_change(phase, ('mempool', 'txids'), sorted(ids))
        self.reject_snapshot_change('rewound', ('entries',), {})

    def test_resident_graph_sizes_fees_and_witness_are_verified(self):
        parent = self.receipt['transactions']['a_parent']['txid']
        child = self.receipt['transactions']['a_child']['txid']
        for txid, field, value in ((parent, 'spentby', []), (child, 'depends', []),
                                   (parent, 'ancestorcount', 2), (parent, 'descendantcount', 1),
                                   (child, 'ancestorsize', 1), (parent, 'descendantsize', 1),
                                   (parent, 'vsize', 1), (child, 'wtxid', '44' * 32)):
            self.reject_snapshot_change('rewound', ('entries', txid, field), value)
        for fee in ('base', 'modified', 'chunk', 'ancestor', 'descendant'):
            self.reject_snapshot_change('a_family_pending', ('entries', parent, 'fees_sats', fee), 1)

    def test_preview_rejection_and_block_preparation_preserve_sequence(self):
        for path in (('admissions', 'a_parent', 'after_preview'),
                     ('admissions', 'b_parent', 'after_preview'),
                     ('rejected', 'equal_fee_parent', 'after'),
                     ('rejected', 'replayed_old_state', 'after'),
                     ('operations', 'stale_b_submit', 'after')):
            self.reject_change(path + ('mempool', 'mempool_sequence'), 900)
        self.reject_snapshot_change('candidate_b_prepared', ('mempool', 'mempool_sequence'), 3)
        self.reject_snapshot_change('a_parent_confirmed', ('mempool', 'mempool_sequence'), 4)
        self.reject_snapshot_change('b_child_pending', ('mempool', 'mempool_sequence'), 6)

    def test_confirmed_transactions_bind_context_amounts_and_proofs(self):
        for name in ('a_parent', 'a_child', 'b_parent', 'b_child'):
            for field, value in (('txid', '44' * 32), ('wtxid', '55' * 32),
                                 ('raw_tx', '00'), ('fee_sats', 1), ('observed_fee_sats', 1),
                                 ('observed_input_sats', 1), ('new_state', 0)):
                self.reject_change(('transactions', name, field), value)
        for path, value in ((('transactions', 'b_parent', 'input', 'vout'), 1),
                            (('transactions', 'b_child', 'input', 'txid'),
                             self.receipt['transactions']['a_parent']['txid']),
                            (('transactions', 'a_child', 'input', 'amount_sats'), 89_001),
                            (('transactions', 'a_parent', 'outputs', 0, 'amount_sats'), 9_001),
                            (('transactions', 'b_child', 'observed_outputs', 0, 'amount_sats'), 84_001),
                            (('transactions', 'b_child', 'witness_hex', 1), '00' * 36),
                            (('transactions', 'a_parent', 'script_hex'), '51'),
                            (('transactions', 'b_parent', 'control_hex'), '00' * 33)):
            self.reject_change(path, value)

    def test_funding_preserves_one_root_and_exact_change(self):
        for path, value in ((('funding', 'outputs', 0, 'amount_sats'), 100_001),
                            (('funding', 'outputs', 1, 'amount_sats'), 4_999_897_999),
                            (('funding', 'fee_sats'), 2_001), (('funding', 'input', 'amount_sats'), 1),
                            (('funding', 'wtxid'), '77' * 32),
                            (('funding', 'admission', 'allowed'), False)):
            self.reject_change(path, value)

    def test_blocks_bind_raw_transactions_ancestry_and_coinbases(self):
        for path, value in ((('blocks', 'a_child', 'previous'), self.receipt['blocks']['b_parent']['hash']),
                            (('blocks', 'b_parent', 'hash'), self.receipt['blocks']['a_parent']['hash']),
                            (('blocks', 'a_child', 'height'), 103),
                            (('blocks', 'funding', 'txids'), []),
                            (('blocks', 'b_child', 'coinbase', 'amount_sats'), 5_000_002_001),
                            (('blocks', 'a_parent', 'coinbase', 'script_pubkey'),
                             self.receipt['blocks']['b_parent']['coinbase']['script_pubkey'])):
            self.reject_change(path, value)
        for name in ('funding', 'a_parent', 'a_child', 'b_parent', 'b_child'):
            raw = self.receipt['blocks'][name]['raw_block']
            self.reject_change(('blocks', name, 'raw_block'), raw[:-2] + ('01' if raw[-2:] == '00' else '00'))

    def test_saved_candidate_must_be_the_exact_block_later_submitted(self):
        previous = self.receipt['blocks']['funding']['hash']
        alternative = block_record(self.transactions['b_parent'], previous, 103,
                                   b'\x51\x20' + wire.RECIPIENTS[1], 1_700_001_103)
        parsed = block_wire.validate_block(bytes.fromhex(alternative['raw_block']), alternative['hash'])
        self.assertTrue(parsed['pow_verified'])
        self.assertTrue(parsed['merkle_verified'])
        self.assertTrue(parsed['witness_commitment_verified'])
        self.assertNotEqual(alternative['hash'], self.receipt['candidate_b']['hash'])
        self.reject_change(('candidate_b',), alternative)
        self.reject_change(('operations', 'stale_b_submit', 'raw_block'), alternative['raw_block'])
        self.reject_change(('operations', 'submit_b', 'raw_block'), alternative['raw_block'])
        self.reject_change(('blocks', 'b_parent'), alternative)

    def test_nonminimal_block_and_coinbase_witness_counts_are_rejected(self):
        block = self.receipt['blocks']['funding']
        raw = bytes.fromhex(block['raw_block'])
        coinbase = block_wire.validate_block(raw, block['hash'])['transactions'][0]['raw']
        witness_offset = 81 + len(bytes.fromhex(coinbase)) - 38
        self.assertEqual(raw[80], 2)
        self.assertEqual(raw[witness_offset:witness_offset + 2], b'\x01\x20')
        for label, offset, replacement in (
            ('block transaction count', 80, b'\xfd\x02\x00'),
            ('coinbase witness count', witness_offset, b'\xfd\x01\x00'),
            ('coinbase reserved value length', witness_offset + 1, b'\xfd\x20\x00'),
        ):
            changed = raw[:offset] + replacement + raw[offset + 1:]
            with self.subTest(encoding=label):
                self.reject_change(('blocks', 'funding', 'raw_block'), changed.hex())

    def test_operation_results_and_tip_boundaries_are_bound(self):
        for path, value in ((('operations', 'stale_b_submit', 'result'), None),
                            (('operations', 'invalidate', 'result'), 'failed'),
                            (('operations', 'submit_b', 'result'), 'inconclusive-not-best-prevblk'),
                            (('operations', 'invalidate', 'block'), self.receipt['blocks']['a_child']['hash']),
                            (('operations', 'invalidate', 'after'), self.receipt['snapshots']['funded']),
                            (('operations', 'submit_b', 'before'), self.receipt['snapshots']['a_family_pending']),
                            (('operations', 'stale_b_submit', 'after'), self.receipt['snapshots']['b_parent_confirmed'])):
            self.reject_change(path, value)

    def test_admissions_bind_names_witness_identity_and_phase(self):
        for name in ('a_parent', 'a_child', 'b_parent', 'b_child'):
            self.reject_change(('admissions', name, 'dry_run', 'allowed'), False)
            self.reject_change(('admissions', name, 'dry_run', 'wtxid'), '66' * 32)
        self.reject_change(('admissions', 'a_parent', 'submitted_txid'), '88' * 32)
        self.reject_change(('admissions', 'a_child', 'before'), self.receipt['snapshots']['funded'])
        self.reject_change(('admissions', 'b_parent', 'transaction'), 'a_parent')

    def test_named_rejections_need_the_corresponding_attempt_and_phase(self):
        self.reject_change(('rejected', 'conflict_with_child'), self.receipt['rejected']['equal_fee_parent'])
        self.reject_change(('rejected', 'stale_a_child'), self.receipt['rejected']['child_without_parent'])
        self.reject_change(('rejected', 'replayed_old_state', 'transaction'), 'a_child')
        self.reject_change(('rejected', 'equal_fee_parent', 'boundary'), 'script')
        self.reject_change(('rejected', 'equal_fee_parent', 'txid'), '99' * 32)
        self.reject_change(('rejected', 'replayed_old_state', 'before'), self.receipt['snapshots']['a_parent_confirmed'])

    def test_old_A_trace_must_use_fresh_B_context_and_valid_prior_arithmetic(self):
        original = self.receipt['rejected']['replayed_old_state']
        for position, value in ((1, bytes.fromhex(self.receipt['transactions']['a_child']['witness_hex'][1])),
                                (2, bytes.fromhex(self.receipt['transactions']['a_child']['witness_hex'][2])),
                                (3, bytes.fromhex(self.receipt['transactions']['a_child']['witness_hex'][3])),
                                (5, number(12)), (6, number(13)), (8, number(2))):
            report = copy.deepcopy(self.receipt)
            witness = [bytes.fromhex(part) for part in original['witness_hex']]
            witness[position] = value
            self.rewrite_rejected_witness(report, 'replayed_old_state', witness)
            if 5 <= position <= 8:
                report['rejected']['replayed_old_state']['trace'][position - 5] = value[0]
            with self.subTest(position=position), self.assertRaises(stage.EvidenceError):
                self.validate(report)
        report = copy.deepcopy(self.receipt)
        witness = list(self.transactions['b_child']['witness'])
        self.rewrite_rejected_witness(report, 'replayed_old_state', witness)
        report['rejected']['replayed_old_state'].update(trace=[12, 14, 16, 1], delta=2)
        with self.assertRaises(stage.EvidenceError):
            self.validate(report)

    def test_failure_codes_and_reasons_cannot_substitute_unrelated_errors(self):
        for name in self.receipt['rejected']:
            self.reject_change(('rejected', name, 'dry_run', 'allowed'), True)
            self.reject_change(('rejected', name, 'dry_run', 'reject-reason'), 'rpc-disconnected')
        for name in ('equal_fee_parent', 'conflict_with_child', 'replayed_old_state', 'stale_a_child'):
            self.reject_change(('rejected', name, 'admission', 'code'), -1)
            self.reject_change(('rejected', name, 'admission', 'message'), 'RPC unavailable')
        self.reject_change(('rejected', 'replayed_old_state', 'block_error', 'code'), -1)
        self.reject_change(('rejected', 'replayed_old_state', 'block_error', 'message'),
                           'TestBlockValidity failed: bad-txns-inputs-missingorspent')
        self.reject_change(('rejected', 'replayed_old_state', 'block_error', 'message'),
                           'TestBlockValidity failed: block-script-verify-flag-failed (script failed: OP_RETURN)')

    def test_all_restarts_and_clean_exits_are_required(self):
        self.reject_change(('restart_checks',), self.receipt['restart_checks'][:2])
        self.reject_change(('restart_checks',), list(reversed(self.receipt['restart_checks'])))
        self.reject_change(('restart_checks', 1, 'bestblock'), self.receipt['blocks']['a_child']['hash'])
        self.reject_change(('restart_checks', 1, 'preserved'), False)
        for exits in ([0, 0, 0], [0, 0, 0, 1], [False, 0, 0, 0], [0, 0, 0, 0, 0]):
            self.reject_change(('node_exit_codes',), exits)
        self.reject_change(('clean_shutdowns',), False)

    def test_discarded_coinbases_stay_absent_and_winning_coinbases_persist(self):
        winner = self.receipt['coinbase_checks']['b_family_confirmed']['b_parent']['chain']
        for phase in self.receipt['coinbase_checks']:
            self.reject_change(('coinbase_checks', phase, 'a_parent', 'chain'), winner)
            self.reject_change(('coinbase_checks', phase, 'a_child', 'overlay'), winner)
        self.reject_change(('coinbase_checks', 'rewound', 'b_parent', 'chain'), winner)
        for phase in ('b_family_confirmed', 'b_confirmed_restarted'):
            for view in ('chain', 'overlay'):
                self.reject_change(('coinbase_checks', phase, 'b_parent', view), None)
                self.reject_change(('coinbase_checks', phase, 'b_child', view, 'confirmations'), 2)
            self.reject_change(('coinbase_checks', phase, 'b_parent', 'chain', 'amount_sats'), 1)
            self.reject_change(('coinbase_checks', phase, 'b_parent', 'chain', 'coinbase'), False)


if __name__ == '__main__':
    unittest.main()
