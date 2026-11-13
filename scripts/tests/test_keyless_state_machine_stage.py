import copy
from dataclasses import replace
import hashlib
from pathlib import Path
import struct
import sys
import unittest

RESEARCH = Path(__file__).resolve().parents[1] / 'research'
sys.path.insert(0, str(RESEARCH))
import keyless_checksig_rpc as wire
import keyless_checksig_stage as stage
import keyless_state_machine as machine


PIN = 'a7' * 32
PROGRAM = hashlib.sha256(b'BIPSpace/Keyless-CHECKSIG/F17/full-trace/v1').digest()
PATHS = ((2, 2), (2, 3), (3, 2), (3, 3))
BLOCKS = ('aa' * 32, 'bb' * 32, 'cc' * 32)
RECIPIENTS = {9: 0, 12: 1, 15: 0, 1: 1, 4: 0}


def tx_identity(raw):
    return hashlib.sha256(hashlib.sha256(bytes.fromhex(raw)).digest()).digest()[::-1].hex()


def number(value):
    return bytes([abs(value) | (0x80 if value < 0 else 0)]) if value else b''


def describe_input(item):
    return {'txid': item.txid[::-1].hex(), 'vout': item.index, 'amount_sats': item.amount,
            'script_pubkey': item.script.hex(), 'sequence': item.sequence}


def describe_outputs(outputs, roles=None):
    rows = [{'amount_sats': item.amount, 'script_pubkey': item.script.hex()} for item in outputs]
    if roles is not None:
        for row, role in zip(rows, roles):
            row['role'] = role
    return rows


def admitted(tx, witness):
    raw, txid = tx.serialize([witness])
    stripped_size = len(tx.body()) + 8
    vsize = (stripped_size * 3 + len(bytes.fromhex(raw)) + 3) // 4
    wtxid = tx_identity(raw)
    fee = sum(item.amount for item in tx.inputs) - sum(item.amount for item in tx.outputs)
    return {'raw_tx': raw, 'txid': txid, 'admission': {
        'allowed': True, 'txid': txid, 'wtxid': wtxid, 'vsize': vsize,
        'fees': {'base': fee / 100_000_000,
                 'effective-feerate': fee * 1_000 / vsize / 100_000_000,
                 'effective-includes': [wtxid]}}}


def complete_receipt():
    compiled = machine.compile_machine()
    leaves = {3: compiled.leaf, 9: compiled.branch(9).successor.leaf,
              12: compiled.branch(12).successor.leaf}
    amounts = {3: 100_000, 9: 89_000, 12: 86_000}
    keys = {old: leaf.output() for old, leaf in leaves.items()}
    bare_leaf = wire.Leaf(b'\x51')
    bare_spk, bare_control = bare_leaf.output()

    def outputs(old, result):
        payout = wire.Output({9: 9_000, 12: 12_000}[result] if old == 3 else
                             {9: 87_000, 12: 84_000}[old],
                             b'\x51\x20' + wire.RECIPIENTS[RECIPIENTS[result]])
        if old == 3:
            second = wire.Output({9: 89_000, 12: 86_000}[result], keys[result][0])
        else:
            tag = hashlib.sha256(b'BIPSpace/Keyless-CHECKSIG/F17/state/v1').digest()
            commitment = hashlib.sha256(tag + tag + PROGRAM + bytes(4) + bytes([result])).digest()
            second = wire.Output(0, b'\x6a\x20' + commitment)
        return payout, second

    def witness(tx, old, delta, rows):
        item = tx.inputs[0]
        script = leaves[old].script
        return [PROGRAM, item.txid + struct.pack('<I', item.index), item.script[2:],
                wire.tapleaf(script), number(delta), *(number(value) for value in rows),
                script, keys[old][1]]

    def spend(old, source, vout, delta):
        rows = tuple((old + index * delta) % 17 for index in range(4))
        tx = wire.Tx((wire.Input(bytes.fromhex(source)[::-1], vout, amounts[old], keys[old][0]),),
                     outputs(old, rows[-1]))
        return tx, witness(tx, old, delta, rows), rows

    funding_tx = wire.Tx((wire.Input(bytes.fromhex('11' * 32), 0, 5_000_000_000, bare_spk),),
                         (wire.Output(100_000, keys[3][0]),) * 4 +
                         (wire.Output(100_000, bare_spk), wire.Output(4_999_498_000, bare_spk)))
    funding = admitted(funding_tx, [bare_leaf.script, bare_control])
    funding.update(block=BLOCKS[0], height=102,
                   outputs=describe_outputs(funding_tx.outputs,
                       ('root', 'root', 'root', 'root', 'spare_input', 'change')))
    report = {'schema_version': 1, 'fixture': 'keyless-state-machine', 'status': 'passed',
              'network': 'regtest', 'binary_sha256': PIN, 'program_id': PROGRAM.hex(),
              'field_modulus': 17, 'trace_rows': 4, 'paths': [list(path) for path in PATHS],
              'transitions': [], 'positive_admissions': {}, 'rejected': {}, 'funding': funding,
              'both_root_alternatives_eligible': True, 'both_child_alternatives_eligible': True,
              'script_signatures': 0, 'peer_count': 0, 'final_height': 104,
              'rejection_count': 39, 'confirmed_transitions': 8,
              'restart_checks': [{'height': 103, 'preserved': True}, {'height': 104, 'preserved': True}],
              'restart_preserved_outputs': True, 'node_exit_codes': [0, 0, 0], 'clean_shutdowns': True,
              'started_at': '2026-01-01T00:00:00+00:00', 'finished_at': '2026-01-01T00:01:00+00:00',
              'scope': 'Bounded F17 four-row trace with two stages and no signatures.'}

    def transition(path, index, old, source, vout, delta):
        tx, proof, rows = spend(old, source, vout, delta)
        record = admitted(tx, proof)
        record.update(path=list(path), stage=index, program_id=PROGRAM.hex(), old_state=old,
                      new_state=rows[-1], trace=list(rows), delta=delta,
                      input=dict(describe_input(tx.inputs[0]), observed_amount_sats=amounts[old]),
                      outputs=describe_outputs(tx.outputs,
                          ('payout', 'successor' if index == 0 else 'state_commitment')),
                      fee_sats=2_000, witness_hex=[item.hex() for item in proof],
                      script_hex=leaves[old].script.hex(), control_hex=keys[old][1].hex(),
                      observed_input_sats=amounts[old], observed_outputs=describe_outputs(tx.outputs),
                      observed_fee_sats=2_000, block=BLOCKS[index + 1], confirmed_height=103 + index)
        report['transitions'].append(record)
        return record

    parents = [transition(path, 0, 3, funding['txid'], reserve, path[0])
               for reserve, path in enumerate(PATHS)]
    for path, parent in zip(PATHS, parents):
        transition(path, 1, (3 + 3 * path[0]) % 17, parent['txid'], 1, path[1])

    for name, old, source, vout, delta in (
        ('root_delta2', 3, funding['txid'], 0, 2),
        ('root_delta3', 3, funding['txid'], 0, 3),
        ('repaired_root_proof', 3, funding['txid'], 0, 2),
        ('child_delta2', 9, parents[0]['txid'], 1, 2),
        ('child_delta3', 9, parents[0]['txid'], 1, 3),
    ):
        tx, proof, rows = spend(old, source, vout, delta)
        record = admitted(tx, proof)
        record.update(trace=list(rows), delta=delta, input=describe_input(tx.inputs[0]),
                      outputs=describe_outputs(tx.outputs))
        report['positive_admissions'][name] = record

    def reject(name, old, tx, proof, rows, delta, extra_witnesses=()):
        boundary = ('missing-inputs' if name == 'spent_input_replay' else
                    'standardness' if name == 'annex' else 'script')
        reason, message, code = {
            'script': ('script-verify-flag-failed', 'consensus-verification-failed', -26),
            'standardness': ('bad-witness-nonstandard', 'bad-witness-nonstandard', -26),
            'missing-inputs': ('missing-inputs', 'bad-txns-inputs-missingorspent', -25),
        }[boundary]
        block_reason = ('bad-txns-inputs-missingorspent' if boundary == 'missing-inputs'
                        else 'block-script-verify-flag-failed')
        height = 104 if name == 'spent_input_replay' else 102 if old == 3 else 103
        raw, txid = tx.serialize([proof] + list(extra_witnesses))
        report['rejected'][name] = {
            'raw_tx': raw, 'txid': txid, 'stage': 0 if old == 3 else 1,
            'trace': list(rows), 'delta': delta,
            'context': {'program_id': PROGRAM.hex(), 'old_state': old,
                        'inputs': [describe_input(item) for item in tx.inputs],
                        'version': tx.version, 'locktime': tx.locktime,
                        'witness_hex': [item.hex() for item in proof]},
            'expected_boundary': boundary, 'height_before': height, 'height_after': height,
            'block_hash_before': BLOCKS[height - 102], 'block_hash_after': BLOCKS[height - 102],
            'dry_run': {'allowed': False, 'reject-reason': reason, 'txid': txid,
                        'wtxid': tx_identity(raw)},
            'admission': {'code': code, 'message': message},
            'block_error': {'code': -25, 'message': 'TestBlockValidity failed: ' + block_reason}}

    root, root_proof, root_rows = spend(3, funding['txid'], 0, 2)
    alternative, alternate_proof, alternate_rows = spend(3, funding['txid'], 0, 3)
    for name, rows, delta in (
        ('wrong_old_state_valid_trace', (0, 3, 6, 9), 3),
        ('trace_out_of_range_high', (3, 17, 7, 9), 2),
        ('trace_out_of_range_negative', (3, -1, 7, 9), 2),
        ('unauthorized_delta', root_rows, 19),
    ):
        reject(name, 3, root, witness(root, 3, delta, rows), rows, delta)
    for name, rows in (
        ('broken_first_edge', (3, 8, 10, 12)),
        ('broken_middle_edge', (3, 5, 10, 12)),
        ('broken_last_edge', (3, 5, 7, 12)),
    ):
        reject(name, 3, alternative, witness(alternative, 3, 2, rows), rows, 2)
    other_program = hashlib.sha256(PROGRAM + b'other-program').digest()
    for name, position, value in (
        ('substituted_program', 0, other_program),
        ('noncanonical_trace_number', 6, b'\x05\x00'),
        ('changed_control', 10, bytes([root_proof[10][0] ^ 1]) + root_proof[10][1:]),
    ):
        proof = root_proof.copy()
        proof[position] = value
        reject(name, 3, root, proof, root_rows, 2)
    different_leaf = machine.compile_machine(other_program).branch(9).successor.leaf
    for name, changed_outputs in (
        ('result_output_mismatch', alternative.outputs),
        ('wrong_payout_recipient', (replace(root.outputs[0], script=b'\x51\x20' + wire.RECIPIENTS[1]), root.outputs[1])),
        ('wrong_payout_amount', (replace(root.outputs[0], amount=9_001), root.outputs[1])),
        ('wrong_successor_state', (root.outputs[0], replace(root.outputs[1], script=keys[12][0]))),
        ('wrong_successor_program', (root.outputs[0], replace(root.outputs[1], script=different_leaf.output()[0]))),
        ('wrong_successor_amount', (root.outputs[0], replace(root.outputs[1], amount=88_999))),
        ('extra_output', root.outputs + (wire.Output(0, b'\x6a'),)),
        ('reordered_outputs', tuple(reversed(root.outputs))),
    ):
        tx = replace(root, outputs=changed_outputs)
        reject(name, 3, tx, witness(tx, 3, 2, root_rows), root_rows, 2)
    tx = replace(root, inputs=root.inputs + (wire.Input(bytes.fromhex(funding['txid'])[::-1], 4, 100_000, bare_spk),))
    reject('additional_funded_input', 3, tx, witness(tx, 3, 2, root_rows), root_rows, 2,
           ([bare_leaf.script, bare_control],))
    for name, tx in (
        ('fresh_version_change', replace(root, version=1)),
        ('fresh_locktime_change', replace(root, locktime=1)),
        ('fresh_sequence_change', replace(root, inputs=(replace(root.inputs[0], sequence=0xfffffffe),))),
    ):
        reject(name, 3, tx, witness(tx, 3, 2, root_rows), root_rows, 2)
    for position, label in ((1, 'outpoint'), (2, 'spent_key'), (3, 'tapleaf')):
        value = root_proof[position]
        for prefix, changed in (('short', value[1:]), ('long', value + b'\x00'),
                                ('wrong', bytes([value[0] ^ 1]) + value[1:])):
            proof = root_proof.copy()
            proof[position] = changed
            reject(prefix + '_' + label + '_context', 3, root, proof, root_rows, 2)
    reject('annex', 3, root, root_proof + [b'\x50state-annex'], root_rows, 2)
    child, child_proof, child_rows = spend(9, parents[0]['txid'], 1, 2)
    for name, rows, delta in (
        ('proof_replay_successor', root_rows, 2),
        ('wrong_old_state_successor_valid_trace', (6, 9, 12, 15), 3),
    ):
        reject(name, 9, child, witness(child, 9, delta, rows), rows, delta)
    commitment = child.outputs[1].script
    for name, changed_outputs in (
        ('terminal_state_commitment_change', (child.outputs[0], replace(child.outputs[1],
            script=commitment[:-1] + bytes([commitment[-1] ^ 1])))),
        ('terminal_recipient_change', (replace(child.outputs[0], script=b'\x51\x20' + wire.RECIPIENTS[1]), child.outputs[1])),
        ('terminal_payout_amount_change', (replace(child.outputs[0], amount=86_999), child.outputs[1])),
        ('terminal_output_reordered', tuple(reversed(child.outputs))),
    ):
        tx = replace(child, outputs=changed_outputs)
        reject(name, 9, tx, witness(tx, 9, 2, child_rows), child_rows, 2)
    reject('spent_input_replay', 3, alternative, alternate_proof, alternate_rows, 3)
    return report


class StateMachineReceiptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.receipt = complete_receipt()

    def validate(self, report):
        return stage.validate_fixture('state-machine-regtest', report, PIN)

    def reject_change(self, path, value):
        changed = copy.deepcopy(self.receipt)
        target = changed
        for field in path[:-1]:
            target = target[field]
        target[path[-1]] = value
        with self.subTest(path=path, value=repr(value)[:80]), self.assertRaises(stage.EvidenceError):
            self.validate(changed)

    def test_complete_independently_constructed_receipt_is_accepted(self):
        self.assertEqual(self.validate(self.receipt), {
            'rejection_count': 39, 'confirmed_transitions': 8, 'completed_paths': 4,
            'restart_preserved_outputs': True, 'clean_shutdowns': True,
            'network': 'regtest', 'peer_count': 0})

    def test_identity_domain_and_completion_are_required(self):
        for field, value in (
            ('schema_version', 2), ('fixture', 'keyless-regtest'), ('status', 'failed'),
            ('binary_sha256', '00' * 32), ('network', 'main'), ('program_id', '00' * 32),
            ('field_modulus', 19), ('trace_rows', 3), ('script_signatures', 1),
            ('peer_count', 1), ('peer_count', False), ('final_height', 103),
            ('confirmed_transitions', 7), ('both_root_alternatives_eligible', False),
            ('both_child_alternatives_eligible', False),
        ):
            self.reject_change((field,), value)

    def test_three_clean_exits_and_both_preserved_restarts_are_required(self):
        for field, value in (
            ('node_exit_codes', [0, 0]), ('node_exit_codes', [0, 1, 0]),
            ('node_exit_codes', [0, 0, -15]), ('clean_shutdowns', False),
            ('restart_preserved_outputs', False), ('restart_checks', []),
            ('restart_checks', [{'height': 103, 'preserved': True}]),
            ('restart_checks', [{'height': 103, 'preserved': False}, {'height': 104, 'preserved': True}]),
            ('restart_checks', [{'height': 102, 'preserved': True}, {'height': 104, 'preserved': True}]),
        ):
            self.reject_change((field,), value)

    def test_exact_path_and_transition_coverage_is_required(self):
        self.reject_change(('paths',), [[2, 2], [2, 3], [3, 2]])
        self.reject_change(('transitions',), self.receipt['transitions'][:-1])
        self.reject_change(('transitions', 1), self.receipt['transitions'][0])
        self.reject_change(('transitions', 1, 'path'), [3, 3])
        self.reject_change(('transitions', 4, 'stage'), 0)
        self.reject_change(('transitions', 1, 'txid'), self.receipt['transitions'][0]['txid'])

    def test_funding_is_confirmed_with_four_separate_reserves(self):
        for path, value in (
            (('height',), 101), (('txid',), 'invalid'), (('block',), ''),
            (('admission', 'allowed'), False), (('admission', 'txid'), '00' * 32),
            (('raw_tx',), ''), (('raw_tx',), '00'), (('admission', 'wtxid'), '00' * 32),
            (('outputs', 2, 'amount_sats'), 99_999),
            (('outputs', 2, 'script_pubkey'), '5120' + '00' * 32),
            (('outputs',), self.receipt['funding']['outputs'][:4]),
        ):
            self.reject_change(('funding',) + path, value)

    def test_transition_trace_is_anchored_to_old_state_and_path_delta(self):
        for index in (0, 4):
            for field, value in (
                ('program_id', '00' * 32), ('old_state', 0), ('new_state', 4),
                ('delta', 3), ('trace', [0, 3, 6, 9]),
            ):
                self.reject_change(('transitions', index, field), value)

    def test_transition_inputs_link_each_path_to_its_own_successor(self):
        for index in (0, 4):
            for field, value in (
                ('txid', '00' * 32), ('vout', 4), ('amount_sats', 98_000),
                ('script_pubkey', '5120' + '00' * 32), ('sequence', 0xffffffff),
                ('observed_amount_sats', 98_000),
            ):
                self.reject_change(('transitions', index, 'input', field), value)
        self.reject_change(('transitions', 4, 'input', 'txid'), self.receipt['transitions'][1]['txid'])

    def test_payout_successor_and_terminal_commitment_are_exact(self):
        for index in (0, 4):
            for output in (0, 1):
                for field, value in (('amount_sats', 1), ('script_pubkey', '6a20' + '00' * 32),
                                     ('role', 'change')):
                    self.reject_change(('transitions', index, 'outputs', output, field), value)
            self.reject_change(('transitions', index, 'outputs'),
                               list(reversed(self.receipt['transitions'][index]['outputs'])))
        for index in (5, 6, 7):
            self.reject_change(('transitions', index, 'outputs', 1, 'script_pubkey'),
                               self.receipt['transitions'][4]['outputs'][1]['script_pubkey'])

    def test_observed_outputs_and_fees_must_match_transaction_bytes(self):
        for index in (0, 4):
            for field, value in (('fee_sats', 2_001), ('observed_fee_sats', 1_999),
                                 ('observed_input_sats', 99_999)):
                self.reject_change(('transitions', index, field), value)
            self.reject_change(('transitions', index, 'observed_outputs', 0, 'amount_sats'), 1)
            self.reject_change(('transitions', index, 'observed_outputs', 1, 'script_pubkey'), '6a')

    def test_transition_bytes_and_both_transaction_identities_are_required(self):
        for index in (0, 4):
            record = self.receipt['transitions'][index]
            self.reject_change(('transitions', index, 'raw_tx'), record['raw_tx'][:-2] + '01')
            self.reject_change(('transitions', index, 'txid'), '00' * 32)
            for field, value in (('allowed', False), ('txid', '00' * 32), ('wtxid', record['txid'])):
                self.reject_change(('transitions', index, 'admission', field), value)

    def test_exact_witness_layout_and_canonical_numbers_are_required(self):
        for position in range(11):
            self.reject_change(('transitions', 0, 'witness_hex', position), '')
        self.reject_change(('transitions', 0, 'witness_hex', 5), '0300')
        self.reject_change(('transitions', 0, 'witness_hex'), self.receipt['transitions'][0]['witness_hex'] + ['50'])
        self.reject_change(('transitions', 0, 'script_hex'), '51')
        self.reject_change(('transitions', 0, 'control_hex'), 'c0' + '00' * 32)

    def test_stage_confirmations_use_shared_blocks_and_exact_heights(self):
        for index in (0, 4):
            self.reject_change(('transitions', index, 'confirmed_height'), 102)
            self.reject_change(('transitions', index, 'block'), 'dd' * 32)
        self.reject_change(('transitions', 1, 'block'), '')
        self.reject_change(('funding', 'block'), BLOCKS[1])

    def test_all_five_positive_controls_use_the_expected_alternative(self):
        positives = self.receipt['positive_admissions']
        self.reject_change(('positive_admissions',), {k: v for k, v in positives.items() if k != 'child_delta3'})
        self.reject_change(('positive_admissions', 'root_delta3'), positives['root_delta2'])
        self.reject_change(('positive_admissions', 'child_delta3'), positives['child_delta2'])
        for name in positives:
            self.reject_change(('positive_admissions', name, 'admission', 'allowed'), False)
            self.reject_change(('positive_admissions', name, 'admission', 'wtxid'), '00' * 32)
        self.reject_change(('positive_admissions', 'repaired_root_proof', 'raw_tx'), '00')

    def test_all_39_negative_cases_are_required(self):
        rejected = self.receipt['rejected']
        for name in rejected:
            self.reject_change(('rejected',), {k: v for k, v in rejected.items() if k != name})
        self.reject_change(('rejection_count',), 38)
        self.reject_change(('rejected',), dict(rejected, unexpected=rejected['annex']))

    def test_named_attacks_cannot_reuse_an_unrelated_failed_proof(self):
        unrelated = self.receipt['rejected']['broken_middle_edge']
        for name in ('wrong_payout_recipient', 'substituted_program', 'wrong_outpoint_context'):
            self.reject_change(('rejected', name), unrelated)

    def test_dry_run_broadcast_and_block_must_reject_at_the_expected_boundary(self):
        for name in ('broken_first_edge', 'annex', 'spent_input_replay', 'proof_replay_successor'):
            for path, value in (
                (('expected_boundary',), 'unobserved'), (('dry_run', 'allowed'), True),
                (('dry_run', 'reject-reason'), 'non-final'), (('admission', 'code'), -1),
                (('admission', 'message'), 'unrelated-error'), (('block_error', 'code'), -1),
                (('block_error', 'message'), 'unrelated-error'),
            ):
                self.reject_change(('rejected', name) + path, value)

    def test_rejected_transaction_bytes_are_bound_to_dry_run_identity(self):
        for name in ('broken_first_edge', 'annex', 'spent_input_replay'):
            for path, value in (
                (('raw_tx',), ''), (('raw_tx',), 'not-hex'),
                (('txid',), '00' * 32), (('dry_run', 'txid'), '00' * 32),
                (('dry_run', 'wtxid'), '00' * 32),
            ):
                self.reject_change(('rejected', name) + path, value)

    def test_each_rejection_must_preserve_the_correct_stage_tip(self):
        for name, height in (('broken_first_edge', 102), ('proof_replay_successor', 103),
                             ('spent_input_replay', 104)):
            for field, value in (('height_before', height - 1), ('height_after', height + 1),
                                 ('block_hash_before', '00' * 32), ('block_hash_after', '00' * 32),
                                 ('stage', 2)):
                self.reject_change(('rejected', name, field), value)

    def test_wrong_old_state_controls_keep_a_valid_fresh_trace_ending_at_an_authorized_result(self):
        for name, rows in (('wrong_old_state_valid_trace', [0, 3, 6, 9]),
                           ('wrong_old_state_successor_valid_trace', [6, 9, 12, 15])):
            case = self.receipt['rejected'][name]
            self.assertEqual(case['trace'], rows)
            self.assertTrue(all((left + 3) % 17 == right for left, right in zip(rows, rows[1:])))
            for path, value in (
                (('trace',), [3, 5, 7, 9]), (('delta',), 2),
                (('context', 'old_state'), rows[0]), (('context', 'version'), 1),
                (('context', 'locktime'), 1), (('context', 'program_id'), '00' * 32),
                (('context', 'inputs', 0, 'amount_sats'), 1),
                (('context', 'witness_hex', 1), '00' * 36),
                (('context', 'witness_hex', 5), '03'),
            ):
                self.reject_change(('rejected', name) + path, value)

    def test_missing_or_malformed_evidence_fails_as_an_evidence_error(self):
        for path, value in (
            (('transitions',), None), (('transitions', 0), None),
            (('positive_admissions',), []), (('positive_admissions', 'root_delta2'), None),
            (('rejected',), None), (('rejected', 'annex'), None),
            (('funding',), None), (('transitions', 0, 'path'), None),
        ):
            self.reject_change(path, value)
        for field in ('funding', 'transitions', 'positive_admissions', 'rejected'):
            changed = copy.deepcopy(self.receipt)
            del changed[field]
            with self.subTest(missing=field), self.assertRaises(stage.EvidenceError):
                self.validate(changed)


if __name__ == '__main__':
    unittest.main()
