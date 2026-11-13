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
    if name == 'state-machine-regtest':
        try:
            return validate_state_machine(report, binary_sha256)
        except (AttributeError, KeyError, IndexError, TypeError, ValueError) as error:
            raise EvidenceError(f'malformed state-machine receipt: {error}') from error
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


def validate_state_machine(report: dict, binary_sha256: str) -> dict:
    from dataclasses import replace
    import keyless_checksig_rpc as wire
    import keyless_state_machine as machine

    require(isinstance(report, dict) and report.get('status') == 'passed',
            'state-machine fixture did not complete successfully')
    require(report.get('schema_version') == 1 and report.get('fixture') == 'keyless-state-machine',
            'state-machine receipt format differs')
    require(report.get('binary_sha256') == binary_sha256, 'fixture used a different executable')
    require(report.get('network') == 'regtest' and type(report.get('peer_count')) is int
            and report['peer_count'] == 0, 'fixture must observe isolated regtest')
    program_id = hashlib.sha256(b'BIPSpace/Keyless-CHECKSIG/F17/full-trace/v1').digest()
    require(report.get('program_id') == program_id.hex() and report.get('field_modulus') == 17
            and report.get('trace_rows') == 4, 'program identity or arithmetic domain differs')
    require(report.get('script_signatures') == 0 and report.get('final_height') == 104,
            'signature count or final height differs')
    exits = report.get('node_exit_codes')
    require(exits == [0, 0, 0] and all(type(code) is int for code in exits)
            and report.get('clean_shutdowns') is True,
            'three clean node exits are required')
    require(report.get('restart_preserved_outputs') is True and report.get('restart_checks') == [
        {'height': 103, 'preserved': True}, {'height': 104, 'preserved': True}],
        'both restarts must preserve the confirmed state')
    require(report.get('both_root_alternatives_eligible') is True
            and report.get('both_child_alternatives_eligible') is True,
            'both alternatives must be checked at each stage')
    paths = ((2, 2), (2, 3), (3, 2), (3, 3))
    require(report.get('paths') == [list(path) for path in paths], 'program path coverage differs')
    program = machine.compile_machine()
    require((program.program_id, program.old_state, program.depth, program.amount)
            == (program_id, 3, 1, 100_000), 'compiled root differs from the program specification')
    for result, amount in ((9, 89_000), (12, 86_000)):
        child = program.branch(result).successor
        require((child.program_id, child.old_state, child.depth, child.amount)
                == (program_id, result, 0, amount), 'compiled successor differs from the program specification')
    root_spk, _ = program.leaf.output()
    recipient_index = {9: 0, 12: 1, 15: 0, 1: 1, 4: 0}

    def identity(value, label):
        require(isinstance(value, str) and bool(re.fullmatch(r'[0-9a-f]{64}', value)),
                f'{label} identity is missing')

    def outputs_for(stage, result):
        recipient = b'\x51\x20' + wire.RECIPIENTS[recipient_index[result]]
        if stage.depth == 1:
            payout, reserve = {9: (9_000, 89_000), 12: (12_000, 86_000)}[result]
            child_spk, _ = program.branch(result).successor.leaf.output()
            return (wire.Output(payout, recipient), wire.Output(reserve, child_spk))
        tag = hashlib.sha256(b'BIPSpace/Keyless-CHECKSIG/F17/state/v1').digest()
        commitment = hashlib.sha256(tag + tag + program_id + bytes(4) + bytes([result])).digest()
        return (wire.Output({9: 87_000, 12: 84_000}[stage.old_state], recipient),
                wire.Output(0, b'\x6a\x20' + commitment))

    def rows_for(outputs):
        return [{'amount_sats': item.amount, 'script_pubkey': item.script.hex()} for item in outputs]

    def expected_spend(stage, txid, vout, delta, trace=None):
        rows = tuple((stage.old_state + i * delta) % 17 for i in range(4)) if trace is None else trace
        spk, control = stage.leaf.output()
        item = wire.Input(bytes.fromhex(txid)[::-1], vout, stage.amount, spk)
        tx = wire.Tx((item,), outputs_for(stage, rows[-1]))
        witness = [program_id, item.outpoint(), spk[2:], wire.tapleaf(stage.leaf.script),
                   bytes([delta]), *(bytes([value]) if value else b'' for value in rows),
                   stage.leaf.script, control]
        context = {'txid': txid, 'vout': vout, 'amount_sats': stage.amount,
                   'script_pubkey': spk.hex(), 'sequence': 0xfffffffd}
        return tx, witness, rows, context

    def accepted(record, tx, witness):
        raw, txid = tx.serialize([witness])
        wtxid = wire.sha(wire.sha(bytes.fromhex(raw)))[::-1].hex()
        require(record.get('raw_tx') == raw and record.get('txid') == txid,
                'accepted transaction bytes differ from the expected transition')
        admission = record.get('admission', {})
        require(admission.get('allowed') is True and admission.get('txid') == txid
                and admission.get('wtxid') == wtxid, 'accepted transaction identity differs')

    funding = report['funding']
    identity(funding.get('txid'), 'funding transaction')
    identity(funding.get('block'), 'funding block')
    require(funding.get('height') == 102 and funding.get('admission', {}).get('allowed') is True
            and funding['admission'].get('txid') == funding['txid'], 'funding was not confirmed')
    require(len(funding['outputs']) == 6 and funding['outputs'][:4] == [
        {'amount_sats': 100_000, 'script_pubkey': root_spk.hex(), 'role': 'root'}] * 4,
        'funding must contain four program reserves')
    base_leaf = wire.Leaf(b'\x51')
    base_spk, base_control = base_leaf.output()
    require(funding['outputs'][4:] == [
        {'amount_sats': 100_000, 'script_pubkey': base_spk.hex(), 'role': 'spare_input'},
        {'amount_sats': 4_999_498_000, 'script_pubkey': base_spk.hex(), 'role': 'change'}],
        'funding spare input or change differs')
    funding_raw = bytes.fromhex(funding['raw_tx'])
    require(len(funding_raw) >= 43 and funding_raw[:7] == b'\x02\x00\x00\x00\x00\x01\x01',
            'funding transaction encoding differs')
    funding_input = wire.Input(funding_raw[7:39], int.from_bytes(funding_raw[39:43], 'little'),
                               5_000_000_000, base_spk)
    funding_tx = wire.Tx((funding_input,), tuple(wire.Output(item['amount_sats'],
        bytes.fromhex(item['script_pubkey'])) for item in funding['outputs']))
    accepted(funding, funding_tx, [base_leaf.script, base_control])
    transitions = report.get('transitions')
    require(isinstance(transitions, list) and len(transitions) == 8
            and report.get('confirmed_transitions') == 8, 'eight transitions must be confirmed')
    records = {(tuple(item['path']), item['stage']): item for item in transitions}
    require(set(records) == {(path, index) for path in paths for index in (0, 1)},
            'transition path or stage coverage differs')
    require(len({item['txid'] for item in transitions}) == 8, 'transitions must be distinct')
    blocks = {index: records[(paths[0], index)]['block'] for index in (0, 1)}
    require(len({funding['block'], *blocks.values()}) == 3, 'confirmation block identities must differ')
    for index, block in blocks.items():
        identity(block, f'stage {index} block')
    for reserve, path in enumerate(paths):
        for index in (0, 1):
            record = records[(path, index)]
            parent = records[(path, 0)]
            first_result = (3 + 3 * path[0]) % 17
            stage = program if index == 0 else program.branch(first_result).successor
            txid, vout = (funding['txid'], reserve) if index == 0 else (parent['txid'], 1)
            tx, witness, rows, context = expected_spend(stage, txid, vout, path[index])
            require(record.get('program_id') == program_id.hex()
                    and record.get('old_state') == stage.old_state and record.get('new_state') == rows[-1]
                    and record.get('trace') == list(rows) and record.get('delta') == path[index],
                    'transition proof differs from the committed program state')
            require(record.get('input') == dict(context, observed_amount_sats=stage.amount),
                    'transition input does not spend the expected reserve or successor')
            roles = ('payout', 'successor' if index == 0 else 'state_commitment')
            expected_outputs = rows_for(tx.outputs)
            require(record.get('outputs') == [dict(item, role=role)
                    for item, role in zip(expected_outputs, roles)]
                    and record.get('observed_outputs') == expected_outputs,
                    'confirmed outputs differ from the program result')
            require(record.get('fee_sats') == 2_000 and record.get('observed_fee_sats') == 2_000
                    and record.get('observed_input_sats') == stage.amount,
                    'observed input value or fee differs')
            require(record.get('confirmed_height') == 103 + index and record.get('block') == blocks[index],
                    'transition confirmation differs')
            require(record.get('witness_hex') == [value.hex() for value in witness]
                    and record.get('script_hex') == stage.leaf.script.hex()
                    and record.get('control_hex') == witness[-1].hex(), 'transition witness differs')
            accepted(record, tx, witness)

    positives = report['positive_admissions']
    controls = {'root_delta2': (0, 2), 'root_delta3': (0, 3), 'repaired_root_proof': (0, 2),
                'child_delta2': (1, 2), 'child_delta3': (1, 3)}
    require(set(positives) == set(controls), 'positive controls are missing or unexpected')
    for name, (index, delta) in controls.items():
        stage = program if index == 0 else program.branch(9).successor
        txid, vout = (funding['txid'], 0) if index == 0 else (records[(paths[0], 0)]['txid'], 1)
        tx, witness, rows, context = expected_spend(stage, txid, vout, delta)
        record = positives[name]
        require(record.get('input') == context and record.get('outputs') == rows_for(tx.outputs)
                and record.get('trace') == list(rows) and record.get('delta') == delta,
                'positive control does not exercise the expected alternative')
        accepted(record, tx, witness)

    root_cases = {
        'wrong_old_state_valid_trace', 'substituted_program', 'trace_out_of_range_high',
        'trace_out_of_range_negative', 'broken_first_edge', 'broken_middle_edge', 'broken_last_edge',
        'noncanonical_trace_number',
        'unauthorized_delta', 'result_output_mismatch', 'wrong_payout_recipient',
        'wrong_payout_amount', 'wrong_successor_state', 'wrong_successor_program',
        'wrong_successor_amount', 'extra_output', 'reordered_outputs', 'additional_funded_input',
        'fresh_version_change', 'fresh_locktime_change', 'fresh_sequence_change',
        'short_outpoint_context', 'long_outpoint_context', 'short_spent_key_context',
        'long_spent_key_context', 'short_tapleaf_context', 'long_tapleaf_context',
        'wrong_outpoint_context', 'wrong_spent_key_context', 'wrong_tapleaf_context',
        'annex', 'changed_control',
    }
    child_cases = {'proof_replay_successor', 'wrong_old_state_successor_valid_trace',
                   'terminal_state_commitment_change', 'terminal_recipient_change',
                   'terminal_payout_amount_change', 'terminal_output_reordered'}
    rejected = report['rejected']
    require(set(rejected) == root_cases | child_cases | {'spent_input_replay'}
            and report.get('rejection_count') == 39, 'rejection coverage differs')
    for name, case in rejected.items():
        height = 102 if name in root_cases else 103 if name in child_cases else 104
        block = funding['block'] if height == 102 else blocks[height - 103]
        boundary = 'standardness' if name == 'annex' else (
            'missing-inputs' if name == 'spent_input_replay' else 'script')
        reason, code, message = {
            'standardness': ('bad-witness-nonstandard', -26, 'bad-witness-nonstandard'),
            'missing-inputs': ('missing-inputs', -25, 'bad-txns-inputs-missingorspent'),
            'script': ('script-verify-flag-failed', -26, 'consensus-verification-failed'),
        }[boundary]
        require(case.get('expected_boundary') == boundary
                and case.get('stage') == (1 if name in child_cases else 0), 'rejection stage differs')
        identity(case.get('txid'), 'rejected transaction')
        raw = bytes.fromhex(case['raw_tx'])
        require(bool(raw), 'rejected transaction bytes are missing')
        dry = case.get('dry_run', {})
        require(dry.get('allowed') is False and dry.get('reject-reason') == reason
                and dry.get('txid') == case['txid']
                and dry.get('wtxid') == wire.sha(wire.sha(raw))[::-1].hex(),
                'expected dry-run rejection or transaction identity is missing')
        require(case.get('admission') == {'code': code, 'message': message},
                'expected broadcast rejection is missing')
        failure = case.get('block_error', {})
        block_reason = 'bad-txns-inputs-missingorspent' if boundary == 'missing-inputs' else 'block-script-verify-flag-failed'
        require(failure.get('code') == -25 and block_reason in str(failure.get('message', '')),
                'expected direct-block rejection is missing')
        require(case.get('height_before') == height and case.get('height_after') == height
                and case.get('block_hash_before') == block and case.get('block_hash_after') == block,
                'invalid block attempt changed the chain or used the wrong tip')

    checked = set()

    def negative(name, stage, tx, witness, rows, delta, other_witnesses=()):
        raw, expected_id = tx.serialize([witness] + list(other_witnesses))
        case = rejected[name]
        inputs = [{'txid': item.txid[::-1].hex(), 'vout': item.index, 'amount_sats': item.amount,
                   'script_pubkey': item.script.hex(), 'sequence': item.sequence} for item in tx.inputs]
        require(case.get('trace') == list(rows) and case.get('delta') == delta
                and case.get('raw_tx') == raw and case.get('txid') == expected_id
                and case.get('context') == {'program_id': program_id.hex(), 'old_state': stage.old_state,
                    'inputs': inputs, 'version': tx.version, 'locktime': tx.locktime,
                    'witness_hex': [item.hex() for item in witness]},
                f'{name}: rejected transaction does not exercise its named attack')
        checked.add(name)

    root_tx, root_witness, root_rows, _ = expected_spend(program, funding['txid'], 0, 2)
    other_tx, other_witness, other_rows, _ = expected_spend(program, funding['txid'], 0, 3)
    child = program.branch(9).successor
    child_tx, child_witness, child_rows, _ = expected_spend(
        child, records[(paths[0], 0)]['txid'], 1, 2)

    def proof_rows(original, rows, delta):
        encoded = [b'\x81' if row == -1 else wire.script_number(row) for row in rows]
        return original[:4] + [wire.script_number(delta), *encoded] + original[-2:]

    for name, rows, delta in (
        ('wrong_old_state_valid_trace', (0, 3, 6, 9), 3),
        ('trace_out_of_range_high', (3, 17, 7, 9), 2),
        ('trace_out_of_range_negative', (3, -1, 7, 9), 2),
        ('unauthorized_delta', root_rows, 19),
    ):
        negative(name, program, root_tx, proof_rows(root_witness, rows, delta), rows, delta)
    for name, rows in (
        ('broken_first_edge', (3, 8, 10, 12)),
        ('broken_middle_edge', (3, 5, 10, 12)),
        ('broken_last_edge', (3, 5, 7, 12)),
    ):
        negative(name, program, other_tx, proof_rows(root_witness, rows, 2), rows, 2)
    alternate = machine.compile_machine(wire.sha(program_id + b'other-program'))
    for name, position, value in (
        ('substituted_program', 0, alternate.program_id),
        ('noncanonical_trace_number', 6, b'\x05\x00'),
        ('changed_control', 10, bytes([root_witness[-1][0] ^ 1]) + root_witness[-1][1:]),
    ):
        witness = root_witness.copy()
        witness[position] = value
        negative(name, program, root_tx, witness, root_rows, 2)
    for position, label in ((1, 'outpoint'), (2, 'spent_key'), (3, 'tapleaf')):
        original = root_witness[position]
        for prefix, value in (('short', original[1:]), ('long', original + b'\x00'),
                              ('wrong', bytes([original[0] ^ 1]) + original[1:])):
            witness = root_witness.copy()
            witness[position] = value
            negative(prefix + '_' + label + '_context', program, root_tx, witness, root_rows, 2)
    negative('annex', program, root_tx, root_witness + [b'\x50state-annex'], root_rows, 2)
    first, second = root_tx.outputs
    wrong_state, _ = program.branch(12).successor.leaf.output()
    wrong_program, _ = alternate.branch(9).successor.leaf.output()
    for name, outputs in (
        ('result_output_mismatch', other_tx.outputs),
        ('wrong_payout_recipient', (replace(first, script=b'\x51\x20' + wire.RECIPIENTS[1]), second)),
        ('wrong_payout_amount', (replace(first, amount=9_001), second)),
        ('wrong_successor_state', (first, replace(second, script=wrong_state))),
        ('wrong_successor_program', (first, replace(second, script=wrong_program))),
        ('wrong_successor_amount', (first, replace(second, amount=88_999))),
        ('extra_output', root_tx.outputs + (wire.Output(0, b'\x6a'),)),
        ('reordered_outputs', (second, first)),
    ):
        negative(name, program, replace(root_tx, outputs=outputs), root_witness, root_rows, 2)
    for name, tx in (
        ('fresh_version_change', replace(root_tx, version=1)),
        ('fresh_locktime_change', replace(root_tx, locktime=1)),
        ('fresh_sequence_change', replace(root_tx, inputs=(replace(root_tx.inputs[0], sequence=0xfffffffe),))),
    ):
        negative(name, program, tx, root_witness, root_rows, 2)
    spare = wire.Input(bytes.fromhex(funding['txid'])[::-1], 4, 100_000, base_spk)
    negative('additional_funded_input', program, replace(root_tx, inputs=root_tx.inputs + (spare,)),
             root_witness, root_rows, 2, ([base_leaf.script, base_control],))
    negative('proof_replay_successor', child, child_tx,
             proof_rows(child_witness, root_rows, 2), root_rows, 2)
    wrong_old = (6, 9, 12, 15)
    negative('wrong_old_state_successor_valid_trace', child, child_tx,
             proof_rows(child_witness, wrong_old, 3), wrong_old, 3)
    payout, commitment = child_tx.outputs
    changed_commitment = commitment.script[:-1] + bytes([commitment.script[-1] ^ 1])
    for name, outputs in (
        ('terminal_state_commitment_change', (payout, replace(commitment, script=changed_commitment))),
        ('terminal_recipient_change', (replace(payout, script=b'\x51\x20' + wire.RECIPIENTS[1]), commitment)),
        ('terminal_payout_amount_change', (replace(payout, amount=86_999), commitment)),
        ('terminal_output_reordered', (commitment, payout)),
    ):
        negative(name, child, replace(child_tx, outputs=outputs), child_witness, child_rows, 2)
    negative('spent_input_replay', program, other_tx, other_witness, other_rows, 3)
    require(checked == set(rejected), 'rejection transaction checks are incomplete')
    return {'rejection_count': 39, 'confirmed_transitions': 8, 'completed_paths': 4,
            'restart_preserved_outputs': True, 'clean_shutdowns': True,
            'network': 'regtest', 'peer_count': 0}


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
        add('state-machine-regtest', [sys.executable, 'scripts/research/keyless_state_machine_rpc.py',
                                     str(binary), '--output', str(output / 'state-machine-regtest')], 'fixture')
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
                    receipt = (output / 'state-machine-regtest' / 'report.json'
                               if step['name'] == 'state-machine-regtest'
                               else output / f"{step['name']}.json")
                    step['evidence'] = validate_fixture(step['name'], json.loads(receipt.read_text()),
                                                       report['binary']['sha256'])
                    step['receipt'] = str(receipt.relative_to(output))
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
