#!/usr/bin/env python3
"""Execute every path through the funded two-stage F17 TXCOMMIT program.

The complete arithmetic trace is disclosed. The experiment uses NUMS P2TR
leaves, the native TXCOMMIT and CAT research features, and public test keys.
"""
from __future__ import annotations

import argparse
from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import signal
import tempfile

import keyless_checksig_rpc as base
import keyless_state_machine as machine


PATHS = ((2, 2), (2, 3), (3, 2), (3, 3))
RECIPIENT_INDEX = {9: 0, 12: 1, 15: 0, 1: 1, 4: 0}
ROOT_FAILURES = frozenset((
    'wrong_old_state_valid_trace', 'substituted_program', 'trace_out_of_range_high',
    'trace_out_of_range_negative', 'broken_first_edge', 'broken_middle_edge',
    'broken_last_edge', 'noncanonical_trace_number',
    'unauthorized_delta', 'result_output_mismatch', 'wrong_payout_recipient',
    'wrong_payout_amount', 'wrong_successor_state', 'wrong_successor_program',
    'wrong_successor_amount', 'extra_output', 'reordered_outputs',
    'additional_funded_input', 'fresh_version_change', 'fresh_locktime_change',
    'fresh_sequence_change', 'short_outpoint_context', 'long_outpoint_context',
    'short_spent_key_context', 'long_spent_key_context', 'short_tapleaf_context',
    'long_tapleaf_context', 'wrong_outpoint_context', 'wrong_spent_key_context',
    'wrong_tapleaf_context', 'annex', 'changed_control',
))
CHILD_FAILURES = frozenset((
    'proof_replay_successor', 'wrong_old_state_successor_valid_trace',
    'terminal_state_commitment_change', 'terminal_recipient_change',
    'terminal_payout_amount_change', 'terminal_output_reordered',
))
EXPECTED_FAILURES = ROOT_FAILURES | CHILD_FAILURES | {'spent_input_replay'}


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def expected_trace(old_state: int, delta: int) -> tuple[int, ...]:
    return tuple((old_state + step * delta) % 17 for step in range(4))


def expected_commitment(program_id: bytes, state: int) -> bytes:
    tag = hashlib.sha256(b'BIPSpace/Keyless-CHECKSIG/F17/state/v1').digest()
    return hashlib.sha256(tag + tag + program_id + bytes(4) + bytes([state])).digest()


def output_rows(outputs, roles=None) -> list[dict]:
    rows = [{'amount_sats': item.amount, 'script_pubkey': item.script.hex()} for item in outputs]
    if roles is not None:
        for row, role in zip(rows, roles):
            row['role'] = role
    return rows


def decoded_outputs(transaction: dict) -> list[dict]:
    return [{'amount_sats': base.satoshis(item['value']),
             'script_pubkey': item['scriptPubKey']['hex']} for item in transaction['vout']]


def describe_input(item: base.Input) -> dict:
    return {'txid': item.txid[::-1].hex(), 'vout': item.index,
            'amount_sats': item.amount, 'script_pubkey': item.script.hex(),
            'sequence': item.sequence}


def checked_transition(stage, funding_id, vout, delta, path, index):
    tx, witness = machine.build_spend(stage, funding_id, vout, delta)
    rows = expected_trace(stage.old_state, delta)
    result = rows[-1]
    recipient = b'\x51\x20' + base.RECIPIENTS[RECIPIENT_INDEX[result]]
    base.require(tx.version == 2 and tx.locktime == 0 and len(tx.inputs) == 1,
                 'compiler changed the strict transaction context')
    base.require(tx.inputs[0].sequence == 0xfffffffd, 'compiler changed sequence')
    base.require(tx.inputs[0].amount == stage.amount, 'compiler changed spent amount')
    if index == 0:
        base.require(stage.old_state == 3 and stage.depth == 1 and stage.amount == 100_000,
                     'root state differs from the funded specification')
        payout, successor_amount = {9: (9_000, 89_000), 12: (12_000, 86_000)}[result]
        child = stage.branch(result).successor
        base.require(child is not None and child.old_state == result and child.depth == 0,
                     'successor state differs from checked result')
        base.require(child.program_id == stage.program_id and child.amount == successor_amount,
                     'successor program or value differs')
        child_spk, _ = child.leaf.output()
        expected = (base.Output(payout, recipient), base.Output(successor_amount, child_spk))
        roles = ('payout', 'successor')
    else:
        payout = {9: 87_000, 12: 84_000}[stage.old_state]
        base.require(stage.depth == 0, 'terminal depth differs')
        expected = (base.Output(payout, recipient),
                    base.Output(0, b'\x6a\x20'+expected_commitment(stage.program_id, result)))
        roles = ('payout', 'state_commitment')
    base.require(tx.outputs == expected, 'compiler outputs differ from the independent specification')
    base.require(stage.amount-sum(item.amount for item in tx.outputs) == 2_000,
                 'transition fee differs from the specification')
    raw, txid = tx.serialize([witness])
    record = {'path': list(path), 'stage': index, 'program_id': stage.program_id.hex(),
              'old_state': stage.old_state, 'new_state': result, 'trace': list(rows), 'delta': delta,
              'input': describe_input(tx.inputs[0]), 'outputs': output_rows(tx.outputs, roles),
              'fee_sats': 2_000, 'raw_tx': raw, 'txid': txid,
              'witness_hex': [item.hex() for item in witness],
              'script_hex': stage.leaf.script.hex(), 'control_hex': witness[-1].hex()}
    return tx, witness, record


def run(binary: Path, output: Path) -> dict:
    base.require_assertions()
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    report = {'schema_version': 1, 'fixture': 'keyless-state-machine', 'status': 'running',
              'started_at': now(), 'network': 'regtest', 'program_id': machine.PROGRAM_ID.hex(),
              'field_modulus': 17, 'trace_rows': 4, 'paths': [list(path) for path in PATHS],
              'transitions': [], 'positive_admissions': {}, 'rejected': {}, 'restart_checks': [],
              'script_signatures': 0,
              'scope': 'All four paths of a two-stage F17 full-trace program; result-bound payouts '
                       'and successor programs in NUMS P2TR; disclosed trace and research TXCOMMIT/CAT.'}
    node = None
    with tempfile.TemporaryDirectory(prefix='keyless-state-machine-') as directory:
        root = Path(directory)
        try:
            binary = binary.resolve(strict=True)
            base.require(binary.is_file() and os.access(binary, os.X_OK), 'node binary is not executable')
            report['binary_sha256'] = hashlib.sha256(binary.read_bytes()).hexdigest()
            program = machine.compile_machine()
            alternate_program = machine.compile_machine(base.sha(machine.PROGRAM_ID+b'other-program'))
            root_spk, _ = program.leaf.output()
            base_leaf = base.Leaf(b'\x51')
            base_spk, base_control = base_leaf.output()
            mining_address = base.address(base_spk[2:])
            node = base.Node(binary, root)
            rpc = node.rpc
            info = node.start()
            base.require(info['blocks'] == 0, 'fresh regtest data required')
            base.require(rpc('getconnectioncount') == 0, 'unexpected regtest peer')
            blocks = rpc('generatetoaddress', [101, mining_address])
            base.require(len(blocks) == 101, 'coinbase maturity blocks missing')
            coinbase = rpc('getblock', [blocks[0], 2])['tx'][0]
            source = next(item for item in coinbase['vout']
                          if item['scriptPubKey']['hex'] == base_spk.hex())
            source_value = base.satoshis(source['value'])
            funding = base.Tx((base.Input(bytes.fromhex(coinbase['txid'])[::-1], source['n'],
                                          source_value, base_spk),),
                              (base.Output(100_000, root_spk),)*4 +
                              (base.Output(100_000, base_spk),
                               base.Output(source_value-500_000-2_000, base_spk)))
            funding_raw, funding_id = funding.serialize([[base_leaf.script, base_control]])
            funding_admission = rpc('testmempoolaccept', [[funding_raw]])[0]
            base.require(funding_admission['allowed'] is True, 'funding rejected')
            base.require(rpc('sendrawtransaction', [funding_raw]) == funding_id, 'funding txid differs')
            funding_block = rpc('generatetoaddress', [1, mining_address])[0]
            base.require(funding_id in rpc('getblock', [funding_block])['tx'], 'funding not confirmed')
            base.require(rpc('getblockcount') == 102, 'unexpected funding height')
            report['funding'] = {'raw_tx': funding_raw, 'txid': funding_id, 'block': funding_block,
                                 'height': 102, 'admission': funding_admission,
                                 'outputs': output_rows(funding.outputs,
                                     ('root', 'root', 'root', 'root', 'spare_input', 'change'))}

            def positive(name, tx, witness, rows, delta):
                raw, txid = tx.serialize([witness])
                observed = rpc('testmempoolaccept', [[raw]])[0]
                report['positive_admissions'][name] = {'raw_tx': raw, 'txid': txid,
                    'trace': list(rows), 'delta': delta, 'input': describe_input(tx.inputs[0]),
                    'outputs': output_rows(tx.outputs), 'admission': observed}
                base.require(observed['allowed'] is True, name+' positive control rejected')

            def reject(name, stage, tx, witness, rows, delta, other_witnesses=()):
                base.require(name not in report['rejected'], 'duplicate rejection name')
                raw, txid = tx.serialize([witness]+list(other_witnesses))
                height = rpc('getblockcount')
                tip = rpc('getbestblockhash')
                boundary = 'missing-inputs' if name == 'spent_input_replay' else (
                    'standardness' if name == 'annex' else 'script')
                entry = {'raw_tx': raw, 'txid': txid, 'stage': 1-stage.depth,
                         'trace': list(rows), 'delta': delta,
                         'context': {'program_id': stage.program_id.hex(), 'old_state': stage.old_state,
                                     'inputs': [describe_input(item) for item in tx.inputs],
                                     'version': tx.version, 'locktime': tx.locktime,
                                     'witness_hex': [item.hex() for item in witness]},
                         'expected_boundary': boundary, 'height_before': height,
                         'block_hash_before': tip}
                report['rejected'][name] = entry
                dry = rpc('testmempoolaccept', [[raw]])[0]
                entry['dry_run'] = dry
                expected_reason = {'missing-inputs': 'missing-inputs', 'standardness': 'bad-witness-nonstandard',
                                   'script': 'script-verify-flag-failed'}[boundary]
                base.require(dry['allowed'] is False and dry.get('reject-reason') == expected_reason,
                             name+' rejected at an unexpected mempool boundary: '+str(dry))
                try:
                    rpc('sendrawtransaction', [raw])
                except base.RpcError as error:
                    entry['admission'] = error.error
                    base.require(error.error['code'] == (-25 if boundary == 'missing-inputs' else -26),
                                 name+' returned an unexpected broadcast error')
                else:
                    raise ValueError(name+' entered the mempool')
                try:
                    rpc('generateblock', [mining_address, [raw]])
                except base.RpcError as error:
                    entry['block_error'] = error.error
                    base.require(error.error['code'] == -25, name+' returned an unexpected block error')
                    if boundary != 'missing-inputs':
                        base.require('block-script-verify-flag-failed' in str(error.error.get('message', '')),
                                     name+' failed outside block Script validation')
                    else:
                        base.require('bad-txns-inputs-missingorspent' in str(error.error.get('message', '')),
                                     name+' failed outside the spent-input boundary')
                else:
                    raise ValueError(name+' entered a block')
                entry['height_after'] = rpc('getblockcount')
                entry['block_hash_after'] = rpc('getbestblockhash')
                base.require(entry['height_after'] == height and entry['block_hash_after'] == tip,
                             name+' changed the chain')

            root_tx, root_witness = machine.build_spend(program, funding_id, 0, 2)
            alternate_tx, alternate_witness = machine.build_spend(program, funding_id, 0, 3)
            rows = expected_trace(3, 2)
            positive('root_delta2', root_tx, root_witness, rows, 2)
            positive('root_delta3', alternate_tx, alternate_witness, expected_trace(3, 3), 3)
            report['both_root_alternatives_eligible'] = True
            wrong_old = (0, 3, 6, 9)
            reject('wrong_old_state_valid_trace', program, root_tx,
                   machine.witness(root_tx, program, wrong_old, 3), wrong_old, 3)
            reject('substituted_program', program, root_tx,
                   machine.witness(root_tx, program, rows, 2, program_id=alternate_program.program_id), rows, 2)
            high_rows = (3, 17, 7, 9)
            reject('trace_out_of_range_high', program, root_tx,
                   machine.witness(root_tx, program, high_rows, 2), high_rows, 2)
            changed = root_witness.copy()
            changed[machine.WITNESS_FIELDS['row1']] = b'\x81'
            reject('trace_out_of_range_negative', program, root_tx, changed, (3, -1, 7, 9), 2)
            for name, broken in (
                ('broken_first_edge', (3, 8, 10, 12)),
                ('broken_middle_edge', (3, 5, 10, 12)),
                ('broken_last_edge', (3, 5, 7, 12)),
            ):
                reject(name, program, alternate_tx,
                       machine.witness(alternate_tx, program, broken, 2), broken, 2)
            changed = root_witness.copy()
            changed[machine.WITNESS_FIELDS['row1']] = b'\x05\x00'
            reject('noncanonical_trace_number', program, root_tx, changed, rows, 2)
            reject('unauthorized_delta', program, root_tx,
                   machine.witness(root_tx, program, rows, 19), rows, 19)

            def output_attack(name, outputs):
                changed_tx = replace(root_tx, outputs=outputs)
                reject(name, program, changed_tx, machine.witness(changed_tx, program, rows, 2), rows, 2)

            output_attack('result_output_mismatch', alternate_tx.outputs)
            output_attack('wrong_payout_recipient',
                          (replace(root_tx.outputs[0], script=b'\x51\x20'+base.RECIPIENTS[1]), root_tx.outputs[1]))
            output_attack('wrong_payout_amount',
                          (replace(root_tx.outputs[0], amount=9_001), root_tx.outputs[1]))
            wrong_child_spk, _ = program.branch(12).successor.leaf.output()
            output_attack('wrong_successor_state',
                          (root_tx.outputs[0], replace(root_tx.outputs[1], script=wrong_child_spk)))
            alternate_child_spk, _ = alternate_program.branch(9).successor.leaf.output()
            output_attack('wrong_successor_program',
                          (root_tx.outputs[0], replace(root_tx.outputs[1], script=alternate_child_spk)))
            output_attack('wrong_successor_amount',
                          (root_tx.outputs[0], replace(root_tx.outputs[1], amount=88_999)))
            output_attack('extra_output', root_tx.outputs+(base.Output(0, b'\x6a'),))
            output_attack('reordered_outputs', tuple(reversed(root_tx.outputs)))
            spare = base.Input(bytes.fromhex(funding_id)[::-1], 4, 100_000, base_spk)
            changed_tx = replace(root_tx, inputs=root_tx.inputs+(spare,))
            reject('additional_funded_input', program, changed_tx,
                   machine.witness(changed_tx, program, rows, 2), rows, 2,
                   ([base_leaf.script, base_control],))
            for name, changed_tx in (
                ('fresh_version_change', replace(root_tx, version=1)),
                ('fresh_locktime_change', replace(root_tx, locktime=1)),
                ('fresh_sequence_change', replace(root_tx,
                    inputs=(replace(root_tx.inputs[0], sequence=0xfffffffe),))),
            ):
                reject(name, program, changed_tx, machine.witness(changed_tx, program, rows, 2), rows, 2)
            for field, label in (('outpoint', 'outpoint'), ('spent_key', 'spent_key'), ('tapleaf', 'tapleaf')):
                position = machine.WITNESS_FIELDS[field]
                for prefix, value in (('short', root_witness[position][1:]),
                                      ('long', root_witness[position]+b'\x00'),
                                      ('wrong', bytes([root_witness[position][0]^1])+root_witness[position][1:])):
                    changed = root_witness.copy()
                    changed[position] = value
                    reject(prefix+'_'+label+'_context', program, root_tx, changed, rows, 2)
            reject('annex', program, root_tx, root_witness+[b'\x50state-annex'], rows, 2)
            changed = root_witness.copy()
            changed[-1] = bytes([changed[-1][0]^1])+changed[-1][1:]
            reject('changed_control', program, root_tx, changed, rows, 2)
            base.require(set(report['rejected']) == ROOT_FAILURES, 'root rejection manifest differs')
            positive('repaired_root_proof', root_tx, machine.witness(root_tx, program, rows, 2), rows, 2)
            base.require(rpc('getrawmempool') == [], 'negative root cases changed the mempool')

            def observe_input(tx, record):
                item = tx.inputs[0]
                coin = rpc('gettxout', [item.txid[::-1].hex(), item.index])
                base.require(coin is not None, 'transition input is unavailable')
                amount = base.satoshis(coin['value'])
                base.require(amount == item.amount and coin['scriptPubKey']['hex'] == item.script.hex(),
                             'observed input differs from the transition context')
                record['observed_input_sats'] = amount
                record['input']['observed_amount_sats'] = amount

            def confirm_batch(batch, height):
                for tx, witness, record in batch:
                    observe_input(tx, record)
                    admission = rpc('testmempoolaccept', [[record['raw_tx']]])[0]
                    record['admission'] = admission
                    base.require(admission['allowed'] is True, 'valid transition rejected')
                    base.require(rpc('sendrawtransaction', [record['raw_tx']]) == record['txid'],
                                 'transition transaction identity differs')
                block = rpc('generatetoaddress', [1, mining_address])[0]
                observed = {item['txid']: item for item in rpc('getblock', [block, 2])['tx']}
                base.require(rpc('getblockcount') == height, 'transition confirmation height differs')
                for tx, witness, record in batch:
                    base.require(record['txid'] in observed, 'transition not present in the mined block')
                    actual_outputs = decoded_outputs(observed[record['txid']])
                    base.require(actual_outputs == output_rows(tx.outputs), 'confirmed output vector differs')
                    actual_fee = record['observed_input_sats']-sum(item['amount_sats'] for item in actual_outputs)
                    base.require(actual_fee == 2_000, 'confirmed transition fee differs')
                    record.update(block=block, confirmed_height=height, observed_outputs=actual_outputs,
                                  observed_fee_sats=actual_fee)

            first_batch = [checked_transition(program, funding_id, index, path[0], path, 0)
                           for index, path in enumerate(PATHS)]
            report['transitions'].extend(item[2] for item in first_batch)
            confirm_batch(first_batch, 103)
            node.stop()
            base.require(node.start()['blocks'] == 103, 'first restart lost height')

            def check_persistent(records, terminal_done):
                by_path = {tuple(record['path']): record for record in records if record['stage'] == 1}
                for record in records:
                    coin = record['input']
                    base.require(rpc('gettxout', [coin['txid'], coin['vout']]) is None,
                                 'restart restored a consumed input')
                    payout = rpc('gettxout', [record['txid'], 0])
                    base.require(payout is not None and base.satoshis(payout['value']) == record['outputs'][0]['amount_sats']
                                 and payout['scriptPubKey']['hex'] == record['outputs'][0]['script_pubkey'],
                                 'restart changed a payout')
                    decoded = next(item for item in rpc('getblock', [record['block'], 2])['tx']
                                   if item['txid'] == record['txid'])
                    base.require(decoded_outputs(decoded) == record['observed_outputs'],
                                 'restart changed the committed output vector')
                    if record['stage'] == 0:
                        successor = rpc('gettxout', [record['txid'], 1])
                        if terminal_done:
                            base.require(tuple(record['path']) in by_path and successor is None,
                                         'terminal transition failed to consume its successor')
                        else:
                            base.require(successor is not None
                                         and base.satoshis(successor['value']) == record['outputs'][1]['amount_sats']
                                         and successor['scriptPubKey']['hex'] == record['outputs'][1]['script_pubkey'],
                                         'restart lost the required successor')
                spare_coin = rpc('gettxout', [funding_id, 4])
                base.require(spare_coin is not None and base.satoshis(spare_coin['value']) == 100_000,
                             'additional-input attack consumed the spare coin')
                base.require(rpc('getconnectioncount') == 0, 'unexpected regtest peer after restart')

            check_persistent(report['transitions'], False)
            report['restart_checks'].append({'height': 103, 'preserved': True})
            child = program.branch(9).successor
            first_parent = first_batch[0][2]['txid']
            child_tx, child_witness = machine.build_spend(child, first_parent, 1, 2)
            child_rows = expected_trace(9, 2)
            child_other, child_other_witness = machine.build_spend(child, first_parent, 1, 3)
            positive('child_delta2', child_tx, child_witness, child_rows, 2)
            positive('child_delta3', child_other, child_other_witness, expected_trace(9, 3), 3)
            report['both_child_alternatives_eligible'] = True
            reject('proof_replay_successor', child, child_tx,
                   machine.witness(child_tx, child, rows, 2), rows, 2)
            valid_wrong_old = (6, 9, 12, 15)
            reject('wrong_old_state_successor_valid_trace', child, child_tx,
                   machine.witness(child_tx, child, valid_wrong_old, 3), valid_wrong_old, 3)
            changed_commitment = child_tx.outputs[1].script[:-1]+bytes([child_tx.outputs[1].script[-1]^1])
            for name, outputs in (
                ('terminal_state_commitment_change', (child_tx.outputs[0],
                    replace(child_tx.outputs[1], script=changed_commitment))),
                ('terminal_recipient_change', (replace(child_tx.outputs[0],
                    script=b'\x51\x20'+base.RECIPIENTS[1]), child_tx.outputs[1])),
                ('terminal_payout_amount_change', (replace(child_tx.outputs[0], amount=86_999),
                    child_tx.outputs[1])),
                ('terminal_output_reordered', tuple(reversed(child_tx.outputs))),
            ):
                changed_tx = replace(child_tx, outputs=outputs)
                reject(name, child, changed_tx, machine.witness(changed_tx, child, child_rows, 2), child_rows, 2)
            base.require(set(report['rejected']) == ROOT_FAILURES | CHILD_FAILURES,
                         'successor rejection manifest differs')
            base.require(rpc('getrawmempool') == [], 'negative successor cases changed the mempool')
            second_batch = []
            for path, first in zip(PATHS, first_batch):
                successor = program.branch(first[2]['new_state']).successor
                second_batch.append(checked_transition(successor, first[2]['txid'], 1, path[1], path, 1))
            report['transitions'].extend(item[2] for item in second_batch)
            confirm_batch(second_batch, 104)
            node.stop()
            base.require(node.start()['blocks'] == 104, 'second restart lost height')
            check_persistent(report['transitions'], True)
            report['restart_checks'].append({'height': 104, 'preserved': True})
            reject('spent_input_replay', program, alternate_tx, alternate_witness, expected_trace(3, 3), 3)
            base.require(set(report['rejected']) == EXPECTED_FAILURES, 'final rejection manifest differs')
            base.require(rpc('getrawmempool') == [], 'unexpected mempool residue')
            peers = rpc('getconnectioncount')
            base.require(peers == 0, 'unexpected peer at fixture completion')
            report.update(status='passed', peer_count=peers, final_height=104,
                          rejection_count=len(report['rejected']), confirmed_transitions=8,
                          restart_preserved_outputs=True)
        except BaseException as error:
            report.update(status='failed', error=f'{type(error).__name__}: {error}')
            raise
        finally:
            try:
                if node is not None:
                    node.stop()
            except BaseException as error:
                report.update(status='failed', shutdown_error=f'{type(error).__name__}: {error}')
                raise
            finally:
                if node is not None:
                    node.log.close()
                report['node_exit_codes'] = list(node.exit_codes) if node is not None else []
                report['clean_shutdowns'] = bool(report['node_exit_codes']) and all(
                    code == 0 for code in report['node_exit_codes'])
                if report['status'] == 'passed' and report['node_exit_codes'] != [0, 0, 0]:
                    report.update(status='failed', shutdown_error='three clean node exits required')
                report['finished_at'] = now()
                with (output/'report.json').open('x') as stream:
                    stream.write(json.dumps(report, indent=2)+'\n')
                if (root/'node.log').exists():
                    with (output/'node.log').open('xb') as stream:
                        stream.write((root/'node.log').read_bytes())
    base.require(report['status'] == 'passed', 'state machine fixture failed')
    print(json.dumps({'status': report['status'], 'confirmed_transitions': 8,
                      'rejection_count': report['rejection_count'], 'report': str(output/'report.json')}, indent=2))
    return report


def main():
    def interrupted(signum, _frame):
        raise KeyboardInterrupt(f'interrupted by signal {signum}')

    signal.signal(signal.SIGTERM, interrupted)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    run(args.binary, args.output)


if __name__ == '__main__':
    main()
