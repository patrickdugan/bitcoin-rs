#!/usr/bin/env python3
"""Exercise competing F17 spends, controlled rollback, and native recovery."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import signal
import tempfile

import keyless_checksig_rpc as base
import keyless_checksig_testnet4 as block_wire
import keyless_state_machine as machine
import keyless_state_machine_rpc as forward


SNAPSHOTS = (
    'funded', 'candidate_b_prepared', 'a_parent_pending', 'a_family_pending',
    'a_parent_confirmed', 'a_family_confirmed', 'a_confirmed_restarted',
    'rewound', 'rewound_restarted', 'b_parent_confirmed', 'b_child_pending',
    'b_family_confirmed', 'b_confirmed_restarted',
)
REJECTIONS = frozenset((
    'child_without_parent', 'equal_fee_parent', 'conflict_with_child',
    'replayed_old_state', 'stale_a_child',
))


def now():
    return datetime.now(timezone.utc).isoformat()


def coin_row(value):
    if value is None:
        return None
    return {'amount_sats': base.satoshis(value['value']),
            'script_pubkey': value['scriptPubKey']['hex'],
            'confirmations': value['confirmations'], 'coinbase': value['coinbase'],
            'bestblock': value['bestblock']}


def entry_row(value):
    return {'depends': sorted(value['depends']), 'spentby': sorted(value['spentby']),
            'ancestorcount': value['ancestorcount'], 'descendantcount': value['descendantcount'],
            'ancestorsize': value['ancestorsize'], 'descendantsize': value['descendantsize'],
            'vsize': value['vsize'], 'wtxid': value['wtxid'],
            'fees_sats': {key: base.satoshis(amount) for key, amount in value['fees'].items()}}


def run(binary: Path, output: Path) -> dict:
    base.require_assertions()
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    report = {'schema_version': 1, 'fixture': 'keyless-state-lifecycle', 'status': 'running',
              'started_at': now(), 'network': 'regtest', 'program_id': machine.PROGRAM_ID.hex(),
              'scope': 'Competing finite F17 spends with explicit invalidation and branch rebuilding; '
                       'isolated native regtest, full traces, fixed fees, and persisted recovery.',
              'transactions': {}, 'blocks': {}, 'admissions': {}, 'rejected': {},
              'snapshots': {}, 'operations': {}, 'restart_checks': [], 'coinbase_checks': {},
              'script_signatures': 0}
    node = None
    with tempfile.TemporaryDirectory(prefix='keyless-state-lifecycle-') as directory:
        root = Path(directory)
        try:
            binary = binary.resolve(strict=True)
            base.require(binary.is_file() and os.access(binary, os.X_OK), 'node binary is not executable')
            report['binary_sha256'] = hashlib.sha256(binary.read_bytes()).hexdigest()
            program = machine.compile_machine()
            root_spk, _ = program.leaf.output()
            funding_leaf = base.Leaf(b'\x51')
            funding_spk, funding_control = funding_leaf.output()
            mining = {'funding': base.address(funding_spk[2:]),
                      'a': base.address(base.RECIPIENTS[0]), 'b': base.address(base.RECIPIENTS[1])}
            mining_scripts = {'funding': funding_spk.hex(),
                              'a': (b'\x51\x20' + base.RECIPIENTS[0]).hex(),
                              'b': (b'\x51\x20' + base.RECIPIENTS[1]).hex()}
            node = base.Node(binary, root)
            rpc = node.rpc
            base.require(node.start()['blocks'] == 0, 'fresh regtest data required')
            maturity = rpc('generatetoaddress', [101, mining['funding']])
            base.require(len(maturity) == 101, 'coinbase maturity blocks missing')
            source = rpc('getblock', [maturity[0], 2])['tx'][0]
            source_output = next(item for item in source['vout']
                                 if item['scriptPubKey']['hex'] == funding_spk.hex())
            source_amount = base.satoshis(source_output['value'])
            base.require(source_amount == 5_000_000_000, 'unexpected regtest subsidy')
            funding = base.Tx((base.Input(bytes.fromhex(source['txid'])[::-1], source_output['n'],
                                          source_amount, funding_spk),),
                              (base.Output(100_000, root_spk),
                               base.Output(source_amount - 102_000, funding_spk)))
            funding_raw, funding_id = funding.serialize([[funding_leaf.script, funding_control]])
            preview = rpc('testmempoolaccept', [[funding_raw]])[0]
            base.require(preview['allowed'] is True, 'funding preview rejected')
            base.require(rpc('sendrawtransaction', [funding_raw]) == funding_id, 'funding identity differs')
            funding_block = rpc('generateblock', [mining['funding'], [funding_raw]])['hash']
            base.require(rpc('getblockcount') == 102, 'funding height differs')
            report['funding'] = {'raw_tx': funding_raw, 'txid': funding_id,
                'wtxid': base.sha(base.sha(bytes.fromhex(funding_raw)))[::-1].hex(),
                'input': forward.describe_input(funding.inputs[0]),
                'witness_hex': [funding_leaf.script.hex(), funding_control.hex()],
                'outputs': forward.output_rows(funding.outputs, ('root', 'change')),
                'fee_sats': 2_000, 'admission': preview, 'block': funding_block, 'height': 102}

            txs = {}
            for family, path, result in (('a', (2, 2), 9), ('b', (3, 2), 12)):
                parent_name, child_name = family + '_parent', family + '_child'
                parent = forward.checked_transition(program, funding_id, 0, path[0], path, 0)
                child = forward.checked_transition(program.branch(result).successor,
                    parent[2]['txid'], 1, path[1], path, 1)
                for name, item in ((parent_name, parent), (child_name, child)):
                    txs[name] = item
                    record = item[2]
                    record['wtxid'] = base.sha(base.sha(bytes.fromhex(record['raw_tx'])))[::-1].hex()
                    report['transactions'][name] = record
            coin_refs = {'root': (funding_id, 0, funding.outputs[0]),
                         'change': (funding_id, 1, funding.outputs[1])}
            for family in ('a', 'b'):
                parent, child = txs[family + '_parent'], txs[family + '_child']
                for label, item, vout in ((family + '_payout', parent, 0),
                    (family + '_successor', parent, 1), (family + '_terminal', child, 0),
                    (family + '_commitment', child, 1)):
                    coin_refs[label] = (item[2]['txid'], vout, item[0].outputs[vout])

            def capture():
                info = rpc('getblockchaininfo')
                pool = rpc('getrawmempool', [False, True])
                base.require(info['chain'] == 'regtest', 'chain identity changed')
                base.require(info['is_apply_halted'] is False and info['is_closed_for_recovery'] is False,
                             'node closed its apply path')
                peers = rpc('getconnectioncount')
                base.require(peers == 0, 'unexpected regtest peer')
                return {'height': info['blocks'], 'bestblock': info['bestblockhash'],
                    'height_hash': rpc('getblockhash', [info['blocks']]), 'peer_count': peers,
                    'is_apply_halted': info['is_apply_halted'],
                    'is_closed_for_recovery': info['is_closed_for_recovery'],
                    'mempool': {'txids': sorted(pool['txids']), 'mempool_sequence': pool['mempool_sequence']},
                    'entries': {txid: entry_row(rpc('getmempoolentry', [txid])) for txid in sorted(pool['txids'])},
                    'coins': {label: {'chain': coin_row(rpc('gettxout', [txid, vout, False])),
                                      'overlay': coin_row(rpc('gettxout', [txid, vout, True]))}
                              for label, (txid, vout, _) in coin_refs.items()}}

            def snapshot(name, height, tip, confirmed, pending):
                state = capture()
                report['snapshots'][name] = state
                base.require(state['height'] == height and state['bestblock'] == tip
                             and state['height_hash'] == tip, name + ': applied tip differs')
                ids = {txs[item][2]['txid'] for item in pending}
                base.require(set(state['mempool']['txids']) == ids, name + ': mempool membership differs')
                chain = {'root': 102, 'change': 102}
                for family in ('a', 'b'):
                    parent_name, child_name = family + '_parent', family + '_child'
                    if parent_name in confirmed:
                        chain.pop('root', None)
                        chain[family + '_payout'] = confirmed[parent_name]
                        chain[family + '_successor'] = confirmed[parent_name]
                    if child_name in confirmed:
                        chain.pop(family + '_successor', None)
                        chain[family + '_terminal'] = confirmed[child_name]
                overlay = dict(chain)
                for family in ('a', 'b'):
                    if family + '_parent' in pending:
                        overlay.pop('root', None)
                        overlay[family + '_payout'] = overlay[family + '_successor'] = None
                    if family + '_child' in pending:
                        overlay.pop(family + '_successor', None)
                        overlay[family + '_terminal'] = overlay[family + '_commitment'] = None
                for label, (_, _, item) in coin_refs.items():
                    for view_name, expected in (('chain', chain), ('overlay', overlay)):
                        observed = state['coins'][label][view_name]
                        if label not in expected:
                            base.require(observed is None, name + ': unexpected ' + view_name + ' coin ' + label)
                            continue
                        confs = 0 if expected[label] is None else height - expected[label] + 1
                        base.require(observed == {'amount_sats': item.amount, 'script_pubkey': item.script.hex(),
                            'confirmations': confs, 'coinbase': False, 'bestblock': tip},
                            name + ': incorrect ' + view_name + ' coin ' + label)
                for item in pending:
                    txid = txs[item][2]['txid']
                    entry = state['entries'][txid]
                    family, kind = item.split('_')
                    parent_name, child_name = family + '_parent', family + '_child'
                    depends = [txs[parent_name][2]['txid']] if kind == 'child' and parent_name in pending else []
                    spentby = [txs[child_name][2]['txid']] if kind == 'parent' and child_name in pending else []
                    base.require(entry['depends'] == depends and entry['spentby'] == spentby,
                                 name + ': dependency links differ')
                    base.require(entry['ancestorcount'] == 1 + len(depends)
                                 and entry['descendantcount'] == 1 + len(spentby)
                                 and entry['fees_sats'] == {'base': 2_000, 'modified': 2_000,
                                     'chunk': 2_000,
                                     'ancestor': 2_000 * (1 + len(depends)),
                                     'descendant': 2_000 * (1 + len(spentby))},
                                 name + ': dependency values differ')
                    base.require(entry['wtxid'] == txs[item][2]['wtxid'], name + ': resident witness differs')
                return state

            def block_record(label, block_hash, raw, height, previous, expected_raw, branch):
                parsed = block_wire.validate_block(bytes.fromhex(raw), block_hash)
                base.require(parsed['previous'] == previous and parsed['tx_count'] == 2,
                             label + ': block ancestry or transaction count differs')
                base.require(parsed['transactions'][1]['raw'] == expected_raw,
                             label + ': block contains a different transaction')
                decoded = rpc('decoderawtransaction', [parsed['transactions'][0]['raw']])
                coinbase = {'txid': decoded['txid'], 'vout': 0,
                            'amount_sats': base.satoshis(decoded['vout'][0]['value']),
                            'script_pubkey': decoded['vout'][0]['scriptPubKey']['hex']}
                base.require(0 <= coinbase['amount_sats'] <= 5_000_002_000
                             and coinbase['script_pubkey'] == mining_scripts[branch],
                             label + ': coinbase payout differs: ' + str(coinbase))
                return {'hash': block_hash, 'raw_block': raw, 'previous': previous, 'height': height,
                        'txids': [item['txid'] for item in parsed['transactions']], 'coinbase': coinbase}

            funding_previous = rpc('getblockhash', [101])
            report['blocks']['funding'] = block_record('funding', funding_block,
                rpc('getblock', [funding_block, 0]), 102, funding_previous, funding_raw, 'funding')
            snapshot('funded', 102, funding_block, {}, set())

            def admit(name, submit=True):
                record = txs[name][2]
                before = capture()
                dry = rpc('testmempoolaccept', [[record['raw_tx']]])[0]
                after_preview = capture()
                entry = {'transaction': name, 'dry_run': dry, 'before': before,
                         'after_preview': after_preview}
                report['admissions'][name] = entry
                base.require(before == after_preview, name + ': preview changed state')
                base.require(dry['allowed'] is True and dry['txid'] == record['txid']
                             and dry['wtxid'] == record['wtxid'], name + ': honest preview rejected')
                if submit:
                    entry['submitted_txid'] = rpc('sendrawtransaction', [record['raw_tx']])
                    base.require(entry['submitted_txid'] == record['txid'], name + ': admission identity differs')

            def reject(name, transaction, boundary, witness=None, rows=None, delta=None, preview_only=False):
                tx, original_witness, record = txs[transaction]
                witness = original_witness if witness is None else witness
                raw, txid = tx.serialize([witness])
                entry = {'transaction': transaction, 'boundary': boundary, 'raw_tx': raw, 'txid': txid,
                    'wtxid': base.sha(base.sha(bytes.fromhex(raw)))[::-1].hex(),
                    'witness_hex': [item.hex() for item in witness],
                    'trace': list(record['trace'] if rows is None else rows),
                    'delta': record['delta'] if delta is None else delta, 'before': capture()}
                report['rejected'][name] = entry
                reason, code, message = {
                    'replacement_fee': ('insufficient fee', -26, 'insufficient fee'),
                    'script': ('script-verify-flag-failed', -26, 'consensus-verification-failed'),
                    'missing_inputs': ('missing-inputs', -25, 'bad-txns-inputs-missingorspent'),
                }[boundary]
                dry = rpc('testmempoolaccept', [[raw]])[0]
                entry['dry_run'] = dry
                base.require(dry['allowed'] is False and dry.get('reject-reason') == reason,
                             name + ': unexpected preview boundary: ' + str(dry))
                if not preview_only:
                    try:
                        rpc('sendrawtransaction', [raw])
                    except base.RpcError as error:
                        entry['admission'] = error.error
                        base.require(error.error == {'code': code, 'message': message},
                                     name + ': unexpected broadcast boundary: ' + str(error.error))
                    else:
                        raise ValueError(name + ': rejected transaction entered mempool')
                    if boundary != 'replacement_fee':
                        try:
                            rpc('generateblock', [mining['b'], [raw]])
                        except base.RpcError as error:
                            entry['block_error'] = error.error
                            expected = ('block-script-verify-flag-failed' if boundary == 'script'
                                        else 'bad-txns-inputs-missingorspent')
                            base.require(error.error['code'] == -25 and expected in error.error['message'],
                                         name + ': unexpected direct-block boundary: ' + str(error.error))
                        else:
                            raise ValueError(name + ': rejected transaction entered block')
                entry['after'] = capture()
                base.require(entry['before'] == entry['after'], name + ': rejection changed state')

            reject('child_without_parent', 'a_child', 'missing_inputs', preview_only=True)
            admit('b_parent', submit=False)
            candidate = rpc('generateblock', [mining['b'], [txs['b_parent'][2]['raw_tx']], False])
            report['candidate_b'] = block_record('candidate_b', candidate['hash'], candidate['hex'],
                103, funding_block, txs['b_parent'][2]['raw_tx'], 'b')
            snapshot('candidate_b_prepared', 102, funding_block, {}, set())
            base.require(report['snapshots']['candidate_b_prepared'] == report['snapshots']['funded'],
                         'preparing an unsubmitted block changed state')
            admit('a_parent')
            snapshot('a_parent_pending', 102, funding_block, {}, {'a_parent'})
            reject('equal_fee_parent', 'b_parent', 'replacement_fee')
            admit('a_child')
            snapshot('a_family_pending', 102, funding_block, {}, {'a_parent', 'a_child'})
            reject('conflict_with_child', 'b_parent', 'replacement_fee')

            def observe_confirmation(name, block_hash, height, previous, input_amount):
                tx, _, record = txs[name]
                decoded = rpc('getblock', [block_hash, 2])
                base.require(decoded['height'] == height and decoded['previousblockhash'] == previous,
                             name + ': confirmation ancestry differs')
                actual = next(item for item in decoded['tx'] if item['txid'] == record['txid'])
                outputs = forward.decoded_outputs(actual)
                base.require(outputs == forward.output_rows(tx.outputs), name + ': confirmed outputs differ')
                fee = input_amount - sum(item['amount_sats'] for item in outputs)
                base.require(fee == 2_000, name + ': confirmed fee differs')
                raw = rpc('getblock', [block_hash, 0])
                report['blocks'][name] = block_record(name, block_hash, raw, height, previous,
                                                     record['raw_tx'], name[0])
                record.update(block=block_hash, confirmed_height=height, observed_input_sats=input_amount,
                              observed_outputs=outputs, observed_fee_sats=fee)

            def mine(name, height, previous):
                record = txs[name][2]
                spent = record['input']
                coin = coin_row(rpc('gettxout', [spent['txid'], spent['vout'], False]))
                base.require(coin is not None and coin['amount_sats'] == spent['amount_sats']
                             and coin['script_pubkey'] == spent['script_pubkey'], name + ': input differs')
                result = rpc('generateblock', [mining[name[0]], [record['raw_tx']]])
                observe_confirmation(name, result['hash'], height, previous, coin['amount_sats'])
                return result['hash']

            a_block = mine('a_parent', 103, funding_block)
            snapshot('a_parent_confirmed', 103, a_block, {'a_parent': 103}, {'a_child'})
            a_child_block = mine('a_child', 104, a_block)
            a_confirmed = {'a_parent': 103, 'a_child': 104}
            snapshot('a_family_confirmed', 104, a_child_block, a_confirmed, set())

            def restart(before_name, after_name, height, tip, confirmed, pending):
                before = report['snapshots'][before_name]
                node.stop()
                base.require(node.start()['blocks'] == height, after_name + ': restart height differs')
                after = snapshot(after_name, height, tip, confirmed, pending)
                left, right = dict(before), dict(after)
                left['mempool'] = {'txids': before['mempool']['txids']}
                right['mempool'] = {'txids': after['mempool']['txids']}
                base.require(left == right, after_name + ': restart changed visible state')
                report['restart_checks'].append({'before': before_name, 'after': after_name,
                                                'height': height, 'bestblock': tip, 'preserved': True})

            restart('a_family_confirmed', 'a_confirmed_restarted', 104, a_child_block, a_confirmed, set())
            before = capture()
            stale = rpc('submitblock', [candidate['hex']])
            after = capture()
            report['operations']['stale_b_submit'] = {'raw_block': candidate['hex'], 'before': before,
                                                    'result': stale, 'after': after}
            base.require(stale == 'inconclusive-not-best-prevblk' and before == after,
                         'stale-parent block submission changed the chain or returned a different boundary')
            before = capture()
            invalidated = rpc('invalidateblock', [a_block])
            base.require(invalidated is None, 'invalidateblock returned an unexpected result')
            rewound = snapshot('rewound', 102, funding_block, {}, {'a_parent', 'a_child'})
            report['operations']['invalidate'] = {'block': a_block, 'before': before,
                                                 'result': invalidated, 'after': rewound}

            def check_coinbases(snapshot_name, active):
                state = report['snapshots'][snapshot_name]
                known = {key: value for key, value in report['blocks'].items() if key != 'funding'}
                known.setdefault('b_parent', report['candidate_b'])
                observed = {}
                for name, block in known.items():
                    coin = block['coinbase']
                    views = {'chain': coin_row(rpc('gettxout', [coin['txid'], coin['vout'], False])),
                             'overlay': coin_row(rpc('gettxout', [coin['txid'], coin['vout'], True]))}
                    observed[name] = views
                    expected = None
                    if name in active:
                        expected = {'amount_sats': coin['amount_sats'], 'script_pubkey': coin['script_pubkey'],
                                    'coinbase': True, 'bestblock': state['bestblock'],
                                    'confirmations': state['height'] - block['height'] + 1}
                    base.require(views == {'chain': expected, 'overlay': expected},
                                 snapshot_name + ': fork coinbase differs: ' + name)
                report['coinbase_checks'][snapshot_name] = observed

            check_coinbases('rewound', set())
            restart('rewound', 'rewound_restarted', 102, funding_block, {}, {'a_parent', 'a_child'})
            check_coinbases('rewound_restarted', set())
            before = capture()
            restored = before['coins']['root']['chain']
            base.require(restored is not None and restored['amount_sats'] == 100_000,
                         'root reserve was not restored before alternative submission')
            submitted = rpc('submitblock', [candidate['hex']])
            base.require(submitted is None, 'saved alternative block was refused')
            b_block = candidate['hash']
            observe_confirmation('b_parent', b_block, 103, funding_block, restored['amount_sats'])
            base.require(report['blocks']['b_parent'] == report['candidate_b'],
                         'accepted alternative differs from the saved block')
            switched = snapshot('b_parent_confirmed', 103, b_block, {'b_parent': 103}, set())
            report['operations']['submit_b'] = {'raw_block': candidate['hex'], 'before': before,
                                               'result': submitted, 'after': switched}
            b_stage = program.branch(12).successor
            replay = (9, 12, 15, 1)
            bad_witness = machine.witness(txs['b_child'][0], b_stage, replay, 3)
            reject('replayed_old_state', 'b_child', 'script', bad_witness, replay, 3)
            base.require('NUMEQUALVERIFY' in report['rejected']['replayed_old_state']['block_error']['message'],
                         'stale-state proof failed outside the committed-state guard')
            admit('b_child')
            snapshot('b_child_pending', 103, b_block, {'b_parent': 103}, {'b_child'})
            b_child_block = mine('b_child', 104, b_block)
            b_confirmed = {'b_parent': 103, 'b_child': 104}
            snapshot('b_family_confirmed', 104, b_child_block, b_confirmed, set())
            base.require(b_child_block != a_child_block, 'winner retained the discarded tip identity')
            check_coinbases('b_family_confirmed', {'b_parent', 'b_child'})
            reject('stale_a_child', 'a_child', 'missing_inputs')
            restart('b_family_confirmed', 'b_confirmed_restarted', 104, b_child_block, b_confirmed, set())
            check_coinbases('b_confirmed_restarted', {'b_parent', 'b_child'})
            base.require(tuple(report['snapshots']) == SNAPSHOTS, 'snapshot manifest differs')
            base.require(set(report['rejected']) == REJECTIONS, 'rejection manifest differs')
            report.update(status='passed', final_height=104, final_tip=b_child_block, final_state=1,
                          active_family='b', confirmed_transitions=4, rewind_depth=2,
                          peer_count=0, rejection_count=len(REJECTIONS), restart_preserved_state=True)
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
                if report['status'] == 'passed' and report['node_exit_codes'] != [0, 0, 0, 0]:
                    report.update(status='failed', shutdown_error='four clean node exits required')
                report['finished_at'] = now()
                with (output / 'report.json').open('x') as stream:
                    stream.write(json.dumps(report, indent=2) + '\n')
                if (root / 'node.log').exists():
                    with (output / 'node.log').open('xb') as stream:
                        stream.write((root / 'node.log').read_bytes())
    base.require(report['status'] == 'passed', 'state lifecycle fixture failed')
    print(json.dumps({'status': report['status'], 'confirmed_transitions': 4,
                      'rejection_count': report['rejection_count'], 'report': str(output / 'report.json')}, indent=2))
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
