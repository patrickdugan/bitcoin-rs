"""Fund CPA outputs and test native Script, mempool, block, and restart behavior.

This disclosed-trace fixture uses only fresh local regtest data and zero peers.
The node must contain the independently gated TXCOMMIT and CAT research features.
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

import canonical_proof_authority as cpa
import cpa_transition as machine
import keyless_checksig_rpc as base


def run(binary: Path, output: Path) -> dict:
    base.require_assertions()
    binary = binary.resolve(strict=True)
    base.require(binary.is_file() and os.access(binary, os.X_OK), 'executable required')
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    report = {'schema_version': 1, 'fixture': 'canonical-proof-authority', 'status': 'running',
              'network': 'regtest', 'started_at': datetime.now(timezone.utc).isoformat(),
              'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
              'dependency_commit': '188e2d78fbb623a12a42772120a2aa4e437905c1',
              'profile': 'disclosed-NAND / two-leaf NUMS P2TR / TXCOMMIT2 / CAT',
              'zero_knowledge': False, 'singleton_lineage': False,
              'positive': {}, 'rejected': {}, 'transitions': [], 'restarts': []}
    sources = (Path(__file__), Path(machine.__file__), Path(cpa.__file__), Path(base.__file__))
    report['source_sha256'] = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in sources}
    node = None
    with tempfile.TemporaryDirectory(prefix='cpa-regtest-') as directory:
        root = Path(directory)
        try:
            stage = machine.compile_machine()
            renamed = machine.compile_machine({'v': ('input', 1), 's': ('input', 2),
                'g': ('nand', 'v', 'u'), 'u': ('input', 0), 'p': ('nand', 'g', 'g')}, ('p', 's'))
            base.require(stage.descriptor.encode() == renamed.descriptor.encode() and
                         stage.leaf.output() == renamed.leaf.output(), 'canonical compilation differs')
            next_epoch = machine.compile_machine(epoch=1)
            wider = machine.compile_machine(cap=9000)
            root_spk = stage.leaf.output()[0]
            coinbase_leaf = base.Leaf(b'\x51')
            coinbase_spk, coinbase_control = coinbase_leaf.output()
            address = base.address(coinbase_spk[2:])
            report['authority'] = {'program_id': stage.program.program_id.hex(),
                'authority_id': stage.authority.hex(), 'state_root': stage.state_root.hex(),
                'descriptor_hex': stage.descriptor.encode().hex(), 'script_hex': stage.leaf.script.hex(),
                'script_bytes': len(stage.leaf.script), 'script_pubkey': root_spk.hex(),
                'address': base.address(root_spk[2:]), 'canonical_copy_equal': True,
                'grant_id': stage.grant.hex(), 'payout_cap_sats': stage.cap}
            node = base.Node(binary, root)
            rpc = node.rpc
            base.require(node.start()['blocks'] == 0, 'fresh chain required')
            blocks = rpc('generatetoaddress', [101, address])
            coinbase = rpc('getblock', [blocks[0], 2])['tx'][0]
            source = next(item for item in coinbase['vout'] if item['scriptPubKey']['hex'] == coinbase_spk.hex())
            amount = base.satoshis(source['value'])
            funding = base.Tx((base.Input(bytes.fromhex(coinbase['txid'])[::-1], source['n'],
                                          amount, coinbase_spk),),
                 (base.Output(100_000, root_spk), base.Output(100_000, root_spk),
                  base.Output(100_000, next_epoch.leaf.output()[0]),
                  base.Output(100_000, wider.leaf.output()[0]), base.Output(100_000, coinbase_spk),
                  base.Output(amount-500_000-2000, coinbase_spk)))
            funding_raw, funding_id = funding.serialize([[coinbase_leaf.script, coinbase_control]])
            base.require(rpc('sendrawtransaction', [funding_raw]) == funding_id, 'funding identity')
            block = rpc('generatetoaddress', [1, address])[0]
            base.require(funding_id in rpc('getblock', [block])['tx'], 'funding absent')
            report['funding'] = {'txid': funding_id, 'raw_tx': funding_raw, 'block': block, 'height': 102}

            def positive(name, tx, witness):
                raw, txid = tx.serialize([witness])
                observed = rpc('testmempoolaccept', [[raw]])[0]
                report['positive'][name] = {'raw_tx': raw, 'txid': txid, 'admission': observed}
                base.require(observed['allowed'] is True, name+' positive control: '+str(observed))

            def reject(name, tx, witness, others=(), boundary='script'):
                base.require(name not in report['rejected'], 'duplicate attack name')
                raw, txid = tx.serialize([witness] + list(others))
                height, tip = rpc('getblockcount'), rpc('getbestblockhash')
                entry = {'raw_tx': raw, 'txid': txid, 'expected_boundary': boundary,
                         'height_before': height, 'tip_before': tip}
                report['rejected'][name] = entry
                dry = rpc('testmempoolaccept', [[raw]])[0]
                entry['dry_run'] = dry
                expected = {'script': 'script-verify-flag-failed',
                            'standardness': 'bad-witness-nonstandard', 'spent': 'missing-inputs',
                            'duplicate': 'missing-inputs'}[boundary]
                base.require(dry['allowed'] is False and dry.get('reject-reason') == expected,
                             name+' wrong mempool boundary: '+str(dry))
                try:
                    rpc('sendrawtransaction', [raw])
                except base.RpcError as error:
                    entry['broadcast_error'] = error.error
                    base.require(error.error['code'] == (-25 if boundary in ('spent', 'duplicate') else -26),
                                 name+' wrong broadcast error')
                else:
                    raise ValueError(name+' entered mempool')
                try:
                    rpc('generateblock', [address, [raw]])
                except base.RpcError as error:
                    entry['block_error'] = error.error
                    token = {'spent': 'bad-txns-inputs-missingorspent', 'duplicate': 'bad-txns-BIP30'}.get(
                        boundary, 'block-script-verify-flag-failed')
                    base.require(error.error['code'] == -25 and token in error.error.get('message', ''),
                                 name+' wrong block boundary: '+str(error.error))
                else:
                    raise ValueError(name+' entered block')
                entry['height_after'], entry['tip_after'] = rpc('getblockcount'), rpc('getbestblockhash')
                base.require((entry['height_after'], entry['tip_after']) == (height, tip),
                             name+' mutated applied chain')

            tx, proof = machine.spend(stage, funding_id, 0)
            second, second_proof = machine.spend(renamed, funding_id, 1)
            positive('canonical_first_coin', tx, proof)
            positive('canonical_duplicate_coin', second, second_proof)
            valid_wide, wide_proof = machine.spend(wider, funding_id, 3, (1, 1, 1))
            positive('wider_guard_same_child_relation', valid_wide, wide_proof)
            epoch_tx, epoch_proof = machine.spend(next_epoch, funding_id, 2)
            positive('new_epoch_fresh_proof', epoch_tx, epoch_proof)
            denied, denied_proof = machine.spend(stage, funding_id, 0, (1, 1, 1))
            reject('parent_cap_with_valid_child_trace', denied, denied_proof)
            for bits in ((0, 0, 0), (0, 1, 0), (1, 0, 0)):
                failed, bad_proof = machine.spend(stage, funding_id, 0, bits)
                reject('child_permission_'+''.join(map(str, bits)), failed, bad_proof)
            for index, name in enumerate(machine.FIELDS):
                changed = proof.copy()
                changed[index] = bytes(len(proof[index]))
                reject('substituted_'+name, tx, changed)
            for offset, (key, record) in enumerate(stage.program.records, len(machine.FIELDS)):
                if record[0] == 2:
                    changed = proof.copy()
                    changed[offset] = b'' if proof[offset] else b'\x01'
                    reject('broken_gate_'+key.hex()[:12], tx, changed)
            gate_offset = len(machine.FIELDS)
            for name, value in (('negative_zero', b'\x80'), ('nonminimal_one', b'\x01\x00'),
                                ('out_of_range_bit', b'\x02')):
                changed = proof.copy()
                changed[gate_offset] = value
                reject(name, tx, changed)
            reject('duplicate_coin_stale_proof', second, proof)
            mixed = second_proof.copy()
            mixed[machine.FIELDS.index('child_statement')] = proof[machine.FIELDS.index('child_statement')]
            reject('duplicate_coin_stale_child_statement', second, mixed)
            mixed = epoch_proof.copy()
            mixed[machine.FIELDS.index('parent_id')] = stage.authority
            reject('cross_authority_parent_rebinding', epoch_tx, mixed)
            mixed = epoch_proof.copy()
            mixed[machine.FIELDS.index('state_opening')] = stage.state
            reject('stale_epoch_opening', epoch_tx, mixed)
            output_mutations = {
                'payout_minus_one': (replace(tx.outputs[0], amount=6999), tx.outputs[1]),
                'payout_plus_one': (replace(tx.outputs[0], amount=7001), tx.outputs[1]),
                'recipient_substitution': (replace(tx.outputs[0], script=b'\x51\x20'+base.RECIPIENTS[1]), tx.outputs[1]),
                'successor_authority_substitution': (tx.outputs[0], replace(tx.outputs[1], script=next_epoch.leaf.output()[0])),
                'successor_amount_substitution': (tx.outputs[0], replace(tx.outputs[1], amount=90999)),
                'output_reordering': tx.outputs[::-1],
                'extra_output': tx.outputs+(base.Output(0, b'\x6a'),),
            }
            for name, outputs in output_mutations.items():
                changed = replace(tx, outputs=outputs)
                reject(name, changed, machine.witness(stage, changed))
            for name, changed in (('version', replace(tx, version=1)), ('locktime', replace(tx, locktime=1)),
                ('sequence', replace(tx, inputs=(replace(tx.inputs[0], sequence=0xfffffffe),)))):
                reject('fresh_'+name, changed, machine.witness(stage, changed))
            added = base.Input(bytes.fromhex(funding_id)[::-1], 4, 100_000, coinbase_spk)
            changed = replace(tx, inputs=tx.inputs+(added,))
            reject('additional_funded_input', changed, machine.witness(stage, changed),
                   ([coinbase_leaf.script, coinbase_control],))
            for field in ('outpoint', 'spent_key', 'tapleaf'):
                index = machine.FIELDS.index(field)
                for width, value in (('short', proof[index][1:]), ('long', proof[index]+b'\x00')):
                    changed = proof.copy()
                    changed[index] = value
                    reject(width+'_'+field, tx, changed)
            fake = replace(tx, inputs=(replace(tx.inputs[0], index=1),))
            reject('false_context_consistent_proof_late_txcommit', tx, machine.witness(stage, fake))
            changed = proof.copy()
            changed[-1] = changed[-1][:-1]+bytes([changed[-1][-1]^1])
            reject('control_sibling_substitution', tx, changed)
            changed = proof.copy()
            changed[-2] = epoch_proof[-2]
            reject('verifier_body_substitution', tx, changed)
            reject('annex', tx, proof+[b'\x50CPA'], boundary='standardness')
            positive('honest_after_all_root_attacks', tx, proof)

            def submit(current_stage, transaction, witness, role):
                raw, txid = transaction.serialize([witness])
                base.require(rpc('sendrawtransaction', [raw]) == txid, 'submitted identity mismatch')
                record = {'role': role, 'txid': txid, 'raw_tx': raw,
                    'authority_id': current_stage.authority.hex(), 'state_root': current_stage.state_root.hex(),
                    'input_txid': transaction.inputs[0].txid[::-1].hex(), 'input_vout': transaction.inputs[0].index,
                    'outputs': [{'amount_sats': item.amount, 'script_pubkey': item.script.hex()}
                                for item in transaction.outputs]}
                report['transitions'].append(record)
                return txid

            root_ids = [submit(stage, tx, proof, 'parent'), submit(renamed, second, second_proof, 'parent')]
            root_block = rpc('generatetoaddress', [1, address])[0]
            base.require(set(root_ids).issubset(rpc('getblock', [root_block])['tx']), 'parents absent')
            child = stage.actions[0].successor
            base.require(child.amount == 91000 and child.epoch == 1 and tx.outputs[0].amount == 7000,
                         'payout or state differs from profile')

            def restart(expected_height):
                tip = rpc('getbestblockhash')
                base.require(rpc('getconnectioncount') == 0, 'unexpected peer')
                node.stop()
                base.require(node.start()['blocks'] == expected_height and rpc('getbestblockhash') == tip,
                             'restart lost durable tip')
                for transition in report['transitions']:
                    base.require(rpc('gettxout', [transition['input_txid'], transition['input_vout']]) is None,
                                 'restart restored a spent input')
                    for index, expected in enumerate(transition['outputs']):
                        if expected['script_pubkey'].startswith('6a'):
                            continue
                        spent = any(other['input_txid'] == transition['txid'] and other['input_vout'] == index
                                    for other in report['transitions'])
                        observed = rpc('gettxout', [transition['txid'], index])
                        if spent:
                            base.require(observed is None, 'restart restored spent successor')
                        else:
                            base.require(observed is not None and base.satoshis(observed['value']) == expected['amount_sats']
                                         and observed['scriptPubKey']['hex'] == expected['script_pubkey'],
                                         'restart changed live output')
                base.require(rpc('getconnectioncount') == 0, 'unexpected restart peer')
                report['restarts'].append({'height': expected_height, 'tip': tip, 'outputs_checked': True})

            restart(103)
            children = [machine.spend(child, root_id, 1, (1, 1, selector))
                        for selector, root_id in enumerate(root_ids)]
            for selector, (child_tx, child_proof) in enumerate(children):
                base.require(child_tx.outputs[0].amount == 89000 and child_tx.outputs[1].amount == 0 and
                             child_tx.outputs[0].script == b'\x51\x20'+base.RECIPIENTS[selector],
                             'child output differs from independent profile')
                positive('child_recipient_'+str(selector), child_tx, child_proof)
            child_tx, child_proof = children[0]
            changed = child_proof.copy()
            changed[0] = stage.state
            reject('child_stale_parent_state', child_tx, changed)
            changed = child_proof.copy()
            changed[machine.FIELDS.index('grant_id')] = stage.grant
            reject('child_stale_parent_grant', child_tx, changed)
            altered = replace(child_tx, outputs=(replace(child_tx.outputs[0], amount=88999), child_tx.outputs[1]))
            reject('child_fresh_unauthorized_payout', altered, machine.witness(child, altered))
            altered = replace(child_tx, outputs=(child_tx.outputs[0], base.Output(0, b'\x6a\x20'+bytes(32))))
            reject('child_terminal_commitment_substitution', altered, machine.witness(child, altered))
            reject('confirmed_transaction_replay', tx, proof, boundary='duplicate')
            reject('spent_input_new_transaction', denied, denied_proof, boundary='spent')
            child_ids = [submit(child, transaction, witness, 'child') for transaction, witness in children]
            child_block = rpc('generatetoaddress', [1, address])[0]
            base.require(set(child_ids).issubset(rpc('getblock', [child_block])['tx']), 'children absent')
            restart(104)
            report.update(status='passed', final_height=104, peer_count=rpc('getconnectioncount'),
                          confirmed_transitions=4, rejection_count=len(report['rejected']),
                          reserve_script_signatures=0)
        except BaseException as error:
            report.update(status='failed', error=f'{type(error).__name__}: {error}')
            raise
        finally:
            try:
                if node is not None:
                    node.stop()
            except BaseException as error:
                report.update(status='failed', error=f'{type(error).__name__}: {error}')
                raise
            finally:
                if node is not None:
                    node.log.close()
                    report['node_exit_codes'] = node.exit_codes
                    (output/'node.log').write_bytes((root/'node.log').read_bytes())
                (output/'report.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps({key: report[key] for key in ('status', 'confirmed_transitions', 'rejection_count',
                                                 'final_height', 'peer_count', 'node_exit_codes')}, indent=2))
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--timeout', type=int, default=180)
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error('timeout must be positive')

    def expired(signum, frame):
        raise TimeoutError('CPA native campaign exceeded its time budget')

    signal.signal(signal.SIGALRM, expired)
    signal.alarm(args.timeout)
    try:
        run(args.binary, args.output)
    finally:
        signal.alarm(0)


if __name__ == '__main__':
    main()
