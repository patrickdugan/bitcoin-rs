"""Validate the funded F17 lifecycle receipt against its finite program and ledger."""
from __future__ import annotations

import hashlib
import re

import keyless_checksig_rpc as wire
import keyless_checksig_testnet4 as block_wire
import keyless_state_machine as machine


def require(condition, message):
    if not condition:
        raise ValueError(message)


def same(actual, expected, label):
    require(type(actual) is type(expected), label + ': type differs')
    if isinstance(expected, dict):
        require(actual.keys() == expected.keys(), label + ': fields differ')
        for key in expected:
            same(actual[key], expected[key], label + '.' + key)
    elif isinstance(expected, list):
        require(len(actual) == len(expected), label + ': length differs')
        for index, value in enumerate(expected):
            same(actual[index], value, f'{label}[{index}]')
    else:
        require(actual == expected, label + ': value differs')


def identity(value, label):
    require(isinstance(value, str) and re.fullmatch(r'[0-9a-f]{64}', value) is not None,
            label + ': missing hash identity')


def output_rows(outputs, roles=None):
    rows = [{'amount_sats': item.amount, 'script_pubkey': item.script.hex()} for item in outputs]
    if roles is not None:
        for row, role in zip(rows, roles):
            row['role'] = role
    return rows


def input_row(item):
    return {'txid': item.txid[::-1].hex(), 'vout': item.index, 'amount_sats': item.amount,
            'script_pubkey': item.script.hex(), 'sequence': item.sequence}


def encoded(tx, witness):
    raw, txid = tx.serialize([witness])
    return {'raw_tx': raw, 'txid': txid,
            'wtxid': wire.sha(wire.sha(bytes.fromhex(raw)))[::-1].hex(),
            'witness_hex': [item.hex() for item in witness]}


def virtual_size(tx, raw):
    return (3 * (len(tx.body()) + 8) + len(bytes.fromhex(raw)) + 3) // 4


def accepted(dry, item, size):
    same({key: dry[key] for key in ('allowed', 'txid', 'wtxid', 'vsize')},
         {'allowed': True, 'txid': item['txid'], 'wtxid': item['wtxid'], 'vsize': size},
         'accepted preview')
    fees = dry['fees']
    same(set(fees), {'base', 'effective-feerate', 'effective-includes'}, 'preview fee fields')
    require(wire.satoshis(fees['base']) == 2_000
            and wire.satoshis(fees['effective-feerate']) == 2_000_000 // size,
            'accepted preview fees differ')
    same(fees['effective-includes'], [item['wtxid']], 'preview fee transaction')


def compact(raw, start):
    value, end = block_wire.compact(raw, start)
    require(end <= len(raw) and raw[start:end] == wire.compact(value),
            'noncanonical or truncated CompactSize')
    return value, end


def validate_coinbase(parsed, height, payout_script):
    raw = bytes.fromhex(parsed['raw'])
    count, offset = compact(raw, 6 if parsed['segwit'] else 4)
    require(count == 1 and raw[offset:offset + 36] == bytes(32) + b'\xff' * 4,
            'block must start with one coinbase input')
    size, offset = compact(raw, offset + 36)
    script = raw[offset:offset + size]
    require(2 <= size <= 100 and script.startswith(wire.push(wire.script_number(height))),
            'coinbase height commitment differs')
    count, offset = compact(raw, offset + size + 4)
    require(count == 2, 'coinbase must contain its payout and witness commitment')
    outputs = []
    for _ in range(count):
        amount = int.from_bytes(raw[offset:offset + 8], 'little')
        size, offset = compact(raw, offset + 8)
        outputs.append((amount, raw[offset:offset + size].hex()))
        offset += size
    require(0 <= outputs[0][0] <= 5_000_002_000 and outputs[0][1] == payout_script,
            'coinbase payout or subsidy bound differs')
    require(outputs[1][0] == 0 and outputs[1][1].startswith('6a24aa21a9ed'),
            'coinbase witness output differs')
    count, offset = compact(raw, offset)
    size, offset = compact(raw, offset)
    require(parsed['segwit'] and count == 1 and size == 32 and offset + size + 4 == len(raw),
            'coinbase witness encoding differs')
    return {'txid': parsed['txid'], 'vout': 0, 'amount_sats': outputs[0][0],
            'script_pubkey': payout_script}


def validate(report, binary_sha256):
    require(__debug__, 'block verification requires Python assertions')
    identity(binary_sha256, 'binary')
    metadata = {'schema_version': 1, 'fixture': 'keyless-state-lifecycle', 'status': 'passed',
                'binary_sha256': binary_sha256, 'network': 'regtest', 'peer_count': 0,
                'script_signatures': 0, 'final_height': 104, 'final_state': 1,
                'active_family': 'b', 'confirmed_transitions': 4, 'rewind_depth': 2,
                'rejection_count': 5, 'restart_preserved_state': True,
                'node_exit_codes': [0, 0, 0, 0], 'clean_shutdowns': True}
    same({key: report[key] for key in metadata}, metadata, 'lifecycle result')
    program_id = hashlib.sha256(b'BIPSpace/Keyless-CHECKSIG/F17/full-trace/v1').digest()
    same(report['program_id'], program_id.hex(), 'program identity')
    program = machine.compile_machine()
    stages = {3: program, 9: program.branch(9).successor, 12: program.branch(12).successor}
    for state, depth, amount in ((3, 1, 100_000), (9, 0, 89_000), (12, 0, 86_000)):
        stage = stages[state]
        require((stage.program_id, stage.old_state, stage.depth, stage.amount)
                == (program_id, state, depth, amount), 'compiled state differs from the program')
    keys = {state: stage.leaf.output() for state, stage in stages.items()}
    bare_leaf = wire.Leaf(b'\x51')
    bare_spk, bare_control = bare_leaf.output()
    funding = report['funding']
    identity(funding['input']['txid'], 'funding source')
    source = wire.Input(bytes.fromhex(funding['input']['txid'])[::-1], 0, 5_000_000_000, bare_spk)
    funding_tx = wire.Tx((source,), (wire.Output(100_000, keys[3][0]),
                                    wire.Output(4_999_898_000, bare_spk)))
    items = {'funding': encoded(funding_tx, [bare_leaf.script, bare_control])}
    txs = {'funding': funding_tx}
    blocks = report['blocks']
    block_names = {'funding', 'a_parent', 'a_child', 'b_parent', 'b_child'}
    same(set(blocks), block_names, 'block manifest')
    for name in block_names:
        identity(blocks[name]['hash'], name + ' block')
    require(len({item['hash'] for item in blocks.values()}) == 5, 'block identities must differ')
    funding_expected = {**items['funding'], 'input': input_row(source),
                        'outputs': output_rows(funding_tx.outputs, ('root', 'change')),
                        'fee_sats': 2_000, 'height': 102, 'block': blocks['funding']['hash'],
                        'admission': funding['admission']}
    same(funding, funding_expected, 'funding')
    accepted(funding['admission'], items['funding'], virtual_size(funding_tx, funding['raw_tx']))
    specs = (
        ('a_parent', 3, 2, 'funding', 0, 9, 9_000, 0, [2, 2], 0),
        ('a_child', 9, 2, 'a_parent', 1, 15, 87_000, 0, [2, 2], 1),
        ('b_parent', 3, 3, 'funding', 0, 12, 12_000, 1, [3, 2], 0),
        ('b_child', 12, 2, 'b_parent', 1, 1, 84_000, 1, [3, 2], 1),
    )
    witnesses = {}
    records = report['transactions']
    same(set(records), block_names - {'funding'}, 'transition manifest')
    for name, old, delta, parent, vout, result, payout, recipient, path, index in specs:
        stage = stages[old]
        rows = [(old + step * delta) % 17 for step in range(4)]
        require(rows[-1] == result, 'specified arithmetic result differs')
        spent = wire.Input(bytes.fromhex(items[parent]['txid'])[::-1], vout, stage.amount, keys[old][0])
        if index == 0:
            successor = wire.Output({9: 89_000, 12: 86_000}[result], keys[result][0])
        else:
            tag = hashlib.sha256(b'BIPSpace/Keyless-CHECKSIG/F17/state/v1').digest()
            commitment = hashlib.sha256(tag + tag + program_id + bytes(4) + bytes([result])).digest()
            successor = wire.Output(0, b'\x6a\x20' + commitment)
        tx = wire.Tx((spent,), (wire.Output(payout, b'\x51\x20' + wire.RECIPIENTS[recipient]), successor))
        witness = [program_id, spent.outpoint(), spent.script[2:], wire.tapleaf(stage.leaf.script),
                   bytes([delta]), *(bytes([row]) if row else b'' for row in rows),
                   stage.leaf.script, keys[old][1]]
        items[name], txs[name], witnesses[name] = encoded(tx, witness), tx, witness
        same(records[name], {**items[name], 'path': path, 'stage': index, 'program_id': program_id.hex(),
             'old_state': old, 'new_state': result, 'trace': rows, 'delta': delta,
             'input': input_row(spent), 'outputs': output_rows(tx.outputs,
                 ('payout', 'successor' if index == 0 else 'state_commitment')),
             'fee_sats': 2_000, 'script_hex': stage.leaf.script.hex(), 'control_hex': keys[old][1].hex(),
             'block': blocks[name]['hash'], 'confirmed_height': 103 + index,
             'observed_input_sats': stage.amount, 'observed_outputs': output_rows(tx.outputs),
             'observed_fee_sats': 2_000}, name)
    sizes = {name: virtual_size(txs[name], item['raw_tx']) for name, item in items.items()}
    identity(blocks['funding']['previous'], 'maturity tip')
    require(blocks['funding']['previous'] not in {item['hash'] for item in blocks.values()},
            'funding ancestry cycles through the campaign')
    for name, parent, height, payout_script in (
        ('funding', None, 102, bare_spk),
        ('a_parent', 'funding', 103, b'\x51\x20' + wire.RECIPIENTS[0]),
        ('a_child', 'a_parent', 104, b'\x51\x20' + wire.RECIPIENTS[0]),
        ('b_parent', 'funding', 103, b'\x51\x20' + wire.RECIPIENTS[1]),
        ('b_child', 'b_parent', 104, b'\x51\x20' + wire.RECIPIENTS[1]),
    ):
        record = blocks[name]
        raw = bytes.fromhex(record['raw_block'])
        require(raw.hex() == record['raw_block'] and raw[72:76] == b'\xff\xff\x7f\x20',
                name + ': block encoding or regtest difficulty differs')
        count, _ = compact(raw, 80)
        require(count == 2, name + ': block transaction count differs')
        parsed = block_wire.validate_block(raw, record['hash'])
        require(parsed['tx_count'] == 2 and parsed['witness_commitment_verified'] is True,
                name + ': block transaction or witness commitment differs')
        same(parsed['transactions'][1]['raw'], items[name]['raw_tx'], name + ' block transaction')
        previous = blocks[parent]['hash'] if parent else record['previous']
        same(parsed['previous'], previous, name + ' parent')
        coinbase = validate_coinbase(parsed['transactions'][0], height, payout_script.hex())
        same(record, {'hash': parsed['hash'], 'raw_block': raw.hex(), 'previous': previous,
             'height': height, 'txids': [coinbase['txid'], items[name]['txid']], 'coinbase': coinbase},
             name + ' block')
    same(report['candidate_b'], blocks['b_parent'], 'saved B block')
    same(report['final_tip'], blocks['b_child']['hash'], 'final tip')
    coins = {'root': funding_tx.outputs[0], 'change': funding_tx.outputs[1]}
    for family in ('a', 'b'):
        for label, source, vout in (('payout', 'parent', 0), ('successor', 'parent', 1),
                                    ('terminal', 'child', 0), ('commitment', 'child', 1)):
            coins[family + '_' + label] = txs[family + '_' + source].outputs[vout]
    funded = {'root': 102, 'change': 102}
    parent_a = {'change': 102, 'a_payout': 103, 'a_successor': 103}
    final_a = {'change': 102, 'a_payout': 103, 'a_terminal': 104}
    parent_b = {'change': 102, 'b_payout': 103, 'b_successor': 103}
    final_b = {'change': 102, 'b_payout': 103, 'b_terminal': 104}
    pending_a = {'change': 102, 'a_payout': None, 'a_successor': None}
    pending_family_a = {'change': 102, 'a_payout': None, 'a_terminal': None, 'a_commitment': None}
    pending_child_a = {'change': 102, 'a_payout': 103, 'a_terminal': None, 'a_commitment': None}
    pending_child_b = {'change': 102, 'b_payout': 103, 'b_terminal': None, 'b_commitment': None}
    phases = (
        ('funded', 'funding', (), funded, funded),
        ('candidate_b_prepared', 'funding', (), funded, funded),
        ('a_parent_pending', 'funding', ('a_parent',), funded, pending_a),
        ('a_family_pending', 'funding', ('a_parent', 'a_child'), funded, pending_family_a),
        ('a_parent_confirmed', 'a_parent', ('a_child',), parent_a, pending_child_a),
        ('a_family_confirmed', 'a_child', (), final_a, final_a),
        ('a_confirmed_restarted', 'a_child', (), final_a, final_a),
        ('rewound', 'funding', ('a_parent', 'a_child'), funded, pending_family_a),
        ('rewound_restarted', 'funding', ('a_parent', 'a_child'), funded, pending_family_a),
        ('b_parent_confirmed', 'b_parent', (), parent_b, parent_b),
        ('b_child_pending', 'b_parent', ('b_child',), parent_b, pending_child_b),
        ('b_family_confirmed', 'b_child', (), final_b, final_b),
        ('b_confirmed_restarted', 'b_child', (), final_b, final_b),
    )
    snapshots = report['snapshots']
    same(set(snapshots), {row[0] for row in phases}, 'snapshot manifest')
    for name, block, pending, chain, overlay in phases:
        tip, height = blocks[block]['hash'], blocks[block]['height']
        sequence = snapshots[name]['mempool']['mempool_sequence']
        require(type(sequence) is int and sequence >= 0, name + ': invalid mempool sequence')
        expected = {'height': height, 'bestblock': tip, 'height_hash': tip, 'peer_count': 0,
                    'is_apply_halted': False, 'is_closed_for_recovery': False,
                    'mempool': {'txids': sorted(items[key]['txid'] for key in pending),
                                'mempool_sequence': sequence}, 'entries': {}, 'coins': {}}
        for label, output in coins.items():
            expected['coins'][label] = {}
            for view, ledger in (('chain', chain), ('overlay', overlay)):
                expected['coins'][label][view] = (None if label not in ledger else
                    {'amount_sats': output.amount, 'script_pubkey': output.script.hex(),
                     'confirmations': 0 if ledger[label] is None else height - ledger[label] + 1,
                     'coinbase': False, 'bestblock': tip})
        for key in pending:
            family, kind = key.split('_')
            parent, child = family + '_parent', family + '_child'
            ancestors = [key] + ([parent] if kind == 'child' and parent in pending else [])
            descendants = [key] + ([child] if kind == 'parent' and child in pending else [])
            expected['entries'][items[key]['txid']] = {
                'depends': [items[item]['txid'] for item in ancestors[1:]],
                'spentby': [items[item]['txid'] for item in descendants[1:]],
                'ancestorcount': len(ancestors), 'descendantcount': len(descendants),
                'ancestorsize': sum(sizes[item] for item in ancestors),
                'descendantsize': sum(sizes[item] for item in descendants),
                'vsize': sizes[key], 'wtxid': items[key]['wtxid'],
                'fees_sats': {'base': 2_000, 'modified': 2_000, 'chunk': 2_000,
                             'ancestor': 2_000 * len(ancestors), 'descendant': 2_000 * len(descendants)}}
        same(snapshots[name], expected, name)
    for before, after, increase in (
        ('funded', 'candidate_b_prepared', 0),
        ('candidate_b_prepared', 'a_parent_pending', 1),
        ('a_parent_pending', 'a_family_pending', 1),
        ('a_family_pending', 'a_parent_confirmed', 1),
        ('a_parent_confirmed', 'a_family_confirmed', 1),
        ('a_confirmed_restarted', 'rewound', 2),
        ('rewound_restarted', 'b_parent_confirmed', 2),
        ('b_parent_confirmed', 'b_child_pending', 1),
        ('b_child_pending', 'b_family_confirmed', 1),
    ):
        require(snapshots[after]['mempool']['mempool_sequence']
                == snapshots[before]['mempool']['mempool_sequence'] + increase,
                after + ': unexpected mempool mutation count')
    same(set(report['admissions']), set(records), 'admission manifest')
    for name, phase in (('b_parent', 'funded'), ('a_parent', 'candidate_b_prepared'),
                        ('a_child', 'a_parent_pending'), ('b_child', 'b_parent_confirmed')):
        record = report['admissions'][name]
        accepted(record['dry_run'], items[name], sizes[name])
        expected = {'transaction': name, 'dry_run': record['dry_run'],
                    'before': snapshots[phase], 'after_preview': snapshots[phase]}
        if name != 'b_parent':
            expected['submitted_txid'] = items[name]['txid']
        same(record, expected, name + ' admission')
    failures = (
        ('child_without_parent', 'a_child', 'missing_inputs', 'funded', 'missing-inputs'),
        ('equal_fee_parent', 'b_parent', 'replacement_fee', 'a_parent_pending', 'insufficient fee'),
        ('conflict_with_child', 'b_parent', 'replacement_fee', 'a_family_pending', 'insufficient fee'),
        ('replayed_old_state', 'b_child', 'script', 'b_parent_confirmed', 'script-verify-flag-failed'),
        ('stale_a_child', 'a_child', 'missing_inputs', 'b_family_confirmed', 'missing-inputs'),
    )
    same(set(report['rejected']), {row[0] for row in failures}, 'rejection manifest')
    for name, transaction, boundary, phase, reason in failures:
        witness = list(witnesses[transaction])
        rows, delta = records[transaction]['trace'], records[transaction]['delta']
        if name == 'replayed_old_state':
            rows, delta = [9, 12, 15, 1], 3
            witness[4:9] = [bytes([delta])] + [bytes([row]) for row in rows]
        item = encoded(txs[transaction], witness)
        expected = {**item, 'transaction': transaction, 'boundary': boundary, 'trace': rows,
                    'delta': delta, 'before': snapshots[phase], 'after': snapshots[phase],
                    'dry_run': {'allowed': False, 'reject-reason': reason,
                                'txid': item['txid'], 'wtxid': item['wtxid']}}
        if name != 'child_without_parent':
            code, message = {'replacement_fee': (-26, 'insufficient fee'),
                             'script': (-26, 'consensus-verification-failed'),
                             'missing_inputs': (-25, 'bad-txns-inputs-missingorspent')}[boundary]
            expected['admission'] = {'code': code, 'message': message}
        if name in ('replayed_old_state', 'stale_a_child'):
            message = ('block-script-verify-flag-failed (script failed: NUMEQUALVERIFY)'
                       if name == 'replayed_old_state' else 'bad-txns-inputs-missingorspent')
            expected['block_error'] = {'code': -25, 'message': 'TestBlockValidity failed: ' + message}
        same(report['rejected'][name], expected, name)
    same(report['operations'], {
        'stale_b_submit': {'raw_block': blocks['b_parent']['raw_block'],
                          'before': snapshots['a_confirmed_restarted'],
                          'result': 'inconclusive-not-best-prevblk',
                          'after': snapshots['a_confirmed_restarted']},
        'invalidate': {'block': blocks['a_parent']['hash'], 'before': snapshots['a_confirmed_restarted'],
                       'result': None, 'after': snapshots['rewound']},
        'submit_b': {'raw_block': blocks['b_parent']['raw_block'],
                     'before': snapshots['rewound_restarted'], 'result': None,
                     'after': snapshots['b_parent_confirmed']},
    }, 'lifecycle operations')
    restarts = []
    for before, after in (('a_family_confirmed', 'a_confirmed_restarted'),
                          ('rewound', 'rewound_restarted'),
                          ('b_family_confirmed', 'b_confirmed_restarted')):
        left, right = dict(snapshots[before]), dict(snapshots[after])
        left['mempool'] = {'txids': left['mempool']['txids']}
        right['mempool'] = {'txids': right['mempool']['txids']}
        same(left, right, after + ' restored state')
        restarts.append({'before': before, 'after': after, 'height': left['height'],
                         'bestblock': left['bestblock'], 'preserved': True})
    same(report['restart_checks'], restarts, 'restart evidence')
    coinbase_checks = {}
    for phase in ('rewound', 'rewound_restarted', 'b_family_confirmed', 'b_confirmed_restarted'):
        checks = {}
        names = ('a_parent', 'a_child', 'b_parent') + (() if phase.startswith('rewound') else ('b_child',))
        for name in names:
            coin = None
            if phase.startswith('b_') and name.startswith('b_'):
                source = blocks[name]['coinbase']
                coin = {'amount_sats': source['amount_sats'], 'script_pubkey': source['script_pubkey'],
                        'confirmations': 104 - blocks[name]['height'] + 1, 'coinbase': True,
                        'bestblock': blocks['b_child']['hash']}
            checks[name] = {'chain': coin, 'overlay': coin}
        coinbase_checks[phase] = checks
    same(report['coinbase_checks'], coinbase_checks, 'fork coinbases')
    return {'confirmed_transitions': 4, 'rewind_depth': 2, 'rejection_count': 5, 'final_state': 1,
            'restart_preserved_state': True, 'clean_shutdowns': True, 'network': 'regtest', 'peer_count': 0}
