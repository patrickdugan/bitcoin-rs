#!/usr/bin/env python3
"""Offline gate-to-authority research. Synthetic targets only; no network access.

Use --bitcoin-rs PATH with the pinned CPA research branch. Experiments enumerate
circuits, check the existing independent Script oracle, and exercise explicitly
insecure alternative derivations. No production key recovery is attempted.
"""
from __future__ import annotations
import argparse
from collections import Counter, defaultdict
from dataclasses import replace
import hashlib
from functools import lru_cache
import itertools
import json
import math
from pathlib import Path
import sys


def load_backend(root: Path):
    sys.path.insert(0, str(root / 'scripts/research'))
    sys.path.insert(0, str(root / 'scripts/tests'))
    import canonical_proof_authority as cpa
    import cpa_transition as machine
    import keyless_checksig_rpc as base
    from test_keyless_state_machine import execute, transaction_digest, ScriptFailure
    base.tweaked_key = lru_cache(maxsize=4096)(base.tweaked_key)
    return cpa, machine, base, execute, transaction_digest, ScriptFailure


def sequences(gates: int, prefix=()):
    if len(prefix) == gates:
        yield prefix
        return
    for pair in itertools.combinations_with_replacement(range(2 + len(prefix)), 2):
        yield from sequences(gates, prefix + (pair,))


def graph(seq):
    used = set()
    def visit(i):
        if i in used:
            return
        used.add(i)
        if i >= 2:
            for child in seq[i-2]:
                visit(child)
    visit(len(seq)+1)
    if any(i not in used for i in range(2, len(seq)+2)):
        return None
    nodes = {'s': ('input', 2)}
    for i in sorted(used):
        nodes[str(i)] = ('input', i) if i < 2 else ('nand', *map(str, seq[i-2]))
    return nodes, (str(len(seq)+1), 's')


def truth_table(seq):
    result = []
    for a, b in itertools.product((0, 1), repeat=2):
        vals = [a, b]
        for i, j in seq:
            vals.append(1 - vals[i] * vals[j])
        result.append(vals[-1])
    return ''.join(map(str, result))


def enumerate_corpus(cpa, max_gates=5):
    if not 1 <= max_gates <= 5:
        raise ValueError('bounded study requires 1 <= max_gates <= 5')
    unique = {}
    by_depth = []
    for g in range(1, max_gates+1):
        raw = live = 0
        at_g = set()
        for seq in sequences(g):
            raw += 1
            spec = graph(seq)
            if spec is None:
                continue
            live += 1
            nodes, outputs = spec
            p = cpa.canonical_program(3, nodes, outputs)
            pid = p.program_id.hex()
            truth = truth_table(seq)
            if pid in unique and unique[pid]['truth'] != truth:
                raise AssertionError('same canonical identity has different truth table')
            at_g.add(pid)
            unique.setdefault(pid, {'sequence': seq, 'nodes': nodes, 'outputs': outputs,
                                    'truth': truth, 'program_id': pid, 'first_gate_bound': g})
        by_depth.append({'nand_gate_count': g, 'raw_sequences': raw,
                         'all_gates_reachable_sequences': live,
                         'identities_at_gate_count': len(at_g),
                         'cumulative_identities': len(unique),
                         'cumulative_functions': len({x['truth'] for x in unique.values()})})
    hist = Counter(x['truth'] for x in unique.values())
    return unique, {'parameters': {'permission_inputs': 2, 'selector_inputs': 1,
                       'permission_output': 'last gate', 'selector_output': 'input 2',
                       'gates': 'NAND only, unordered operands, all gates reachable',
                       'max_nand_gates': max_gates},
                   'layers': by_depth, 'unique_programs': len(unique),
                   'semantic_functions': len(hist), 'function_multiplicities': dict(sorted(hist.items()))}


def accepts(execute, digest, failure, stage, tx, witness):
    try:
        return execute(stage.leaf.script, witness[:-2], digest(tx, stage.leaf.script)) == [b'\x01']
    except failure:
        return False


def compiler_check(backend, corpus, sample_limit=32):
    cpa, machine, base, execute, digest, failure = backend
    representatives = {}
    for row in corpus.values():
        representatives.setdefault(row['truth'], row)
    selected = list(representatives.values())
    known = {row['program_id'] for row in selected}
    for row in sorted(corpus.values(), key=lambda x: x['program_id']):
        if len(selected) >= sample_limit:
            break
        if row['program_id'] not in known:
            known.add(row['program_id'])
            selected.append(row)
    cases = mismatches = accepted = 0
    rows = []
    for row in selected:
        stage = machine.compile_machine(row['nodes'], row['outputs'])
        local_accepted = 0
        for a, b, select in itertools.product((0, 1), repeat=3):
            tx, proof = machine.spend(stage, '42'*32, 0, (a,b,select))
            expected = row['truth'][2*a+b] == '1' and select == 0
            actual = accepts(execute, digest, failure, stage, tx, proof)
            cases += 1
            accepted += actual
            local_accepted += actual
            mismatches += actual != expected
        rows.append({'program_id': stage.program.program_id.hex(), 'authority_id': stage.authority.hex(),
                     'output_key': stage.leaf.output()[0][2:].hex(), 'script_bytes': len(stage.leaf.script),
                     'truth': row['truth'], 'accepted_inputs': local_accepted,
                     'taproot_root': cpa.tapbranch(base.tapleaf(stage.leaf.script), base.tapleaf(b'\x6a')).hex()})
    return {'programs_tested': len(selected), 'exhaustive_truth_tables_represented': len(representatives),
            'input_cases': cases, 'accepted': accepted, 'mismatches': mismatches,
            'level': 'existing independent Python Script oracle; no native HF verifier'}, rows


def planted_collisions(cpa, corpus):
    topology_buckets = defaultdict(list)
    for row in corpus.values():
        counts = Counter(node[0] for node in row['nodes'].values())
        identity = tuple(sorted(counts.items()))
        topology_buckets[identity].append(row)
    unsafe = [v for v in topology_buckets.values() if len({r['truth'] for r in v}) > 1]
    a = ((0,1),(0,2))
    b = ((0,0),(1,2))
    sa, sb = graph(a), graph(b)
    pa = cpa.canonical_program(3, *sa)
    pb = cpa.canonical_program(3, *sb)
    counts_a = Counter(n[0] for n in sa[0].values())
    counts_b = Counter(n[0] for n in sb[0].values())
    if counts_a != counts_b or truth_table(a) == truth_table(b) or pa.program_id == pb.program_id:
        raise AssertionError('failed topology-collision control')
    return {'planted_mutant': 'identifier commits only to gate/input type histogram; wiring omitted',
            'buckets': len(topology_buckets), 'semantically_ambiguous_buckets': len(unsafe),
            'programs_in_ambiguous_buckets': sum(len(v) for v in unsafe),
            'concrete_pair': {'C1': 'NAND(a, NAND(a,b))', 'C2': 'NAND(b, NAND(a,a))',
                             'truth_C1': truth_table(a), 'truth_C2': truth_table(b),
                             'type_histogram': dict(counts_a), 'CPA_ids_distinct': True,
                             'permission_leak_inputs_C1_to_C2': [i for i in range(4)
                               if truth_table(a)[i] == '0' and truth_table(b)[i] == '1']}}


def relation_and_key_experiments(backend, rows):
    cpa, _, base, _, _, _ = backend
    nums = base.lift_x(base.NUMS_X)
    synthetic_secret = int.from_bytes(cpa.tagged_hash('CPA/Arena/KNOWN-TEST-SECRET', b'anchor'), 'big') % base.N
    synthetic_point = base.point_mul(synthetic_secret, base.G)
    anchored = []
    for row in rows:
        root = bytes.fromhex(row['taproot_root'])
        t = int.from_bytes(base.tagged('TapTweak', base.NUMS_X + root), 'big')
        assert t < base.N
        q = base.point_add(nums, base.point_mul(t, base.G))
        assert q[0].to_bytes(32, 'big').hex() == row['output_key']
        q_test = base.point_add(synthetic_point, base.point_mul(t, base.G))
        actual_secret = (synthetic_secret+t) % base.N
        if q is None or q_test is None or actual_secret == 0:
            raise ValueError('exceptional point; deterministic fixture needs replacement')
        normalized_secret = actual_secret if q_test[1] % 2 == 0 else (-actual_secret) % base.N
        epsilon = 1 if q_test[1] % 2 == 0 else -1
        recovered_anchor = (epsilon*normalized_secret-t) % base.N
        assert recovered_anchor == synthetic_secret
        anchored.append((t,q))
    recovered = sum(base.point_add(q, base.point_mul((-t)%base.N, base.G)) == nums for t,q in anchored)
    scalar_exposure = 0
    for row in rows:
        k = int.from_bytes(cpa.tagged_hash('CPA/Arena/PublicScalar', bytes.fromhex(row['program_id'])), 'big') % base.N
        pub = base.point_mul(k, base.G)
        scalar_exposure += pub is not None
    a,b = anchored[:2]
    relation = base.point_add(b[1], base.point_mul((a[0]-b[0])%base.N, base.G)) == a[1]
    return {'known_tweaks_removed_to_actual_NUMS_point': recovered,
            'tested_authorities': len(rows), 'known_tweak_pair_relation_verified': relation,
            'planted_public_scalar_construction_recomputable_secrets': scalar_exposure,
            'synthetic_anchor_leak_recoveries': len(rows),
            'actual_NUMS_private_log_recovered': False,
            'scope': 'public group identities and planted known-secret controls; no real private key recovered'}


def mutation_tests(backend):
    cpa,machine,base,execute,digest,failure = backend
    stage = machine.compile_machine()
    tx, proof = machine.spend(stage,'43'*32,0)
    result=[]
    def record(label, t, p, expected, reason):
        actual=accepts(execute,digest,failure,stage,t,p)
        result.append({'family':label,'expected_accept':expected,'observed_accept':actual,
                       'matches_expectation':expected==actual,'reason':reason})
    record('honest',tx,proof,True,'exact committed action')
    t,p=machine.spend(stage,'43'*32,0,(1,1,1))
    record('valid_child_over_parent_cap',t,p,False,'parent retained guard')
    for field in ('parent_id','current_state','grant_id','child_statement'):
        changed=proof.copy();i=machine.FIELDS.index(field);changed[i]=bytes(32)
        record('replace_'+field,tx,changed,False,'authority/context binding')
    for amount in (6999,7001):
        t=replace(tx,outputs=(replace(tx.outputs[0],amount=amount),tx.outputs[1]))
        record('fresh_wrong_payout_'+str(amount),t,machine.witness(stage,t),False,'actual output binding')
    second,fresh=machine.spend(stage,'43'*32,1)
    record('copy_between_same_address_coins',second,proof,False,'outpoint differs')
    record('rebind_same_address_coin',second,fresh,True,'public relation permits a fresh valid witness')
    twin=machine.compile_machine(cap=9000)
    t,p=machine.spend(twin,'43'*32,0,(1,1,1))
    actual=accepts(execute,digest,failure,twin,t,p)
    result.append({'family':'wider_authority_positive_control','expected_accept':True,
                   'observed_accept':actual,'matches_expectation':actual,
                   'different_address':twin.leaf.output()[0]!=stage.leaf.output()[0],
                   'reason':'legitimate different policy; cannot impersonate the fixed funded authority'})
    return result


def field_alias_controls():
    r=2**255-19
    low=17
    high=low+r
    broken=lambda x: x%r
    fixed=lambda x:(x&((1<<128)-1),x>>128)
    return {'field_modulus':str(r),'x_low':str(low),'x_high':str(high),
            'one_field_reduction_alias':broken(low)==broken(high),
            'two_128bit_limbs_distinct':fixed(low)!=fixed(high),
            'scope':'planted public-input encoder; does not solve any SHA256 digest target'}


def run(root: Path, out: Path, max_gates=5, sample_limit=32):
    backend=load_backend(root)
    corpus, enumeration=enumerate_corpus(backend[0],max_gates)
    checks,rows=compiler_check(backend,corpus,sample_limit)
    result={'schema':'cpa-gate-enumeration-study/v1','scope':'offline synthetic and existing CPA Python oracle',
            'source_head':'29ca519031fcd67f467881e16ba73e0eb1211759',
            'arena_native_source_available':False,'HF_consensus_verifier_implemented':False,
            'enumeration':enumeration,'compiler':checks,
            'planted_topology_collision':planted_collisions(backend[0],corpus),
            'key_relations':relation_and_key_experiments(backend,rows),
            'statement_packing':field_alias_controls(),
            'mutations':mutation_tests(backend),
            'prefix_grinding_expected_trials':{str(b):str(2**b) for b in (16,32,64,128,256)},
            'raw_bound_k8_g24_log2':sum(math.log2(math.comb(8+i+1,2)) for i in range(24)),
            'source_sha256':{name:hashlib.sha256((root/path).read_bytes()).hexdigest()
               for name,path in [('canonical_proof_authority','scripts/research/canonical_proof_authority.py'),
                                 ('cpa_transition','scripts/research/cpa_transition.py'),
                                 ('independent_oracle','scripts/tests/test_keyless_state_machine.py')]}}
    if checks['mismatches'] or not all(x['matches_expectation'] for x in result['mutations']):
        raise AssertionError('acceptance mismatch: see result')
    out.mkdir(parents=True,exist_ok=True)
    (out/'results.json').write_text(json.dumps(result,indent=2)+'\n')
    (out/'compiled_authorities.json').write_text(json.dumps(rows,indent=2)+'\n')
    with (out/'circuits.jsonl').open('w') as stream:
        for row in sorted(corpus.values(),key=lambda x:x['program_id']):
            stream.write(json.dumps(row,sort_keys=True)+'\n')
    print(json.dumps({k:result[k] for k in ('enumeration','compiler','planted_topology_collision','key_relations')},indent=2))
    return result


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bitcoin-rs',type=Path,required=True)
    parser.add_argument('--out',type=Path,default=Path('evidence'))
    parser.add_argument('--max-gates',type=int,default=5)
    parser.add_argument('--sample-limit',type=int,default=32)
    args=parser.parse_args()
    if not 16<=args.sample_limit<=64:
        parser.error('--sample-limit must be 16..64')
    run(args.bitcoin_rs,args.out,args.max_gates,args.sample_limit)
