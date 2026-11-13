"""Independent Script execution and CPA profile invariants."""
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/research'))
import canonical_proof_authority as cpa
import cpa_transition as machine
import keyless_checksig_rpc as base
from test_keyless_state_machine import execute, transaction_digest, ScriptFailure


class CpaTransitionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = machine.compile_machine()

    def check(self, stage, tx, proof):
        self.assertEqual(execute(stage.leaf.script, proof[:-2],
                                 transaction_digest(tx, stage.leaf.script)), [b'\x01'])

    def reject(self, stage, tx, proof):
        with self.assertRaises(ScriptFailure):
            execute(stage.leaf.script, proof[:-2], transaction_digest(tx, stage.leaf.script))

    def test_all_boolean_inputs_match_independent_policy(self):
        for stage in (self.root, self.root.actions[0].successor):
            for left in (0, 1):
                for right in (0, 1):
                    for select in (0, 1):
                        with self.subTest(epoch=stage.epoch, bits=(left, right, select)):
                            tx, proof = machine.spend(stage, '42'*32, 0, (left, right, select))
                            valid = left == right == 1 and (stage.epoch == 1 or select == 0)
                            (self.check if valid else self.reject)(stage, tx, proof)

    def test_independent_gates_and_renamed_reordered_graph_give_same_address(self):
        nodes = {'yes': ('nand', 'tmp', 'tmp'), 'choice': ('input', 2),
                 'second': ('input', 1), 'tmp': ('nand', 'second', 'first'),
                 'first': ('input', 0)}
        other = machine.compile_machine(nodes, ('yes', 'choice'))
        self.assertEqual(other.program.program_id, self.root.program.program_id)
        self.assertEqual(other.descriptor.encode(), self.root.descriptor.encode())
        self.assertEqual(other.leaf.output(), self.root.leaf.output())
        tx, proof = machine.spend(other, '42'*32, 0)
        self.check(self.root, tx, proof)

    def test_each_gate_mutation_fails(self):
        tx, proof = machine.spend(self.root, '42'*32, 0)
        for offset, (key, _) in enumerate(self.root.program.records, len(machine.FIELDS)):
            changed = proof.copy()
            changed[offset] = b'' if proof[offset] else b'\x01'
            with self.subTest(node=key.hex()):
                self.reject(self.root, tx, changed)

    def test_noncanonical_bits_fail(self):
        tx, proof = machine.spend(self.root, '42'*32, 0)
        for offset in range(len(machine.FIELDS), len(proof)-2):
            for value in (b'\x00', b'\x80', b'\x01\x00', b'\x02', b'\x81'):
                with self.subTest(offset=offset, value=value):
                    changed = proof.copy()
                    changed[offset] = value
                    self.reject(self.root, tx, changed)

    def test_every_context_field_is_enforced(self):
        tx, proof = machine.spend(self.root, '42'*32, 0)
        for index, field in enumerate(machine.FIELDS):
            for changed_value in (bytes(len(proof[index])), proof[index][1:], proof[index]+b'\x00'):
                with self.subTest(field=field, width=len(changed_value)):
                    changed = proof.copy()
                    changed[index] = changed_value
                    self.reject(self.root, tx, changed)

    def test_guard_remains_after_fresh_valid_child_trace(self):
        tx, proof = machine.spend(self.root, '42'*32, 0, (1, 1, 1))
        values = dict(zip((h for h, _ in self.root.program.records),
                          machine.trace(self.root.program, (1, 1, 1))))
        self.assertEqual(values[self.root.program.output_hashes[0]], 1)
        self.assertEqual(tx.outputs[0].amount, 9000)
        self.assertEqual(self.root.cap, 8000)
        self.reject(self.root, tx, proof)
        wider = machine.compile_machine(cap=9000)
        accepted, new_proof = machine.spend(wider, '42'*32, 0, (1, 1, 1))
        self.check(wider, accepted, new_proof)
        self.assertNotEqual(wider.authority, self.root.authority)

    def test_fresh_proof_cannot_authorize_wrong_outputs(self):
        tx, proof = machine.spend(self.root, '42'*32, 0)
        mutations = [replace(tx, outputs=(replace(tx.outputs[0], amount=value), tx.outputs[1]))
                     for value in (6999, 7001)]
        mutations.extend((replace(tx, outputs=tx.outputs[::-1]),
                          replace(tx, outputs=tx.outputs+(base.Output(0, b'\x6a'),)),
                          replace(tx, outputs=(replace(tx.outputs[0], script=b'\x51\x20'+base.RECIPIENTS[1]),
                                               tx.outputs[1])),
                          replace(tx, outputs=(tx.outputs[0], replace(tx.outputs[1], script=self.root.leaf.output()[0])))))
        for changed in mutations:
            self.reject(self.root, changed, machine.witness(self.root, changed))

    def test_strict_transaction_context(self):
        tx, _ = machine.spend(self.root, '42'*32, 0)
        for changed in (replace(tx, version=1), replace(tx, locktime=1),
                        replace(tx, inputs=(replace(tx.inputs[0], sequence=0xfffffffe),)),
                        replace(tx, inputs=tx.inputs+(replace(tx.inputs[0], index=1),))):
            self.reject(self.root, changed, machine.witness(self.root, changed))

    def test_replay_to_second_identical_coin_fails_until_rebound(self):
        first, proof = machine.spend(self.root, '42'*32, 0)
        second, fresh = machine.spend(self.root, '42'*32, 1)
        self.assertEqual(first.inputs[0].script, second.inputs[0].script)
        self.reject(self.root, second, proof)
        self.check(self.root, second, fresh)
        mixed = fresh.copy()
        mixed[machine.FIELDS.index('child_statement')] = proof[machine.FIELDS.index('child_statement')]
        self.reject(self.root, second, mixed)

    def test_successor_spend_and_epoch_replay(self):
        tx, proof = machine.spend(self.root, '42'*32, 0)
        _, txid = tx.serialize([proof])
        child = self.root.actions[0].successor
        self.assertEqual((tx.outputs[0].amount, tx.outputs[1].amount), (7000, 91000))
        self.assertEqual(tx.outputs[1].script, child.leaf.output()[0])
        for select in (0, 1):
            spent, witness = machine.spend(child, txid, 1, (1, 1, select))
            self.assertEqual(spent.outputs[0].amount, 89000)
            self.assertEqual(spent.outputs[0].script, b'\x51\x20'+base.RECIPIENTS[select])
            self.check(child, spent, witness)
            witness[0] = self.root.state
            self.reject(child, spent, witness)

    def test_descriptor_decode_strict(self):
        encoded = self.root.descriptor.encode()
        self.assertEqual(cpa.Descriptor.decode(encoded), self.root.descriptor)
        for changed in (encoded[:-1], encoded+b'\x00', b'\x01\x00'+encoded[2:]):
            with self.assertRaises(ValueError):
                cpa.Descriptor.decode(changed)

    def test_published_commitment_vectors(self):
        vector = json.loads((ROOT/'scripts/tests/data/cpa-v0-commitments.json').read_text())
        self.assertEqual(cpa.demo(), vector)

    def test_program_and_resource_limits(self):
        for kwargs in ({'n_inputs': 0}, {'n_inputs': 9}, {'outputs': ('permit',)},
                       {'nodes': {'x': ('input', 0)}}, {'epoch': 2**32-1},
                       {'cap': 2**31}, {'cap': True}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                machine.compile_machine(**kwargs)

    def test_two_leaf_nums_commitment_independent(self):
        leaf = self.root.leaf
        script, control = leaf.output()
        tag = lambda name, data: hashlib.sha256(hashlib.sha256(name.encode()).digest()*2 + data).digest()
        failing = tag('TapLeaf', b'\xc0\x01\x6a')
        live = tag('TapLeaf', b'\xc0'+base.compact(len(leaf.script))+leaf.script)
        root = tag('TapBranch', b''.join(sorted((live, failing))))
        key, parity = base.tweaked_key(base.NUMS_X, root)
        self.assertEqual(script, b'\x51\x20'+key)
        self.assertEqual(control, bytes([0xc0|parity])+base.NUMS_X+failing)


if __name__ == '__main__':
    unittest.main()
