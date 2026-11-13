from __future__ import annotations
from collections import Counter
from pathlib import Path
import os
import unittest
import sys

REPOSITORY = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY / 'scripts/research'))
import bitvm_authority_enumeration as study

ROOT = Path(os.environ.get('CPA_SOURCE', REPOSITORY))

class StudyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.backend=study.load_backend(ROOT)
        cls.cpa=cls.backend[0]

    def test_sequence_count_matches_product(self):
        from math import comb,prod
        for gates in range(1,5):
            expected=prod(comb(2+i+1,2) for i in range(gates))
            self.assertEqual(sum(1 for _ in study.sequences(gates)),expected)

    def test_reject_dead_gate(self):
        self.assertIsNone(study.graph(((0,0),(1,1))))

    def test_truth_table_nand(self):
        self.assertEqual(study.truth_table(((0,1),)),'1110')

    def test_truth_table_and(self):
        self.assertEqual(study.truth_table(((0,1),(2,2))),'0001')

    def test_truth_table_xor(self):
        self.assertEqual(study.truth_table(((0,1),(0,2),(1,2),(3,4))),'0110')

    def test_wiring_loss_counterexample(self):
        left=((0,1),(0,2));right=((0,0),(1,2))
        a,b=study.graph(left),study.graph(right)
        self.assertEqual(Counter(x[0] for x in a[0].values()),Counter(x[0] for x in b[0].values()))
        self.assertEqual(study.truth_table(left),'1101')
        self.assertEqual(study.truth_table(right),'1011')
        self.assertNotEqual(self.cpa.canonical_program(3,*a).program_id,
                            self.cpa.canonical_program(3,*b).program_id)

    def test_input_role_ids_preserved(self):
        left=self.cpa.canonical_program(2,{'x':('input',0)},('x',))
        right=self.cpa.canonical_program(2,{'x':('input',1)},('x',))
        self.assertNotEqual(left.program_id,right.program_id)

    def test_duplicate_gate_is_merged(self):
        a=self.cpa.canonical_program(2,{'a':('input',0),'b':('input',1),
             'g':('nand','a','b'),'o':('nand','g','g')},('o',))
        b=self.cpa.canonical_program(2,{'a':('input',0),'b':('input',1),
             'g':('nand','a','b'),'g2':('nand','b','a'),'o':('nand','g','g2')},('o',))
        self.assertEqual(a,b)

    def test_field_reduction_alias_and_limb_control(self):
        result=study.field_alias_controls()
        self.assertTrue(result['one_field_reduction_alias'])
        self.assertTrue(result['two_128bit_limbs_distinct'])
        self.assertLess(int(result['x_high']),2**256)

    def test_boolean_relation_refinement_is_intersection(self):
        for parent in range(16):
            for child in range(16):
                accepted=parent & child
                self.assertEqual(accepted & (~parent & 15),0)

    def test_mismatched_join_leaks_retained_guard(self):
        parent,child=1,2
        self.assertNotEqual((parent|child)&(~parent&15),0)

    def test_existing_script_mutation_controls(self):
        controls=study.mutation_tests(self.backend)
        self.assertTrue(all(x['matches_expectation'] for x in controls))
        self.assertEqual(sum(x['observed_accept'] for x in controls),3)

    def test_known_scalar_anchor_identity(self):
        base=self.backend[2]
        p,t1,t2=7,11,19
        p1=base.point_mul((p+t1)%base.N,base.G)
        p2=base.point_mul((p+t2)%base.N,base.G)
        self.assertEqual(base.point_add(p2,base.point_mul((t1-t2)%base.N,base.G)),p1)
        self.assertEqual(((p+t1)-t1)%base.N,p)

    def test_unprefixed_schnorr_related_key_negative_control(self):
        base=self.backend[2]
        secret,nonce,tweak,challenge=7,13,11,19
        pub=base.point_mul(secret,base.G)
        R=base.point_mul(nonce,base.G)
        s=(nonce+challenge*secret)%base.N
        shifted=base.point_add(pub,base.point_mul(tweak,base.G))
        s2=(s+challenge*tweak)%base.N
        self.assertEqual(base.point_mul(s2,base.G),base.point_add(R,base.point_mul(challenge,shifted)))
        changed_challenge=23
        self.assertNotEqual(base.point_mul(s2,base.G),base.point_add(R,base.point_mul(changed_challenge,shifted)))

if __name__=='__main__':
    unittest.main()
