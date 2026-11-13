import unittest
from dataclasses import replace
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts/research'))
from canonical_proof_authority import *


class Commitments(unittest.TestCase):
    def setUp(self):
        self.nodes = {
            "x": ("input", 0), "y": ("input", 1),
            "n": ("nand", "x", "y"), "o": ("nand", "n", "n"),
        }
        self.p = canonical_program(2, self.nodes, ["o"])
        h = lambda x: tagged_hash("CPA/v0/TestOnly", x)
        self.body = b"\x6a"
        self.d = Descriptor(h(b"network"), SEMANTICS, self.p.program_id,
                            h(b"profile"), h(b"suite"), body_hash(self.body),
                            h(b"abi"), h(b"delegation"), h(b"resources"))
        self.s = state_root(b"state")

    def test_renaming_and_serialization_order(self):
        other = {"out": ("nand", "gate", "gate"),
                 "b": ("input", 1), "gate": ("nand", "a", "b"),
                 "a": ("input", 0)}
        self.assertEqual(self.p, canonical_program(2, other, ["out"]))

    def test_nand_operand_order(self):
        n = dict(self.nodes, n=("nand", "y", "x"))
        self.assertEqual(self.p, canonical_program(2, n, ["o"]))

    def test_duplicate_subexpression_merging(self):
        n = dict(self.nodes, n2=("nand", "x", "y"), o=("nand", "n", "n2"))
        self.assertEqual(self.p, canonical_program(2, n, ["o"]))

    def test_distinct_output(self):
        n = {k: v for k, v in self.nodes.items() if k != "o"}
        self.assertNotEqual(self.p.program_id, canonical_program(2, n, ["n"]).program_id)

    def test_output_order(self):
        a = canonical_program(2, self.nodes, ["o", "x"])
        b = canonical_program(2, self.nodes, ["x", "o"])
        self.assertNotEqual(a.program_id, b.program_id)

    def test_declared_input_count(self):
        self.assertNotEqual(self.p.program_id,
                            canonical_program(3, self.nodes, ["o"]).program_id)

    def test_semantic_equivalence_not_normalized(self):
        p1 = canonical_program(1, {"x": ("input", 0)}, ["x"])
        p2 = canonical_program(1, {"x": ("input", 0), "n": ("nand", "x", "x"),
                                  "o": ("nand", "n", "n")}, ["o"])
        self.assertNotEqual(p1.program_id, p2.program_id)

    def test_cycle(self):
        with self.assertRaises(ValueError):
            canonical_program(1, {"x": ("input", 0), "o": ("nand", "o", "x")}, ["o"])

    def test_missing_node(self):
        with self.assertRaises(ValueError):
            canonical_program(0, {"o": ("nand", "absent", "absent")}, ["o"])

    def test_unreachable_declaration(self):
        with self.assertRaises(ValueError):
            canonical_program(2, dict(self.nodes, dead=("const", 0)), ["o"])

    def test_unknown_gate(self):
        with self.assertRaises(ValueError):
            canonical_program(0, {"o": ("alien",)}, ["o"])

    def test_input_bounds(self):
        with self.assertRaises(ValueError):
            canonical_program(0, {"o": ("input", 0)}, ["o"])

    def test_invalid_constant(self):
        with self.assertRaises(ValueError):
            canonical_program(0, {"o": ("const", 2)}, ["o"])

    def test_empty_outputs(self):
        with self.assertRaises(ValueError):
            canonical_program(0, {}, [])

    def test_descriptor_field_separation(self):
        for f in fields(self.d):
            with self.subTest(field=f.name):
                altered = replace(self.d, **{f.name: b"\xff" * 32})
                self.assertNotEqual(self.d.authority_id(), altered.authority_id())

    def test_descriptor_encoding(self):
        self.assertEqual(len(self.d.encode()), 290)
        self.assertEqual(self.d.encode()[:2], b"\0\0")

    def test_descriptor_bad_hash(self):
        with self.assertRaises(ValueError):
            replace(self.d, program_id=b"short").encode()

    def test_verifier_substitution_rejected(self):
        with self.assertRaises(ValueError):
            authority_script(self.d, self.s, b"\x51")

    def test_state_changes_output(self):
        x = output_commitment(self.d, self.s, self.body)
        y = output_commitment(self.d, state_root(b"state2"), self.body)
        self.assertEqual(x["authority_id"], y["authority_id"])
        self.assertNotEqual(x["script_pubkey"], y["script_pubkey"])

    def test_script_template(self):
        script = authority_script(self.d, self.s, self.body)
        self.assertEqual(script[:33], b"\x20" + self.d.authority_id())
        self.assertEqual(script[33:66], b"\x20" + self.s)
        self.assertTrue(script.endswith(b"\x21" + TXCOMMIT_KEY + b"\xad\x51"))

    def test_p2mr_depth_one_and_control(self):
        x = output_commitment(self.d, self.s, self.body)
        self.assertEqual(x["control_block"][:2], "c1")
        self.assertEqual(len(bytes.fromhex(x["control_block"])), 33)
        self.assertEqual(bytes.fromhex(x["script_pubkey"])[:2], b"\x52\x20")
        self.assertNotEqual(x["merkle_root"], x["tapleaf_hash"])

    def test_branch_is_sorted(self):
        a, b = b"\x11" * 32, b"\x22" * 32
        self.assertEqual(tapbranch(a, b), tapbranch(b, a))

    def test_hash_domain_separation(self):
        self.assertNotEqual(tagged_hash("CPA/v0/State", b"x"),
                            tagged_hash("CPA/v0/Authority", b"x"))

    def test_statement_layout_and_mutations(self):
        a, d = self.d.authority_id(), b"\x33" * 32
        x = proof_public_input(a, self.s, d)
        self.assertEqual(len(x), 96)
        self.assertEqual(x, a + self.s + d)
        for i in range(3):
            args = [a, self.s, d]
            args[i] = b"\xff" * 32
            self.assertNotEqual(x, proof_public_input(*args))

    def test_statement_bad_length(self):
        with self.assertRaises(ValueError):
            proof_public_input(b"", self.s, b"\x33" * 32)

    def test_compact_size_boundaries(self):
        self.assertEqual(compact_size(252), b"\xfc")
        self.assertEqual(compact_size(253), b"\xfd\xfd\x00")
        self.assertEqual(compact_size(65536), b"\xfe\x00\x00\x01\x00")

    def test_negative_sizes(self):
        with self.assertRaises(ValueError):
            compact_size(-1)

    def test_demo_reproducible(self):
        self.assertEqual(demo(), demo())
        self.assertEqual(demo()["descriptor_bytes"], 290)


if __name__ == "__main__":
    unittest.main()
