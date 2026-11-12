"""Offline checks of the public-key and canonical-claim fixture boundaries."""
from dataclasses import replace
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'research'))
from muladdmod_dispute_rpc import Claim, Leaf, N, NUMS_X, Spend, public_key, sha, sign


class ClaimFixtureTests(unittest.TestCase):
    def test_bip340_official_signing_vector_zero(self):
        self.assertEqual(public_key(3).hex().upper(),
            'F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9')
        expected = bytes.fromhex(
            'E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA8215'
            '25F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0')
        self.assertEqual(sign(bytes(32), 3), expected)

    def test_bip340_official_signing_vector_one(self):
        secret = int('B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF', 16)
        message = bytes.fromhex('243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89')
        expected = bytes.fromhex(
            '6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE33418'
            '906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A')
        self.assertEqual(sign(message, secret, (1).to_bytes(32, 'big')), expected)

    def test_claim_admission_checks_each_residue(self):
        values = dict(instance=bytes(32), a=7, b=11, c=3, claimed=13, modulus=17)
        for name in ('a', 'b', 'c', 'claimed'):
            for bad in (-1, 17):
                with self.subTest(name=name, bad=bad), self.assertRaises(ValueError):
                    Claim(**(values | {name: bad}))

    def test_claim_context_limits(self):
        claim = Claim(bytes(32), 0, 0, 0, 0, 17)
        for edits in ({'instance': bytes(31)}, {'modulus': 1}, {'modulus': 2**256},
                      {'delay': 0}, {'delay': 65536}):
            with self.subTest(edits=edits), self.assertRaises(ValueError):
                replace(claim, **edits)

    def test_wide_claim_values_are_fixed_width(self):
        modulus = 2**255-19
        claim = Claim(bytes(32), modulus-1, modulus-1, modulus-1, 0, modulus)
        self.assertEqual(claim.values(), [(modulus-1).to_bytes(32, 'little')]*3+[bytes(32)])

    def test_claim_context_binds_taproot_output(self):
        claim = Claim(bytes(32), 7, 11, 3, 13, 17)
        original = claim.leaf().output()[0]
        for edits in ({'instance': b'\x01'*32}, {'a': 8}, {'b': 12}, {'c': 4},
                      {'claimed': 12}, {'modulus': 19}, {'delay': 7}):
            with self.subTest(edits=edits):
                self.assertNotEqual(original, replace(claim, **edits).leaf().output()[0])
        self.assertEqual(claim.leaf().output()[1][1:], NUMS_X)

    def test_signer_rejects_invalid_secret_and_input_lengths(self):
        for secret in (0, N, -1):
            with self.subTest(secret=secret), self.assertRaises(ValueError):
                sign(bytes(32), secret)
        for message, aux in ((b'', bytes(32)), (bytes(32), b'')):
            with self.assertRaises(ValueError):
                sign(message, 3, aux)

    def test_default_sighash_binds_input_value_script_sequence_and_outputs(self):
        leaf = Leaf(b'\x51')
        spend = Spend('01'*32, 0, 100000, leaf.output()[0], ((98000, b'\x51'),))
        base = spend.sighash(leaf)
        for edits in ({'txid': '02'*32}, {'index': 1}, {'amount': 99999},
                      {'prev_script': b'\x51'}, {'sequence': 6},
                      {'outputs': ((97000, b'\x51'),)}, {'outputs': ((98000, b'\x00'),)}):
            with self.subTest(edits=edits):
                self.assertNotEqual(base, replace(spend, **edits).sighash(leaf))
        self.assertNotEqual(base, spend.sighash(Leaf(b'\x52')))

    def test_witness_changes_preserve_transaction_identifier(self):
        spend = Spend('01'*32, 0, 100000, b'\x51', ((98000, b'\x51'),))
        left, txid = spend.serialize([b'\x01'])
        right, changed = spend.serialize([b'\x02'])
        self.assertEqual(txid, changed)
        self.assertNotEqual(left, right)
        self.assertNotEqual(sha(bytes.fromhex(left)), sha(bytes.fromhex(right)))


if __name__ == '__main__':
    unittest.main()
