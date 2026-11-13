"""Offline checks for the MULADDMOD adversarial campaign library."""
import random
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / 'research'
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'campaign'))

import muladdmod_dispute_rpc as reference  # noqa: E402
from btc import schnorr_sign, schnorr_verify, xonly, sha  # noqa: E402
from contract import Claim, spend_claim  # noqa: E402
import refinterp  # noqa: E402


class CampaignLibrary(unittest.TestCase):
    def test_contract_leaf_matches_reference_fixture(self):
        for modulus, (a, b, c) in [(17, (7, 11, 3)), (2**255 - 19, (2**255 - 20,) * 3)]:
            for i in range(3):
                claimed = (a * b + c + i) % modulus
                instance = sha(b'claim' + bytes([i]))
                ours = Claim(instance, a, b, c, claimed, modulus)
                theirs = reference.Claim(instance, a, b, c, claimed, modulus)
                self.assertEqual(ours.script(), theirs.leaf().script)
                self.assertEqual(ours.spk(), theirs.leaf().output()[0])
                self.assertEqual(ours.tree().control(0), theirs.leaf().output()[1])

    def test_schnorr_roundtrip_and_reference_signer_agree(self):
        msg = sha(b'campaign')
        for secret in (1, 3, 5, 7, 2**200 + 12345):
            sig = schnorr_sign(msg, secret)
            self.assertTrue(schnorr_verify(msg, xonly(secret), sig))
            self.assertEqual(sig, reference.sign(msg, secret))
            self.assertFalse(schnorr_verify(msg, xonly(secret), bytes([sig[0] ^ 1]) + sig[1:]))

    def test_reference_interpreter_decides_recovery_by_arithmetic(self):
        txid = '11' * 32
        for claimed, expected in [(13, 'OK'), (12, 'EVAL_FALSE')]:
            claim = Claim(sha(b'x'), 7, 11, 3, claimed, 17)
            tx = spend_claim(claim, txid, 0, 100_000, True)
            got = refinterp.verify_taproot_input(tx, 0, [(100_000, claim.spk())], muladdmod=True)
            self.assertEqual(got, expected)
            # flag off: 0xf0 is OP_SUCCESS240 and the whole leaf succeeds
            off = refinterp.verify_taproot_input(tx, 0, [(100_000, claim.spk())], muladdmod=False)
            self.assertEqual(off, 'OK')

    def test_reference_muladdmod_matches_integer_semantics(self):
        rng = random.Random(7)
        for _ in range(500):
            w = rng.randint(1, 32)
            m = rng.randrange(max(2, 1 << (8 * (w - 1))), 1 << (8 * w))
            a, b, c = (rng.randrange(m) for _ in range(3))
            enc = [x.to_bytes(w, 'little') for x in (a, b, c, m)]
            self.assertEqual(refinterp.muladdmod(*enc), ((a * b + c) % m).to_bytes(w, 'little'))


if __name__ == '__main__':
    unittest.main()
