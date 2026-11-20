import importlib.util
from pathlib import Path
import sys
import unittest

SCRIPTS = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SCRIPTS))
SPEC = importlib.util.spec_from_file_location("ark_regtest", SCRIPTS / "run-ark-nested-musig2-regtest.py")
ARK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ARK)


class ClassifyCoreRejectReasons(unittest.TestCase):
    def test_core_reject_reasons_map_to_stages(self):
        cases = {
            "non-BIP68-final": "relative-locktime",
            "bad-txns-inputs-missingorspent": "missing-inputs",
            "missing-inputs": "missing-inputs",
            "txn-already-known": "already-known",
            "insufficient fee, rejecting replacement abc; new feerate 0.00001 <= old feerate 0.00002": "replacement-fee",
            "min relay fee not met, 0 < 110": "min-relay-fee",
            "mempool-script-verify-flag-failed (Invalid Schnorr signature)": "script-verification",
            "txn-mempool-conflict": "conflict",
        }
        for reason, stage in cases.items():
            with self.subTest(reason=reason):
                self.assertEqual(ARK.classify(reason), stage)

    def test_unknown_reason_is_not_silently_accepted(self):
        self.assertEqual(ARK.classify("something new"), "unclassified")
        self.assertEqual(ARK.classify(None), "unclassified")


if __name__ == "__main__":
    unittest.main()
