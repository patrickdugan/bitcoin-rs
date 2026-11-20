import importlib.util
from pathlib import Path
import unittest
from decimal import Decimal


SPEC = importlib.util.spec_from_file_location(
    "nested_musig2_staging", Path(__file__).resolve().parents[1] / "nested_musig2_staging.py"
)
STAGING = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(STAGING)


class RpcBoundaryTests(unittest.TestCase):
    def test_credentials_stay_on_literal_loopback_endpoint(self):
        for url in (
            "https://127.0.0.1:18443",
            "http://localhost:18443",
            "http://192.168.1.2:18443",
            "http://example.com:18443",
            "http://user:password@127.0.0.1:18443",
            "http://127.0.0.1:18443/wallet/staging",
            "http://127.0.0.1:18443/?key=ignored",
            "http://127.0.0.1:18443/#ignored",
            "http://127.0.0.1",
        ):
            with self.subTest(url=url), self.assertRaises(STAGING.StagingError):
                STAGING.Rpc(url, credentials="test:test")
        for url in ("http://127.0.0.1:18443", "http://[::1]:18443/"):
            with self.subTest(url=url):
                self.assertEqual(STAGING.Rpc(url, credentials="test:test").url, url)

    def test_redirect_refuses_credential_forwarding(self):
        with self.assertRaises(STAGING.RpcError):
            STAGING.NoRedirect().redirect_request(
                None, None, 302, "redirect", {}, "http://192.0.2.1:18443"
            )

    def test_satoshi_conversion_requires_exact_integral_amount(self):
        self.assertEqual(STAGING.btc_to_sat(Decimal("0.00000001")), 1)
        self.assertEqual(STAGING.btc_to_sat(Decimal("1.25000000")), 125_000_000)
        for amount in (Decimal("0.000000001"), Decimal("Infinity"), Decimal("NaN")):
            with self.subTest(amount=amount), self.assertRaises(STAGING.StagingError):
                STAGING.btc_to_sat(amount)

    def test_prevout_check_refuses_wrong_value_tree_or_maturity(self):
        class StubRpc:
            def __init__(self, result):
                self.result = result

            def call(self, *arguments):
                return self.result

        public = {"script_pubkey": "5120" + "01" * 32}
        good = {
            "value": Decimal("0.001"),
            "scriptPubKey": {"hex": public["script_pubkey"]},
            "confirmations": 100,
            "coinbase": True,
        }
        self.assertEqual(
            STAGING.verified_prevout(StubRpc(good), public, "01" * 32, 0, 100_000), good
        )
        for result in (
            None,
            {**good, "value": Decimal("0.0009")},
            {**good, "scriptPubKey": {"hex": "51"}},
            {**good, "confirmations": 99},
        ):
            with self.subTest(result=result), self.assertRaises(STAGING.StagingError):
                STAGING.verified_prevout(StubRpc(result), public, "01" * 32, 0, 100_000)


if __name__ == "__main__":
    unittest.main()
