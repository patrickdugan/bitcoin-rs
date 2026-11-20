#!/usr/bin/env python3

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

SECP256K1_P = 2**256 - 2**32 - 977


def xonly_from(seed):
    while True:
        candidate = int.from_bytes(hashlib.sha256(seed).digest(), "big")
        if candidate < SECP256K1_P:
            y_squared = (pow(candidate, 3, SECP256K1_P) + 7) % SECP256K1_P
            if pow(y_squared, (SECP256K1_P - 1) // 2, SECP256K1_P) == 1:
                return candidate.to_bytes(32, "big").hex()
        seed = hashlib.sha256(seed).digest()


def cases():
    fixed = [
        ("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
         "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5", 12),
    ]
    derived = [(xonly_from(b"server%d" % index), xonly_from(b"owner%d" % index), blocks)
               for index, blocks in enumerate((1, 16, 17, 144, 1008, 65535))]
    return [{"server_xonly": s, "owner_xonly": o, "exit_blocks": b} for s, o, b in fixed + derived]


def main():
    parser = argparse.ArgumentParser(description="Compare default VTXO scripts with arkade-os/rust-sdk ark-core")
    parser.add_argument("--ark", type=Path, required=True)
    parser.add_argument("--arkade", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    request = {"network": "regtest", "cases": cases()}
    upstream = json.loads(subprocess.run([str(args.arkade)], input=json.dumps(request), capture_output=True,
                                         text=True, check=True, timeout=120).stdout)
    results = []
    for case, theirs in zip(request["cases"], upstream["cases"]):
        ours = json.loads(subprocess.run(
            [str(args.ark), "vtxo-script", "--server", case["server_xonly"], "--owner", case["owner_xonly"],
             "--exit-blocks", str(case["exit_blocks"])], capture_output=True, text=True, check=True, timeout=60).stdout)
        results.append({
            **case,
            "ark_core_script_pubkey": theirs["script_pubkey"],
            "ark_nm2_script_pubkey": ours["script_pubkey"],
            "script_pubkey_equal": theirs["script_pubkey"] == ours["script_pubkey"],
            "leaves_equal": sorted(theirs["tapscripts"]) == sorted(ours["tapscripts"]),
        })
    summary = {"schema": "ark-interop-comparison-v1", "ark_core_rev": upstream.get("ark_core_rev"), "cases": results,
               "all_equal": all(r["script_pubkey_equal"] and r["leaves_equal"] for r in results)}
    args.output.write_text(json.dumps(summary, indent=2) + "\n")
    equal = sum(r["script_pubkey_equal"] and r["leaves_equal"] for r in results)
    print(f"::notice title=ark-core interop::{equal}/{len(results)} default VTXO scripts identical to ark-core {summary['ark_core_rev']}")
    if not summary["all_equal"]:
        sys.exit(1)


if __name__ == "__main__":
    main()
