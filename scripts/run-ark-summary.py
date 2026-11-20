#!/usr/bin/env python3

import argparse
import json
from pathlib import Path


def notice(title, message):
    print(f"::notice title={title}::{message}")


def main():
    parser = argparse.ArgumentParser(description="Emit Ark regtest and benchmark results as workflow annotations")
    parser.add_argument("--regtest", type=Path, required=True)
    parser.add_argument("--bench", type=Path, required=True)
    args = parser.parse_args()
    receipt_path = args.regtest / "receipt.json"
    if receipt_path.exists():
        receipt = json.loads(receipt_path.read_text())
        submits = [p for p in receipt["plays"] if p["step"] == "submit"]
        notice("ark regtest", f"{receipt['status']}: {len(receipt['plays'])} plays, {len(submits)} submissions, "
                              f"{len(receipt['failures'])} unexpected, {len(receipt['stage_mismatches'])} stage mismatches, "
                              f"{len(receipt['utxo_state']['differences'])} UTXO differences, height {receipt['final_height']}")
        for mismatch in receipt["stage_mismatches"]:
            notice("ark stage", f"{mismatch['id']} expected {mismatch['expected']} observed {mismatch['nodes']} {mismatch['reasons']}")
        for play in receipt["plays"]:
            if play["step"] == "package":
                notice("ark package", " ".join(f"{name}: parent-alone {v['parent_alone']['allowed']} package {v['package_accepted']}"
                                               for name, v in play["nodes"].items()))
            if play["step"] == "reorg":
                notice("ark reorg", " ".join(f"{name}: returned {len(v['returned_to_mempool'])} dropped {len(v['dropped'])}"
                                             for name, v in play["nodes"].items()))
        scenario = args.regtest / "scenario" / "scenario.json"
        if scenario.exists():
            data = json.loads(scenario.read_text())
            good = sum(1 for case in data["adversarial"] if case["as_expected"])
            notice("ark adversarial", f"{good}/{len(data['adversarial'])} cases as expected")
            for case in data["adversarial"]:
                if not case["as_expected"]:
                    notice("ark adversarial", f"{case['name']} expected {case['expected_stage']} observed {case['observed_stage']}")
            for record in data["signing"]:
                t = record["traffic"]
                notice("ark signing", f"{record['round']} {record['shape']}: {t['sessions']} sessions {t['messages']} messages "
                                      f"{t['bytes']} bytes root fan-in {t['root_fan_in']} depth {t['max_depth']} {t['seconds']:.3f}s")
    bench_path = args.bench / "bench.json"
    if bench_path.exists():
        for row in json.loads(bench_path.read_text()):
            t = row["traffic"]
            notice("ark bench", f"{row['vtxos']} {row['shape']}: commitment {row['commitment_vsize']} vB, tree {row['tree_txs']} txs "
                                f"{row['tree_vsize_total']} vB, one exit {row['unilateral_exit_vbytes_one_user']} vB, "
                                f"sign {row['signing_seconds']:.2f}s {t['messages']} msgs fan-in {t['root_fan_in']}")


if __name__ == "__main__":
    main()
