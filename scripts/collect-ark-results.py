#!/usr/bin/env python3

import argparse
import json
from pathlib import Path


def load(path):
    return json.loads(Path(path).read_text()) if path and Path(path).exists() else None


def submissions(receipt):
    rows = []
    for play in receipt["plays"]:
        if play["step"] != "submit":
            continue
        rows.append({
            "id": play["id"], "txid": play["txid"], "expect": play["expect"], "expected_stage": play["expected_stage"],
            "outcome_as_expected": play["outcome_as_expected"],
            "nodes": {name: {"allowed": v["allowed"], "stage": v["stage"], "reject_reason": v["reject_reason"],
                             "vsize": v.get("vsize"), "fee_sat": v.get("fee_sat")} for name, v in play["nodes"].items()},
            "executed_against": ["bitcoin-rs node (native engine)", "Bitcoin Core 31.1"],
        })
    return rows


def lifecycle(directory):
    receipt = load(Path(directory) / "receipt.json")
    scenario = load(Path(directory) / "scenario" / "scenario.json")
    blocks = [p for p in receipt["plays"] if p["step"] == "mine"]
    return {
        "status": receipt["status"],
        "source_revision": receipt["source_revision"],
        "source_dirty": receipt["source_dirty"],
        "binary_sha256": receipt["binary_sha256"],
        "core_version": receipt["core_version"],
        "plays": len(receipt["plays"]),
        "unexpected_outcomes": len(receipt["failures"]),
        "stage_mismatches": receipt["stage_mismatches"],
        "utxo_state": {"checked_outpoints": receipt["utxo_state"]["checked_outpoints"],
                       "differences": receipt["utxo_state"]["differences"]},
        "final_height": receipt["final_height"],
        "final_tips": receipt["final_tips"],
        "signing_wall_seconds": receipt["signing_wall_seconds"],
        "total_wall_seconds": receipt["total_wall_seconds"],
        "funding_txid": receipt["funding_txid"],
        "confirmed_blocks": [{"block": b["block"], "height": b["height"], "include": b["include"]} for b in blocks],
        "csv_probe": receipt.get("csv_probe"),
        "package_probe": next((p for p in receipt["plays"] if p["step"] == "package"), None),
        "reorg": next((p for p in receipt["plays"] if p["step"] == "reorg"), None),
        "submissions": submissions(receipt),
        "signing": scenario["signing"],
        "statements": [{k: s[k] for k in ("name", "digest", "bytes")} | {"native_check_accepted": s["check"]["accepted"],
                        "coverage": s["check"]["coverage"]} for s in scenario["statements"]],
        "adversarial": scenario["adversarial"],
        "transactions": [{k: t[k] for k in ("id", "kind", "txid", "wtxid", "version", "vsize", "weight", "fee_sat", "signers", "statement")}
                         for t in scenario["txs"]],
    }


def scale(directory):
    receipt = load(Path(directory) / "receipt.json")
    scenario = load(Path(directory) / "scenario" / "scenario.json")
    txs = scenario["txs"]
    by_kind = {}
    for tx in txs:
        entry = by_kind.setdefault(tx["kind"], {"count": 0, "vsize": 0, "fee_sat": 0})
        entry["count"] += 1
        entry["vsize"] += tx["vsize"]
        entry["fee_sat"] += tx["fee_sat"] or 0
    return {
        "mode": receipt.get("mode"),
        "status": receipt["status"],
        "plays": len(receipt["plays"]),
        "unexpected_outcomes": len(receipt["failures"]),
        "utxo_differences": len(receipt["utxo_state"]["differences"]),
        "checked_outpoints": receipt["utxo_state"]["checked_outpoints"],
        "final_height": receipt["final_height"],
        "signing_wall_seconds": receipt["signing_wall_seconds"],
        "total_wall_seconds": receipt["total_wall_seconds"],
        "signing": scenario["signing"],
        "l1_by_kind": by_kind,
        "statement": {k: scenario["statements"][0][k] for k in ("digest", "bytes")},
        "executed_against": ["bitcoin-rs node (native engine)", "Bitcoin Core 31.1"],
    }


def main():
    parser = argparse.ArgumentParser(description="Collect Ark experiment outputs into results.json")
    parser.add_argument("--lifecycle", type=Path, required=True)
    parser.add_argument("--scale", type=Path, nargs="*", default=[])
    parser.add_argument("--bench", type=Path, required=True)
    parser.add_argument("--nova-bench", type=Path)
    parser.add_argument("--nova-mode", type=Path)
    parser.add_argument("--interop", type=Path)
    parser.add_argument("--ci", action="append", default=[], help="label=run-id:conclusion")
    parser.add_argument("--environment", required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    out = args.out
    out.mkdir(parents=True, exist_ok=True)
    life = lifecycle(args.lifecycle)
    scenario = load(args.lifecycle / "scenario" / "scenario.json")
    (out / "transactions.json").write_text(json.dumps(
        {"schema": "ark-nested-musig2-transactions-v1", "source_revision": life["source_revision"],
         "transactions": [{k: t[k] for k in ("id", "kind", "txid", "hex", "vsize", "fee_sat", "signers")} for t in scenario["txs"]],
         "statements": [{k: s[k] for k in ("name", "digest", "hex")} for s in scenario["statements"]]},
        indent=1) + "\n")
    (out / "adversarial-traces.json").write_text(json.dumps(
        {"schema": "ark-nested-musig2-adversarial-v1", "rust_level": life["adversarial"], "l1_submissions": life["submissions"]},
        indent=1) + "\n")
    results = {
        "schema": "ark-nested-musig2-results-v1",
        "environment": args.environment,
        "ci_runs": args.ci,
        "native": {"lifecycle": {k: v for k, v in life.items() if k not in ("transactions", "submissions", "adversarial")},
                   "adversarial_summary": {"total": len(life["adversarial"]),
                                           "as_expected": sum(1 for c in life["adversarial"] if c["as_expected"])},
                   "l1_submissions": {"total": len(life["submissions"]),
                                      "as_expected": sum(1 for s in life["submissions"] if s["outcome_as_expected"])},
                   "scale": [scale(directory) for directory in args.scale],
                   "bench": load(args.bench)},
        "nova": {"bench": load(args.nova_bench), "mode": load(args.nova_mode)},
        "interop": load(args.interop),
        "files": {"transactions": "transactions.json", "adversarial_traces": "adversarial-traces.json",
                  "sources": "sources.json"},
    }
    (out / "results.json").write_text(json.dumps(results, indent=1, sort_keys=True) + "\n")
    print(f"wrote {out / 'results.json'}")


if __name__ == "__main__":
    main()
