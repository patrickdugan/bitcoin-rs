#!/usr/bin/env python3

import argparse
import json
from pathlib import Path
import subprocess
import sys

from nested_musig2_staging import (
    Rpc,
    RpcError,
    StagingError,
    btc_to_sat,
    file_hash,
    source_dirty,
    source_revision,
    write_json,
)

TESTNET4_GENESIS = "00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043"


def run_json(binary, *arguments, timeout=1800):
    completed = subprocess.run([str(binary), *map(str, arguments)], capture_output=True, text=True, check=False, timeout=timeout)
    if completed.returncode != 0:
        raise StagingError(f"ark-nm2 {arguments[0]} failed: {completed.stderr.strip()[-2000:]}")
    return json.loads(completed.stdout) if completed.stdout.strip().startswith(("{", "[")) else completed.stdout


def preflight(rpc, minimum_progress):
    info = rpc.call("getblockchaininfo")
    checks = {
        "chain_is_testnet4": info.get("chain") == "testnet4",
        "genesis_matches": rpc.call("getblockhash", 0) == TESTNET4_GENESIS,
        "not_initial_download": info.get("initialblockdownload") is False,
        "headers_equal_blocks": info.get("headers") == info.get("blocks"),
        "verification_progress": float(info.get("verificationprogress", 0)) >= minimum_progress,
    }
    return {"blocks": info.get("blocks"), "best_hash": info.get("bestblockhash"), "checks": checks,
            "passed": all(checks.values())}


def preview(rpc, raw_list):
    try:
        return rpc.call("testmempoolaccept", raw_list)
    except RpcError as error:
        return [{"allowed": False, "reject-reason": str(error)}]


def main():
    parser = argparse.ArgumentParser(description="Ark NestedMuSig2 testnet4 staging; broadcasts only with --broadcast")
    parser.add_argument("--stage", choices=("preflight", "fund", "round"), required=True)
    parser.add_argument("--ark", type=Path, required=True)
    parser.add_argument("--keys", type=Path, required=True, help="directory from `ark-nm2 init --network testnet4`")
    parser.add_argument("--rpc-url", required=True)
    parser.add_argument("--cookie", type=Path, required=True)
    parser.add_argument("--second-rpc-url")
    parser.add_argument("--second-cookie", type=Path)
    parser.add_argument("--faucet-outpoint", help="txid:vout paying the faucet key from `init`")
    parser.add_argument("--faucet-sat", type=int)
    parser.add_argument("--boarding-sat", type=int, default=20_000)
    parser.add_argument("--liquidity-sat", type=int, default=100_000)
    parser.add_argument("--max-total-sat", type=int, default=600_000)
    parser.add_argument("--funding", type=Path, help="funding.json from the fund stage (round stage)")
    parser.add_argument("--remote-users", default="2,3")
    parser.add_argument("--minimum-progress", type=float, default=0.9999)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--broadcast", action="store_true")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    ark = args.ark.resolve(strict=True)
    rpc = Rpc(args.rpc_url, cookie=args.cookie, timeout=120)
    observers = [("primary", rpc)]
    if args.second_rpc_url:
        observers.append(("secondary", Rpc(args.second_rpc_url, cookie=args.second_cookie, timeout=120)))
    receipt = {
        "schema": "ark-nested-musig2-testnet4-receipt-v1",
        "stage": args.stage,
        "source_revision": source_revision(),
        "source_dirty": source_dirty(),
        "ark_sha256": file_hash(ark),
        "broadcast_requested": args.broadcast,
        "broadcast": [],
        "preflight": {name: preflight(node, args.minimum_progress) for name, node in observers},
    }
    if not all(p["passed"] for p in receipt["preflight"].values()):
        write_json(args.output / "receipt.json", receipt)
        raise StagingError(f"preflight failed: {receipt['preflight']}")
    if args.stage == "preflight":
        write_json(args.output / "receipt.json", receipt)
        print("preflight passed", flush=True)
        return
    if args.stage == "fund":
        if not args.faucet_outpoint or args.faucet_sat is None:
            raise StagingError("--faucet-outpoint and --faucet-sat are required")
        txid, vout = args.faucet_outpoint.split(":")
        seen = rpc.call("gettxout", txid, int(vout), False)
        if seen is None or btc_to_sat(seen["value"]) != args.faucet_sat or seen["confirmations"] < 1:
            raise StagingError("faucet outpoint is absent, unconfirmed, or has a different value")
        funding = run_json(ark, "fund", "--dir", args.keys, "--network", "testnet4", "--users", 5, "--rounds", 3,
                           "--coinbase", args.faucet_outpoint, "--coinbase-sat", args.faucet_sat,
                           "--boarding-sat", args.boarding_sat, "--liquidity-sat", args.liquidity_sat)
        spent = sum(o["amount_sat"] for o in funding["outputs"] if o["role"] != "change") + funding["fee_sat"]
        if spent > args.max_total_sat:
            raise StagingError(f"funding commits {spent} sat, above --max-total-sat {args.max_total_sat}")
        faucet_script = next(o["script_pubkey"] for o in funding["outputs"] if o["role"] == "change")
        if seen["scriptPubKey"]["hex"] != faucet_script:
            raise StagingError("faucet outpoint does not pay the faucet key in --keys")
        write_json(args.output / "funding.json", funding)
        receipt["funding_preview"] = preview(rpc, [funding["hex"]])
        if not receipt["funding_preview"][0].get("allowed"):
            write_json(args.output / "receipt.json", receipt)
            raise StagingError(f"funding preview rejected: {receipt['funding_preview']}")
        if args.broadcast:
            receipt["broadcast"].append({"id": "funding", "txid": rpc.call("sendrawtransaction", funding["hex"])})
        write_json(args.output / "receipt.json", receipt)
        print(f"funding {funding['txid']} previewed; broadcast={args.broadcast}", flush=True)
        return
    if args.funding is None:
        raise StagingError("--funding is required for the round stage")
    funding = json.loads(args.funding.read_text())
    observed_paths = []
    for name, node in (observers * 2)[:2]:
        utxos = []
        for output in funding["outputs"]:
            seen = node.call("gettxout", funding["txid"], output["vout"], True)
            if seen is None:
                raise StagingError(f"{name} lacks funding output {output['vout']}; confirm the funding first")
            utxos.append({"outpoint": f"{funding['txid']}:{output['vout']}", "amount_sat": btc_to_sat(seen["value"]),
                          "script_pubkey": seen["scriptPubKey"]["hex"], "confirmations": seen["confirmations"]})
        path = args.output / f"observed-{len(observed_paths)}-{name}.json"
        write_json(path, {"node": name, "best_hash": node.call("getbestblockhash"), "height": node.call("getblockcount"),
                          "utxos": utxos})
        observed_paths.append(path)
    receipt["observers"] = [name for name, _ in observers]
    run_json(ark, "scenario", "--dir", args.keys, "--network", "testnet4", "--funding", args.funding,
             "--observed", observed_paths[0], observed_paths[1], "--remote-users", args.remote_users,
             "--out", args.output / "scenario")
    scenario = json.loads((args.output / "scenario" / "scenario.json").read_text())
    txs = {tx["id"]: tx for tx in scenario["txs"]}
    receipt["native_checks"] = {r["name"]: r["check"]["accepted"] for r in scenario["statements"]}
    receipt["adversarial_as_expected"] = sum(1 for c in scenario["adversarial"] if c["as_expected"])
    receipt["adversarial_total"] = len(scenario["adversarial"])
    commitment = txs["r1-commitment"]["hex"]
    trees = [txs[i]["hex"] for i in sorted(t for t in txs if t.startswith("r1-tree-"))]
    receipt["cooperative_preview"] = preview(rpc, [commitment])
    receipt["tree_package_preview"] = preview(rpc, [commitment, *trees])
    receipt["recovery_packages"] = {}
    for user, exit_id in (("D", "exit-d"), ("B", "exit-b")):
        exit_preview = preview(rpc, [commitment, *trees, txs[exit_id]["hex"]])
        receipt["recovery_packages"][user] = {
            "exit_signers": txs[exit_id]["signers"],
            "preview": exit_preview,
            "exit_blocked_only_by_relative_locktime": any("bip68" in str(r.get("reject-reason", "")).lower()
                                                           for r in exit_preview),
        }
    if args.broadcast:
        if not receipt["cooperative_preview"][0].get("allowed"):
            raise StagingError("refusing to broadcast a commitment that the node rejects")
        receipt["broadcast"].append({"id": "r1-commitment", "txid": rpc.call("sendrawtransaction", commitment)})
    write_json(args.output / "receipt.json", receipt)
    print(f"round stage complete; cooperative preview {receipt['cooperative_preview']}; broadcast={args.broadcast}", flush=True)


if __name__ == "__main__":
    try:
        main()
    except (OSError, StagingError, subprocess.SubprocessError, ValueError, KeyError) as error:
        print(f"testnet4 staging failed: {error}", file=sys.stderr)
        sys.exit(1)
