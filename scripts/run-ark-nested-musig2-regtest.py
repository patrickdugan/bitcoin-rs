#!/usr/bin/env python3

import argparse
from contextlib import ExitStack
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import tempfile
import time

from nested_musig2_staging import (
    Rpc,
    RpcError,
    StagingError,
    btc_to_sat,
    file_hash,
    source_dirty,
    source_revision,
    stop_process,
    wait_rpc,
    write_json,
)

STAGE_CLASSES = {
    "relative-locktime": ("non-bip68-final", "non-final", "sequence lock", "locktime"),
    "missing-inputs": ("missingorspent", "missing-inputs", "missing inputs", "inputs-missing", "input not found", "unknown input", "spent"),
    "already-known": ("already-known", "already-in-mempool", "already in", "same-nonwitness", "already exists"),
    "replacement-fee": ("insufficient fee", "replacement", "rbf", "rejecting replacement"),
    "min-relay-fee": ("min relay fee", "min fee", "minimum fee", "fee too low", "mempool min fee", "below minimum"),
    "script-verification": ("script-verify", "script verify", "script", "signature", "schnorr"),
    "conflict": ("conflict",),
}
EXPECTED_CLASSES = {
    "already-spent": ("already-known", "missing-inputs"),
}


def classify(reason):
    text = (reason or "").lower()
    for stage, needles in STAGE_CLASSES.items():
        if any(needle in text for needle in needles):
            return stage
    return "unclassified"


def free_port():
    with socket.socket() as connection:
        connection.bind(("127.0.0.1", 0))
        return connection.getsockname()[1]


def run_json(binary, *arguments, timeout=1800):
    completed = subprocess.run(
        [str(binary), *map(str, arguments)], capture_output=True, text=True, check=False, timeout=timeout
    )
    if completed.returncode != 0:
        raise StagingError(f"{Path(binary).name} {arguments[0]} failed: {completed.stderr.strip()[-2000:]}")
    return json.loads(completed.stdout)


class Nodes:
    def __init__(self, rs, core, mine_address):
        self.rs = rs
        self.core = core
        self.both = (("bitcoin-rs", rs), ("core", core))
        self.mine_address = mine_address

    def mine(self, txids):
        block = self.rs.call("generateblock", self.mine_address, list(txids))["hash"]
        result = self.core.call("submitblock", self.rs.call("getblock", block, 0))
        if result is not None:
            raise StagingError(f"Core rejected native block {block}: {result}")
        for name, rpc in self.both:
            if rpc.call("getbestblockhash") != block:
                raise StagingError(f"{name} tip differs after mining {block}")
            included = set(rpc.call("getblock", block, 1)["tx"])
            missing = [txid for txid in txids if txid not in included]
            if missing:
                raise StagingError(f"{name} block {block} lacks {missing}")
        return block

    def height(self):
        return self.core.call("getblockcount")


def node_verdict(rpc, raw):
    try:
        result = rpc.call("testmempoolaccept", [raw])[0]
    except RpcError as error:
        return {"allowed": False, "reject_reason": str(error), "stage": classify(str(error))}
    reason = result.get("reject-reason") or result.get("reject_reason")
    if reason and result.get("reject-details"):
        reason = f"{reason} ({result['reject-details']})"
    return {
        "allowed": bool(result.get("allowed")),
        "reject_reason": reason,
        "stage": None if result.get("allowed") else classify(reason),
        "vsize": result.get("vsize"),
        "fee_sat": btc_to_sat(result["fees"]["base"]) if result.get("allowed") and result.get("fees") else None,
    }


def play_submit(nodes, play, txs):
    tx = txs[play["id"]]
    verdicts = {name: node_verdict(rpc, tx["hex"]) for name, rpc in nodes.both}
    expect_accept = play["expect"] == "accept"
    record = {"step": "submit", "id": play["id"], "txid": tx["txid"], "expect": play["expect"],
              "expected_stage": play["stage"] or None, "note": play["note"], "nodes": verdicts}
    agreed = all(v["allowed"] == expect_accept for v in verdicts.values())
    record["outcome_as_expected"] = agreed
    if not expect_accept:
        allowed = EXPECTED_CLASSES.get(play["stage"], (play["stage"],))
        record["stage_match"] = {name: v["stage"] in allowed for name, v in verdicts.items()}
    if expect_accept and agreed:
        for name, rpc in nodes.both:
            if rpc.call("sendrawtransaction", tx["hex"]) != tx["txid"]:
                raise StagingError(f"{name} returned a different txid for {play['id']}")
            if tx["txid"] not in rpc.call("getrawmempool"):
                raise StagingError(f"{play['id']} absent from the {name} mempool")
    return record


def play_package(nodes, play, txs):
    parent, child = txs[play["parent"]], txs[play["child"]]
    record = {"step": "package", "parent": play["parent"], "child": play["child"], "note": play["note"], "nodes": {}}
    for name, rpc in nodes.both:
        alone = node_verdict(rpc, parent["hex"])
        try:
            package = rpc.call("submitpackage", [parent["hex"], child["hex"]])
            message = package.get("package_msg") if isinstance(package, dict) else package
            accepted = message == "success"
        except RpcError as error:
            package, accepted = {"error": str(error)}, False
        record["nodes"][name] = {"parent_alone": alone, "package": package, "package_accepted": accepted}
    return record


def play_reorg(nodes, play, txs):
    depth = play["depth"]
    tip = nodes.core.call("getbestblockhash")
    target_height = nodes.height() - depth + 1
    target = nodes.core.call("getblockhash", target_height)
    removed = set()
    for height in range(target_height, target_height + depth):
        removed.update(nodes.core.call("getblock", nodes.core.call("getblockhash", height), 1)["tx"][1:])
    record = {"step": "reorg", "depth": depth, "invalidated": target, "old_tip": tip, "note": play["note"], "nodes": {}}
    for name, rpc in nodes.both:
        rpc.call("invalidateblock", target)
        mempool = set(rpc.call("getrawmempool"))
        record["nodes"][name] = {
            "new_tip": rpc.call("getbestblockhash"),
            "returned_to_mempool": sorted(removed & mempool),
            "dropped": sorted(removed - mempool),
        }
    if record["nodes"]["bitcoin-rs"]["new_tip"] != record["nodes"]["core"]["new_tip"]:
        raise StagingError("tips differ after the reorganization")
    return record


def resolve(funding_txid, txs, identifier):
    return funding_txid if identifier == "funding" else txs[identifier]["txid"]


def play_utxo(nodes, play, txs, funding_txid):
    txid = resolve(funding_txid, txs, play["id"])
    seen = {name: rpc.call("gettxout", txid, play["vout"], True) is not None for name, rpc in nodes.both}
    return {"step": "assert-utxo", "outpoint": f"{txid}:{play['vout']}", "expected_unspent": play["unspent"],
            "nodes": seen, "outcome_as_expected": all(value == play["unspent"] for value in seen.values()),
            "note": play["note"]}


def play_age(nodes, play, txs):
    txid = txs[play["id"]]["txid"]
    mined = 0
    while True:
        output = nodes.core.call("gettxout", txid, play["vout"], True)
        if output is None:
            raise StagingError(f"{play['id']}:{play['vout']} is not an unspent output")
        if output["confirmations"] >= play["age"]:
            break
        nodes.mine([])
        mined += 1
    return {"step": "mine-until-age", "outpoint": f"{txid}:{play['vout']}", "age": play["age"], "blocks_mined": mined,
            "height": nodes.height(), "note": play["note"]}


def compare_utxos(nodes, txs, funding):
    differences, checked = [], 0
    outpoints = [(funding["txid"], output["vout"]) for output in funding["outputs"]]
    for tx in txs.values():
        decoded = nodes.core.call("decoderawtransaction", tx["hex"])
        outpoints += [(tx["txid"], output["n"]) for output in decoded["vout"]]
    for txid, vout in outpoints:
        views = {}
        for name, rpc in nodes.both:
            output = rpc.call("gettxout", txid, vout, False)
            views[name] = None if output is None else (btc_to_sat(output["value"]), output["scriptPubKey"]["hex"])
        checked += 1
        if views["bitcoin-rs"] != views["core"]:
            differences.append({"outpoint": f"{txid}:{vout}", **{k: v for k, v in views.items()}})
    return {"checked_outpoints": checked, "differences": differences}


def main():
    parser = argparse.ArgumentParser(description="Ark NestedMuSig2 lifecycle on bitcoin-rs and Bitcoin Core regtest")
    parser.add_argument("--bitcoin-rs", type=Path, required=True)
    parser.add_argument("--bitcoind", type=Path, required=True)
    parser.add_argument("--ark", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--remote-users", default="2,3")
    parser.add_argument("--timeout", type=int, default=180)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    ark = args.ark.resolve(strict=True)
    node = args.bitcoin_rs.resolve(strict=True)
    core = args.bitcoind.resolve(strict=True)
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="ark-nm2-regtest-") as temporary, ExitStack() as stack:
        transient = Path(temporary)
        keys = transient / "keys"
        keys.mkdir(mode=0o700)
        init = run_json(ark, "init", "--dir", keys, "--users", 5, "--network", "regtest")
        write_json(args.output / "public-keys.json", init)
        core_dir, rs_dir = transient / "core", transient / "rs"
        core_dir.mkdir(mode=0o700)
        rs_dir.mkdir(mode=0o700)
        ports = set()
        while len(ports) < 4:
            ports.add(free_port())
        rs_rpc_port, core_rpc_port, rs_p2p_port, core_p2p_port = sorted(ports)
        rpc_secret = secrets.token_hex(24)
        environment = {k: v for k, v in os.environ.items() if not k.startswith("BITCOIN_RS_")}
        environment["BITCOIN_RS_RPC_USER"] = "ark-staging"
        environment["BITCOIN_RS_RPC_PASSWORD"] = rpc_secret
        rs_log = stack.enter_context((args.output / "bitcoin-rs.log").open("x"))
        rs_process = subprocess.Popen(
            [str(node), "--network", "regtest", "--data-dir", str(rs_dir),
             "--rpc-bind", f"127.0.0.1:{rs_rpc_port}", "--p2p-listen", f"127.0.0.1:{rs_p2p_port}",
             "--dns-seeds-enabled=false", "--validation-engine", "native", "--log-level", "info"],
            env=environment, stdout=rs_log, stderr=subprocess.STDOUT,
        )
        stack.callback(stop_process, rs_process)
        core_log = stack.enter_context((args.output / "bitcoind.log").open("x"))
        core_process = subprocess.Popen(
            [str(core), "-regtest", f"-datadir={core_dir}", f"-port={core_p2p_port}", f"-rpcport={core_rpc_port}",
             "-rpcbind=127.0.0.1", "-rpcallowip=127.0.0.1", "-listen=0", "-dnsseed=0", "-connect=0",
             "-disablewallet=1", "-server=1", "-printtoconsole=1"],
            stdout=core_log, stderr=subprocess.STDOUT,
        )
        stack.callback(stop_process, core_process)
        rs = Rpc(f"http://127.0.0.1:{rs_rpc_port}", credentials="ark-staging:" + rpc_secret, timeout=args.timeout)
        reference = Rpc(f"http://127.0.0.1:{core_rpc_port}", cookie=core_dir / "regtest" / ".cookie", timeout=args.timeout)
        wait_rpc(rs, rs_process, args.timeout)
        wait_rpc(reference, core_process, args.timeout)
        if rs.call("getpeerinfo") or reference.call("getpeerinfo"):
            raise StagingError("isolated regtest nodes unexpectedly have peers")
        nodes = Nodes(rs, reference, init["faucet_address"])
        blocks = rs.call("generatetoaddress", 110, init["faucet_address"])
        for block in blocks:
            result = reference.call("submitblock", rs.call("getblock", block, 0))
            if result is not None:
                raise StagingError(f"Core rejected a native funding block: {result}")
        coinbase = reference.call("getblock", blocks[0], 2)["tx"][0]
        paid = [o for o in coinbase["vout"] if o["scriptPubKey"].get("address") == init["faucet_address"]]
        if len(paid) != 1:
            raise StagingError("faucet coinbase output not found")
        funding = run_json(ark, "fund", "--dir", keys, "--network", "regtest", "--users", 5, "--rounds", 3,
                           "--coinbase", f"{coinbase['txid']}:{paid[0]['n']}",
                           "--coinbase-sat", btc_to_sat(paid[0]["value"]))
        write_json(args.output / "funding.json", funding)
        for name, rpc in nodes.both:
            verdict = node_verdict(rpc, funding["hex"])
            if not verdict["allowed"]:
                raise StagingError(f"{name} rejected the funding transaction: {verdict}")
            rpc.call("sendrawtransaction", funding["hex"])
        funding_block = nodes.mine([funding["txid"]])
        observed_paths = []
        for name, rpc in nodes.both:
            utxos = []
            for output in funding["outputs"]:
                seen = rpc.call("gettxout", funding["txid"], output["vout"], True)
                if seen is None:
                    raise StagingError(f"{name} lacks funding output {output['vout']}")
                utxos.append({"outpoint": f"{funding['txid']}:{output['vout']}", "amount_sat": btc_to_sat(seen["value"]),
                              "script_pubkey": seen["scriptPubKey"]["hex"], "confirmations": seen["confirmations"]})
            path = args.output / f"observed-{name}.json"
            write_json(path, {"node": name, "best_hash": rpc.call("getbestblockhash"),
                              "height": rpc.call("getblockcount"), "utxos": utxos})
            observed_paths.append(path)
        scenario_dir = args.output / "scenario"
        signing_started = time.monotonic()
        summary = run_json(ark, "scenario", "--dir", keys, "--network", "regtest",
                           "--funding", args.output / "funding.json",
                           "--observed", observed_paths[0], observed_paths[1],
                           "--remote-users", args.remote_users, "--out", scenario_dir)
        signing_seconds = time.monotonic() - signing_started
        scenario = json.loads((scenario_dir / "scenario.json").read_text())
        txs = {tx["id"]: tx for tx in scenario["txs"]}
        results = []
        for play in scenario["plays"]:
            kind = play["step"]
            if kind == "submit":
                results.append(play_submit(nodes, play, txs))
            elif kind == "package":
                results.append(play_package(nodes, play, txs))
            elif kind == "mine":
                txids = [txs[identifier]["txid"] for identifier in play["include"]]
                results.append({"step": "mine", "include": play["include"], "block": nodes.mine(txids),
                                "height": nodes.height(), "note": play["note"]})
            elif kind == "mine-until-age":
                results.append(play_age(nodes, play, txs))
            elif kind == "assert-utxo":
                results.append(play_utxo(nodes, play, txs, funding["txid"]))
            elif kind == "assert-mempool":
                seen = {name: txs[play["id"]]["txid"] in rpc.call("getrawmempool") for name, rpc in nodes.both}
                results.append({"step": "assert-mempool", "id": play["id"], "expected_present": play["present"],
                                "nodes": seen, "outcome_as_expected": all(v == play["present"] for v in seen.values()),
                                "note": play["note"]})
            elif kind == "reorg":
                results.append(play_reorg(nodes, play, txs))
            else:
                raise StagingError(f"unknown play {kind}")
            print(f"{kind:15} {play.get('id', play.get('include', ''))} -> "
                  f"{results[-1].get('outcome_as_expected', 'recorded')}", flush=True)
        utxo_state = compare_utxos(nodes, txs, funding)
        failures = [r for r in results if r.get("outcome_as_expected") is False]
        mismatched = [{"id": r["id"], "expected": r["expected_stage"], "nodes": {n: v["stage"] for n, v in r["nodes"].items()},
                       "reasons": {n: v["reject_reason"] for n, v in r["nodes"].items()}}
                      for r in results if r.get("stage_match") and not all(r["stage_match"].values())]
        tips = {name: rpc.call("getbestblockhash") for name, rpc in nodes.both}
        receipt = {
            "schema": "ark-nested-musig2-regtest-receipt-v1",
            "status": "passed" if not failures and not utxo_state["differences"] and len(set(tips.values())) == 1 else "failed",
            "source_revision": source_revision(),
            "source_dirty": source_dirty(),
            "binary_sha256": {"bitcoin-rs": file_hash(node), "ark-nm2": file_hash(ark), "bitcoind": file_hash(core)},
            "core_version": reference.call("getnetworkinfo")["version"],
            "network": "regtest",
            "funding_txid": funding["txid"],
            "funding_block": funding_block,
            "scenario_summary": summary,
            "signing_wall_seconds": round(signing_seconds, 3),
            "total_wall_seconds": round(time.monotonic() - started, 3),
            "final_tips": tips,
            "final_height": nodes.height(),
            "plays": results,
            "failures": failures,
            "stage_mismatches": mismatched,
            "utxo_state": utxo_state,
        }
        write_json(args.output / "receipt.json", receipt)
        print(f"status {receipt['status']}: {len(results)} plays, {len(failures)} unexpected outcomes, "
              f"{len(mismatched)} stage mismatches, {len(utxo_state['differences'])} UTXO differences", flush=True)
        if receipt["status"] != "passed":
            sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except (OSError, StagingError, subprocess.SubprocessError, ValueError, KeyError) as error:
        print(f"ark regtest failed: {error}", file=sys.stderr)
        sys.exit(1)
