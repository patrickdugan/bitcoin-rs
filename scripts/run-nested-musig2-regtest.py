#!/usr/bin/env python3

import argparse
from contextlib import ExitStack
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import tempfile

from nested_musig2_staging import (
    Rpc,
    StagingError,
    assert_chain,
    btc_to_sat,
    file_hash,
    make_signature,
    mempool_check,
    signer_json,
    source_dirty,
    source_revision,
    stop_process,
    verified_prevout,
    wait_rpc,
    write_json,
)


def free_port():
    with socket.socket() as connection:
        connection.bind(("127.0.0.1", 0))
        return connection.getsockname()[1]


def main():
    parser = argparse.ArgumentParser(description="NestedMuSig2 native-node/Core regtest evidence")
    parser.add_argument("--bitcoin-rs", type=Path, required=True)
    parser.add_argument("--bitcoind", type=Path, required=True)
    parser.add_argument("--signer", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=180)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    signer = args.signer.resolve(strict=True)
    node = args.bitcoin_rs.resolve(strict=True)
    core = args.bitcoind.resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="nested-musig2-regtest-") as temporary, ExitStack() as stack:
        transient = Path(temporary)
        keys = transient / "keys.bin"
        public = signer_json(signer, "init", "--network", "regtest", "--keys", keys)
        destination_keys = transient / "destination.bin"
        destination = signer_json(
            signer, "init", "--network", "regtest", "--keys", destination_keys
        )["address"]
        write_json(args.output / "public-tree.json", public)
        core_dir = transient / "core"
        rs_dir = transient / "rs"
        core_dir.mkdir(mode=0o700)
        rs_dir.mkdir(mode=0o700)
        ports = set()
        while len(ports) < 4:
            ports.add(free_port())
        rs_rpc_port, core_rpc_port, rs_p2p_port, core_p2p_port = sorted(ports)
        rpc_secret = secrets.token_hex(24)
        environment = os.environ.copy()
        for key in tuple(environment):
            if key.startswith("BITCOIN_RS_"):
                del environment[key]
        environment["BITCOIN_RS_RPC_USER"] = "nested-staging"
        environment["BITCOIN_RS_RPC_PASSWORD"] = rpc_secret
        rs_log = stack.enter_context((args.output / "bitcoin-rs.log").open("x"))
        rs_process = subprocess.Popen(
            [
                str(node), "--network", "regtest", "--data-dir", str(rs_dir),
                "--rpc-bind", f"127.0.0.1:{rs_rpc_port}",
                "--p2p-listen", f"127.0.0.1:{rs_p2p_port}",
                "--dns-seeds-enabled=false", "--validation-engine", "native",
                "--log-level", "info",
            ],
            env=environment, stdout=rs_log, stderr=subprocess.STDOUT,
        )
        stack.callback(stop_process, rs_process)
        core_log = stack.enter_context((args.output / "bitcoind.log").open("x"))
        core_process = subprocess.Popen(
            [
                str(core), "-regtest", f"-datadir={core_dir}",
                f"-port={core_p2p_port}", f"-rpcport={core_rpc_port}",
                "-rpcbind=127.0.0.1", "-rpcallowip=127.0.0.1",
                "-listen=0", "-dnsseed=0", "-connect=0", "-disablewallet=1",
                "-server=1", "-printtoconsole=1",
            ],
            stdout=core_log, stderr=subprocess.STDOUT,
        )
        stack.callback(stop_process, core_process)
        rs = Rpc(
            f"http://127.0.0.1:{rs_rpc_port}",
            credentials="nested-staging:" + rpc_secret,
            timeout=args.timeout,
        )
        reference = Rpc(
            f"http://127.0.0.1:{core_rpc_port}",
            cookie=core_dir / "regtest" / ".cookie",
            timeout=args.timeout,
        )
        wait_rpc(rs, rs_process, args.timeout)
        wait_rpc(reference, core_process, args.timeout)
        assert_chain(rs, public, "regtest")
        assert_chain(reference, public, "regtest")
        if rs.call("getpeerinfo") or reference.call("getpeerinfo"):
            raise StagingError("isolated regtest nodes unexpectedly have peers")
        print("Mining fresh NestedMuSig2 Taproot funding on bitcoin-rs", flush=True)
        blocks = rs.call("generatetoaddress", 101, public["address"])
        if len(blocks) != 101:
            raise StagingError("native node did not generate 101 funding blocks")
        for block in blocks:
            result = reference.call("submitblock", rs.call("getblock", block, 0))
            if result is not None:
                raise StagingError(f"Core rejected a native funding block: {result}")
        if rs.call("getbestblockhash") != reference.call("getbestblockhash"):
            raise StagingError("funding chain tips differ")
        funding = reference.call("getblock", blocks[0], 2)["tx"][0]
        matches = [output for output in funding["vout"] if output["scriptPubKey"]["hex"] == public["script_pubkey"]]
        if len(matches) != 1:
            raise StagingError("funding coinbase has an unexpected payout")
        funding_output = matches[0]
        txid, vout = funding["txid"], funding_output["n"]
        amount = btc_to_sat(funding_output["value"])
        native_prevout = verified_prevout(rs, public, txid, vout, amount)
        reference_prevout = verified_prevout(reference, public, txid, vout, amount)
        signed = make_signature(signer, keys, public, txid, vout, amount, destination, 1000, 1000)
        write_json(args.output / "signed-transaction.json", signed)
        signature = bytes.fromhex(signed["signature"])
        altered = bytearray(signature)
        altered[-1] ^= 1
        raw_bytes = bytes.fromhex(signed["transaction_hex"])
        if raw_bytes.count(signature) != 1:
            raise StagingError("signature was not uniquely located in the witness")
        bad_transaction = raw_bytes.replace(signature, altered).hex()
        native_bad = mempool_check(rs, signed, raw=bad_transaction, allow=False)
        reference_bad = mempool_check(reference, signed, raw=bad_transaction, allow=False)
        native_good = mempool_check(rs, signed)
        reference_good = mempool_check(reference, signed)
        for rpc in (rs, reference):
            if rpc.call("sendrawtransaction", signed["transaction_hex"]) != signed["txid"]:
                raise StagingError("broadcast transaction ID differs from the signer")
            if signed["txid"] not in rpc.call("getrawmempool"):
                raise StagingError("submitted transaction is absent from the mempool")
        print("Both nodes accepted the signature and rejected the altered witness", flush=True)
        mined = rs.call("generateblock", destination, [signed["txid"]])["hash"]
        result = reference.call("submitblock", rs.call("getblock", mined, 0))
        if result is not None:
            raise StagingError(f"Core rejected the native spend block: {result}")
        for rpc in (rs, reference):
            if rpc.call("getbestblockhash") != mined:
                raise StagingError("spend chain tips differ")
            if signed["txid"] not in rpc.call("getblock", mined, 1)["tx"]:
                raise StagingError("signed transaction is absent from the confirmed block")
            if rpc.call("gettxout", txid, vout, True) is not None:
                raise StagingError("funding outpoint remains unspent")
            output = rpc.call("gettxout", signed["txid"], 0, True)
            if output is None or btc_to_sat(output["value"]) != amount - 1000:
                raise StagingError("confirmed output value differs from the signed transaction")
            if rpc.call("getpeerinfo"):
                raise StagingError("isolated regtest node acquired a peer")
        receipt = {
            "schema": "nested-musig2-regtest-receipt-v1",
            "status": "passed",
            "source_revision": source_revision(),
            "source_dirty": source_dirty(),
            "binary_sha256": {"bitcoin-rs": file_hash(node), "nested-musig2": file_hash(signer), "bitcoind": file_hash(core)},
            "network": "regtest",
            "genesis": public["genesis_hash"],
            "profile": public["profile"],
            "native_validation_engine": "native",
            "native_peer_count": 0,
            "core_peer_count": 0,
            "core_version": reference.call("getnetworkinfo")["version"],
            "funding_height": 1,
            "funding_chain_height": 101,
            "native_prevout": native_prevout,
            "core_prevout": reference_prevout,
            "native_tampered_rejection": native_bad,
            "core_tampered_rejection": reference_bad,
            "native_acceptance": native_good,
            "core_acceptance": reference_good,
            "txid": signed["txid"],
            "wtxid": signed["wtxid"],
            "fee_sat": signed["fee_sat"],
            "vsize": signed["vsize"],
            "confirmed_block": mined,
            "confirmed_height": 102,
        }
        write_json(args.output / "receipt.json", receipt)
        print(f"Confirmed NestedMuSig2 spend {signed['txid']} at height 102", flush=True)


if __name__ == "__main__":
    try:
        main()
    except (OSError, StagingError, subprocess.SubprocessError, ValueError) as error:
        print(f"regtest staging failed: {error}", file=sys.stderr)
        sys.exit(1)
