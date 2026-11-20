#!/usr/bin/env python3

import argparse
from pathlib import Path
import subprocess
import sys

from nested_musig2_staging import (
    Rpc,
    StagingError,
    assert_chain,
    file_hash,
    make_signature,
    mempool_check,
    signer_json,
    source_dirty,
    source_revision,
    verified_prevout,
    write_json,
)


def main():
    parser = argparse.ArgumentParser(description="Stage a NestedMuSig2 spend against a local testnet4 node")
    parser.add_argument("--network", choices=["testnet4"], required=True)
    parser.add_argument("--signer", type=Path, required=True)
    parser.add_argument("--keys", type=Path, required=True)
    parser.add_argument("--rpc-url", required=True)
    parser.add_argument("--cookie", type=Path, required=True)
    parser.add_argument("--txid", required=True)
    parser.add_argument("--vout", type=int, required=True)
    parser.add_argument("--amount-sat", type=int, required=True)
    parser.add_argument("--destination", required=True)
    parser.add_argument("--fee-sat", type=int, required=True)
    parser.add_argument("--max-fee-sat", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--broadcast", action="store_true")
    args = parser.parse_args()
    if args.amount_sat <= 0 or args.vout < 0 or args.fee_sat <= 0 or args.fee_sat > args.max_fee_sat:
        raise StagingError("amount, output index, and fee policy are invalid")
    signer = args.signer.resolve(strict=True)
    public = signer_json(signer, "info", "--network", args.network, "--keys", args.keys)
    rpc = Rpc(args.rpc_url, cookie=args.cookie)
    chain = assert_chain(rpc, public, "testnet4")
    if chain.get("initialblockdownload", True):
        raise StagingError("local node must finish initial synchronization")
    prevout = verified_prevout(rpc, public, args.txid, args.vout, args.amount_sat)
    signed = make_signature(
        signer, args.keys, public, args.txid, args.vout, args.amount_sat,
        args.destination, args.fee_sat, args.max_fee_sat,
    )
    verdict = mempool_check(rpc, signed)
    args.output.mkdir(parents=True, exist_ok=False)
    write_json(args.output / "signed-transaction.json", signed)
    receipt = {
        "schema": "nested-musig2-testnet-receipt-v1",
        "status": "prepared",
        "source_revision": source_revision(),
        "source_dirty": source_dirty(),
        "signer_sha256": file_hash(signer),
        "network": "testnet4",
        "genesis": public["genesis_hash"],
        "checked_tip": chain["bestblockhash"],
        "checked_prevout": prevout,
        "mempool_acceptance": verdict,
        "txid": signed["txid"],
        "fee_sat": args.fee_sat,
        "max_fee_sat": args.max_fee_sat,
    }
    if args.broadcast:
        verified_prevout(rpc, public, args.txid, args.vout, args.amount_sat)
        submitted = rpc.call("sendrawtransaction", signed["transaction_hex"])
        if submitted != signed["txid"]:
            raise StagingError("submitted transaction ID differs from the signed transaction")
        receipt["status"] = "broadcast"
        receipt["in_mempool"] = signed["txid"] in rpc.call("getrawmempool")
        print(f"Broadcast testnet4 transaction {submitted}")
    else:
        print(f"Prepared testnet4 transaction {signed['txid']}")
    write_json(args.output / "receipt.json", receipt)


if __name__ == "__main__":
    try:
        main()
    except (OSError, StagingError, subprocess.SubprocessError, ValueError) as error:
        print(f"testnet staging failed: {error}", file=sys.stderr)
        sys.exit(1)
