#!/usr/bin/env python3

import argparse
import json
from pathlib import Path
import subprocess
import sys
import time


class ModeError(RuntimeError):
    pass


def timed(command, timeout):
    started = time.monotonic()
    wrapped = ["/usr/bin/time", "-f", "%M", *map(str, command)]
    completed = subprocess.run(wrapped, capture_output=True, text=True, check=False, timeout=timeout)
    seconds = time.monotonic() - started
    lines = completed.stderr.strip().splitlines()
    peak_kib = int(lines[-1]) if lines and lines[-1].isdigit() else None
    return completed, seconds, peak_kib


def ark_json(ark, *arguments, timeout=600):
    completed = subprocess.run([str(ark), *map(str, arguments)], capture_output=True, text=True, check=False, timeout=timeout)
    if completed.returncode != 0:
        raise ModeError(f"ark-nm2 {arguments[0]} failed: {completed.stderr.strip()}")
    return json.loads(completed.stdout)


def verify(ark, verifier, vk, statement, public, proof, witness, network="regtest"):
    return ark_json(ark, "verify-proof", "--statement", statement, "--public", public, "--proof", proof,
                    "--witness", witness, "--verifier", verifier, "--vk", vk, "--network", network)


def signed_hex(scenario, prefix):
    return [tx["hex"] for tx in scenario["txs"] if tx["id"].startswith(prefix) and tx["kind"] in ("commitment", "tree", "forfeit")]


def main():
    parser = argparse.ArgumentParser(description="Native versus Nova verification of the same Ark statements")
    parser.add_argument("--ark", type=Path, required=True)
    parser.add_argument("--ark-nova", type=Path, required=True)
    parser.add_argument("--scenario-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--vk", required=True)
    parser.add_argument("--rounds", default="r1,r2")
    parser.add_argument("--prove-timeout", type=int, default=3600)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    ark, nova = args.ark.resolve(strict=True), args.ark_nova.resolve(strict=True)
    scenario = json.loads((args.scenario_dir / "scenario.json").read_text())
    rounds = {}
    for name in args.rounds.split(","):
        statement = args.scenario_dir / f"statement-{name}.bin"
        witness = args.scenario_dir / f"nova-witness-{name}.json"
        signed = args.output / f"signed-{name}.txt"
        signed.write_text("\n".join(signed_hex(scenario, f"{name}-")) + "\n")
        native_started = time.monotonic()
        native = ark_json(ark, "check", "--statement", statement, "--signed", signed)
        native_seconds = time.monotonic() - native_started
        proof_dir = args.output / f"proof-{name}"
        completed, prove_seconds, prove_peak = timed([nova, "prove", "--witness", witness, "--out", proof_dir], args.prove_timeout)
        if completed.returncode != 0:
            raise ModeError(f"ark-nova prove {name} failed: {completed.stderr.strip()[-2000:]}")
        public = json.loads((proof_dir / "public.json").read_text())
        result = verify(ark, nova, args.vk, statement, proof_dir / "public.json", proof_dir / "proof.bin", witness)
        rounds[name] = {
            "statement": str(statement.name),
            "native_check": {"accepted": native["accepted"], "seconds": round(native_seconds, 4),
                             "findings": len(native["findings"]), "coverage": native["coverage"]},
            "nova": {"prove_wall_seconds": round(prove_seconds, 3), "prove_peak_rss_kib": prove_peak,
                     "public": public, "proof_bytes": (proof_dir / "proof.bin").stat().st_size,
                     "verification": result},
        }
        print(f"{name}: native accepted={native['accepted']} in {native_seconds:.3f}s; "
              f"nova prove {prove_seconds:.1f}s, verify accepted={result['accepted']} in {result['verify_seconds']:.2f}s", flush=True)

    first, second = args.rounds.split(",")[:2]
    s1, w1 = args.scenario_dir / f"statement-{first}.bin", args.scenario_dir / f"nova-witness-{first}.json"
    s2 = args.scenario_dir / f"statement-{second}.bin"
    p1 = args.output / f"proof-{first}"
    controls = []

    def control(name, expected, result):
        observed = result.get("rejected_at") if not result.get("accepted") else "accepted"
        controls.append({"name": name, "expected_stage": expected, "observed_stage": observed,
                         "as_expected": observed == expected, "executed_against": ["ark-nm2 verify-proof", "nova-verifier"]})

    control("wrong-network", "network", verify(ark, nova, args.vk, s1, p1 / "public.json", p1 / "proof.bin", w1, network="testnet4"))
    control("proof-attached-to-other-round", "statement-digest", verify(ark, nova, args.vk, s2, p1 / "public.json", p1 / "proof.bin", w1))
    tampered = json.loads((p1 / "public.json").read_text())
    tampered["fee_bound_sat"] += 1
    altered_public = args.output / "altered-public.json"
    altered_public.write_text(json.dumps(tampered))
    control("altered-public-inputs", "public-inputs", verify(ark, nova, args.vk, s1, altered_public, p1 / "proof.bin", w1))
    control("unpinned-verifier-key", "verifier-key", verify(ark, nova, "00" * 32, s1, p1 / "public.json", p1 / "proof.bin", w1))
    unknown = dict(json.loads((p1 / "public.json").read_text()), schema="ark-transition-nova-public-v0")
    unknown_public = args.output / "unknown-schema-public.json"
    unknown_public.write_text(json.dumps(unknown))
    control("unrecognized-schema", "unrecognized-schema", verify(ark, nova, args.vk, s1, unknown_public, p1 / "proof.bin", w1))
    short_witness = json.loads(w1.read_text())
    short_witness["items"] = short_witness["items"][:-1]
    short_path = args.output / "incomplete-witness.json"
    short_path.write_text(json.dumps(short_witness))
    control("incomplete-transcript", "incomplete-transcript", verify(ark, nova, args.vk, s1, p1 / "public.json", p1 / "proof.bin", short_path))
    truncated = args.output / "truncated-proof.bin"
    data = (p1 / "proof.bin").read_bytes()
    truncated.write_bytes(data[: len(data) // 2])
    control("truncated-proof", "nova-verifier", verify(ark, nova, args.vk, s1, p1 / "public.json", truncated, w1))

    bad_signed = args.output / "signed-invalid-signature.txt"
    lines = (args.output / f"signed-{first}.txt").read_text().split()
    tree_hex = next(tx["hex"] for tx in scenario["txs"] if tx["id"] == f"{first}-tree-0")
    signature_offset = tree_hex.index("0140") + 4
    flipped = tree_hex[:signature_offset] + ("0" if tree_hex[signature_offset] != "0" else "1") + tree_hex[signature_offset + 1:]
    bad_signed.write_text("\n".join(flipped if line == tree_hex else line for line in lines) + "\n")
    native_bad = ark_json(ark, "check", "--statement", s1, "--signed", bad_signed)
    proof_still = rounds[first]["nova"]["verification"]["accepted"]
    controls.append({
        "name": "valid-proof-invalid-spend",
        "expected_stage": "script-verification",
        "observed_stage": next((f["rule"] for f in native_bad["findings"] if not f["ok"]), "accepted"),
        "as_expected": (not native_bad["accepted"]) and proof_still,
        "detail": "the Nova proof for the statement still verifies; the settlement verdict requires the native script check, which rejects the altered tree signature",
        "executed_against": ["nova-verifier", "bitcoin-rs-script"],
    })
    mutation_dir = args.output / "mutations"
    completed, _, _ = timed([nova, "mutate", "--witness", w1, "--out", mutation_dir], args.prove_timeout)
    mutations = json.loads((mutation_dir / "mutations.json").read_text()) if (mutation_dir / "mutations.json").exists() else None
    summary = {
        "schema": "ark-nova-mode-v1",
        "ark_nova_sha256": subprocess.run(["sha256sum", str(nova)], capture_output=True, text=True).stdout.split()[0],
        "vk_digest": args.vk,
        "rounds": rounds,
        "envelope_controls": controls,
        "prover_mutations": mutations,
        "mutate_exit": completed.returncode,
    }
    (args.output / "nova-mode.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    bad = [c["name"] for c in controls if not c["as_expected"]]
    print(f"envelope controls: {len(controls) - len(bad)}/{len(controls)} as expected {bad}", flush=True)
    if bad or any(not r["nova"]["verification"]["accepted"] for r in rounds.values()):
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ModeError, subprocess.SubprocessError, ValueError, KeyError) as error:
        print(f"nova mode failed: {error}", file=sys.stderr)
        sys.exit(1)
