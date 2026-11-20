import argparse
import hashlib
import importlib.util
import json
from pathlib import Path


SOURCES = {
    "nested": {
        "repository": "patrickdugan/bips",
        "commit": "44e9d2518e7fa9073fd904f6224b221057c48c2c",
        "path": "bip-nested-musig2/reference.py",
        "sha256": "e22d98df42838a3ac9106df0c6e96b3ee3242a5a081aee54ae183aa0b282d2ef",
    },
    "bip327": {
        "repository": "bitcoin/bips",
        "commit": "9cf75150d27c4e735ddde933a92d00bf083a18d4",
        "path": "bip-0327/reference.py",
        "sha256": "1167993fe159c39c004f74d9046e931ae700a2ce9203c4cf58a51a000c1294e8",
    },
}


def load_reference(name, path):
    expected = SOURCES[name]["sha256"]
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if actual != expected:
        raise ValueError(f"{name} reference SHA256 mismatch: {actual}")
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def scalar(value):
    return value.to_bytes(32, "big")


def make_tree(reference, shape, name="root"):
    if isinstance(shape, int):
        secret = scalar(shape)
        return {"id": name, "secret_key": secret, "public_key": reference.individual_pk(secret)}
    children = [make_tree(reference, child, f"{name}.{index}") for index, child in enumerate(shape)]
    context = reference.key_agg(reference.key_sort([child["public_key"] for child in children]))
    return {"id": name, "children": children, "key_context": context, "public_key": reference.cbytes(context.Q)}


def generate_case(reference, standard, name, shape, message, tweak_values, tweak_modes):
    root = make_tree(reference, shape)
    tweaks = [scalar(value) for value in tweak_values]
    final_context = reference.apply_tweaks(root["key_context"], tweaks, tweak_modes)
    final_key = reference.get_xonly_pk(final_context)
    leaves = []
    nodes = []
    extra_input = b"bitcoin-rs-nested-musig2-conformance-v1"

    def round_one(node):
        if "children" not in node:
            randomness = hashlib.sha256((name + ":" + node["id"]).encode()).digest()
            secnonce, pubnonce = reference.nonce_gen_internal(
                randomness, node["secret_key"], node["public_key"], final_key, message, extra_input
            )
            node.update(randomness=randomness, secret_nonce=bytes(secnonce), public_nonce=pubnonce, outward=pubnonce)
            return
        for child in node["children"]:
            round_one(child)
        internal = reference.nonce_agg([child["outward"] for child in node["children"]])
        node["internal_nonce"] = internal
        if node is not root:
            node["outward"] = reference.nonce_agg_ext(internal, node["public_key"])

    def round_two(node, nonce_path, key_path):
        session = reference.SessionContext(nonce_path, key_path, tweaks, tweak_modes, message)
        if "children" not in node:
            secret_nonce = bytearray(node["secret_nonce"])
            partial = reference.sign(secret_nonce, node["secret_key"], session)
            assert secret_nonce[:64] == bytes(64)
            assert reference.partial_sig_verify(partial, node["public_nonce"], node["public_key"], session)
            row = {
                "id": node["id"],
                "secret_key": node["secret_key"].hex(),
                "public_key": node["public_key"].hex(),
                "randomness": node["randomness"].hex(),
                "secret_nonce": node["secret_nonce"].hex(),
                "public_nonce": node["public_nonce"].hex(),
                "nonce_path": [value.hex() for value in nonce_path],
                "key_path": [[value.hex() for value in level] for level in key_path],
                "partial_signature": partial.hex(),
            }
            leaves.append(row)
            node["partial"] = partial
            return partial
        partials = []
        for index, child in enumerate(node["children"]):
            siblings = [other["public_key"] for other_index, other in enumerate(node["children"]) if other_index != index]
            partials.append(round_two(child, nonce_path + [node["internal_nonce"]], key_path + [siblings]))
        partial_sum = reference.partial_sig_agg_intermediate(partials)
        node["partial"] = partial_sum
        if node is not root:
            assert reference.partial_sig_verify(partial_sum, node["outward"], node["public_key"], session)
        nodes.append({
            "id": node["id"],
            "public_keys": [child["public_key"].hex() for child in node["children"]],
            "aggregate_key": node["public_key"].hex(),
            "child_nonces": [child["outward"].hex() for child in node["children"]],
            "internal_nonce": node["internal_nonce"].hex(),
            "external_nonce": node.get("outward", b"").hex(),
            "binding_coefficient": scalar(reference.agg_nonce_coeff_hash(node["internal_nonce"], node["key_context"].Q)).hex(),
            "child_partials": [partial.hex() for partial in partials],
            "partial_sum": partial_sum.hex(),
            "nonce_path": [value.hex() for value in nonce_path],
            "key_path": [[value.hex() for value in level] for level in key_path],
        })
        if node is root:
            root_session = reference.RootSessionContext(
                node["internal_nonce"], reference.key_sort([child["public_key"] for child in node["children"]]),
                tweaks, tweak_modes, message,
            )
            return reference.partial_sig_agg_root(partials, root_session)
        return partial_sum

    round_one(root)
    signature = round_two(root, [], [])
    assert reference.schnorr_verify(message, final_key, signature)
    flat = all("children" not in child for child in root["children"])
    if flat:
        sorted_keys = standard.key_sort([child["public_key"] for child in root["children"]])
        standard_session = standard.SessionContext(root["internal_nonce"], sorted_keys, tweaks, tweak_modes, message)
        standard_partials = []
        for child in root["children"]:
            standard_nonce, standard_public_nonce = standard.nonce_gen_internal(
                child["randomness"], child["secret_key"], child["public_key"], final_key, message, extra_input
            )
            assert bytes(standard_nonce) == child["secret_nonce"]
            assert standard_public_nonce == child["public_nonce"]
            partial = standard.sign(standard_nonce, child["secret_key"], standard_session)
            assert partial == child["partial"]
            standard_partials.append(partial)
        assert standard.partial_sig_agg(standard_partials, standard_session) == signature
    wrong_tweak_signature = ""
    if name == "root_tweak_final_parity":
        assert final_context.gacc == 1 and not reference.has_even_y(final_context.Q)
        challenge = int.from_bytes(reference.tagged_hash("BIP0340/challenge", signature[:32] + final_key + message), "big") % reference.n
        wrong_sum = (int.from_bytes(root["partial"], "big") + challenge * final_context.gacc * final_context.tacc) % reference.n
        wrong = signature[:32] + scalar(wrong_sum)
        assert not reference.schnorr_verify(message, final_key, wrong)
        wrong_tweak_signature = wrong.hex()
    return {
        "name": name,
        "message": message.hex(),
        "extra_input": extra_input.hex(),
        "tweaks": [{"scalar": tweak.hex(), "is_xonly": mode} for tweak, mode in zip(tweaks, tweak_modes)],
        "root_public_keys": [child["public_key"].hex() for child in root["children"]],
        "untweaked_key": root["public_key"].hex(),
        "aggregate_key": reference.cbytes(final_context.Q).hex(),
        "aggregate_xonly": final_key.hex(),
        "gacc": scalar(final_context.gacc).hex(),
        "tacc": scalar(final_context.tacc).hex(),
        "root_nonce": root["internal_nonce"].hex(),
        "signature": signature.hex(),
        "wrong_tweak_signature": wrong_tweak_signature,
        "bip327_exact": flat,
        "nodes": nodes,
        "leaves": leaves,
    }


def nonce_generation(standard):
    results = []
    secret = bytes([2]) * 32
    public = standard.individual_pk(secret)
    random = bytes([15]) * 32
    aggregate = bytes([7]) * 32
    extra = bytes([8]) * 32
    inputs = [
        ("all_optional", secret, public, aggregate, bytes([1]) * 32, extra),
        ("empty_message", secret, public, aggregate, b"", extra),
        ("long_message", secret, public, aggregate, bytes([38]) * 38, extra),
        ("no_optional", None, standard.individual_pk(scalar(3)), None, None, None),
    ]
    for name, secret, public, aggregate, message, extra in inputs:
        _, nonce = standard.nonce_gen_internal(random, secret, public, aggregate, message, extra)
        results.append({
            "name": name,
            "randomness": random.hex(),
            "secret_key": secret.hex() if secret is not None else None,
            "public_key": public.hex(),
            "aggregate_key": aggregate.hex() if aggregate is not None else None,
            "message": message.hex() if message is not None else None,
            "extra_input": extra.hex() if extra is not None else None,
            "public_nonce": nonce.hex(),
        })
    return results


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--nested-reference", type=Path, required=True)
    parser.add_argument("--bip327-reference", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=Path(__file__).with_name("conformance.json"))
    args = parser.parse_args()
    reference = load_reference("nested", args.nested_reference)
    standard = load_reference("bip327", args.bip327_reference)
    cases = [
        ("flat_empty", [3], b"", [], []),
        ("flat_32", [5, 7], bytes(range(32)), [], []),
        ("flat_one", [11, 13, 17], b"x", [], []),
        ("flat_duplicate", [19, 19, 23], b"d" * 17, [], []),
        ("flat_plain_tweak", [29, 31], b"p" * 33, [1], [False]),
        ("flat_xonly_tweak", [37, 41], b"q" * 32, [2], [True]),
        ("flat_mixed_tweaks", [43, 47], b"r" * 100, [3, 4, 5], [False, True, False]),
        ("flat_all_duplicate", [53, 53], b"s" * 32, [6, 7], [True, True]),
        ("nested_balanced", [[3, 5], [7, 11]], b"b" * 32, [], []),
        ("nested_mixed_depth_tweaks", [[7, 11], 19], b"h" * 32, [31, 37], [True, False]),
        ("nested_duplicate", [[19, 19], [23, 29]], b"n" * 17, [], []),
        ("nested_depth_three", [[[2, 3], 5], [7, 11]], b"t" * 32, [11, 13], [False, True]),
        ("nested_root_tweaks", [[31, 37], [41, 43]], b"z" * 32, [17, 19, 23], [True, False, True]),
        ("root_tweak_final_parity", [3], b"\x42" * 32, [3], [False]),
    ]
    sessions = []
    for values in cases:
        sessions.append(generate_case(reference, standard, *values))
        print(values[0], flush=True)
    generator_nonce = reference.cbytes(reference.G) + reference.cbytes(reference.point_mul(reference.G, 2))
    generator_key = reference.cbytes(reference.G)
    payload = {
        "format": 1,
        "sources": SOURCES,
        "upstream_draft_commit": "4523ee0eed72f2367a1d1774941f70b2aca5af43",
        "sessions": sessions,
        "nonce_generation": nonce_generation(standard),
        "finite_generator": {
            "aggregate_key": generator_key.hex(),
            "internal_nonce": generator_nonce.hex(),
            "external_nonce": reference.nonce_agg_ext(generator_nonce, generator_key).hex(),
        },
    }
    args.output.write_text(json.dumps(payload, indent=2) + "\n")
    print(f"Wrote {len(sessions)} sessions and {sum(len(row['leaves']) for row in sessions)} leaf signatures")


if __name__ == "__main__":
    main()
