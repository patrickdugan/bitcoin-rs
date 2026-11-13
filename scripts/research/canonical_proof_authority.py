"""CPA v0 commitment model. Research only; never fund these outputs.

Implements normalized circuit commitments, descriptor encoding, the exact
proposed locking-script template, and two-leaf P2MR commitments.
No activation logic is defined here. The demonstration body is OP_RETURN.
The separate cpa_transition module implements a bounded disclosed-trace profile.
"""
from __future__ import annotations
from dataclasses import dataclass, fields
from hashlib import sha256
import json
import struct
from typing import Mapping, Sequence


def tagged_hash(tag: str, data: bytes) -> bytes:
    t = sha256(tag.encode("ascii")).digest()
    return sha256(t + t + data).digest()


def hash32(value: bytes, name: str = "hash") -> bytes:
    if not isinstance(value, bytes) or len(value) != 32:
        raise ValueError(f"{name} must be exactly 32 bytes")
    return value


def u32(value: int) -> bytes:
    if type(value) is not int or not 0 <= value < 2**32:
        raise ValueError("value is outside uint32")
    return struct.pack("<I", value)


def compact_size(value: int) -> bytes:
    if type(value) is not int or not 0 <= value < 2**64:
        raise ValueError("value is outside uint64")
    if value < 253:
        return bytes([value])
    if value <= 65535:
        return b"\xfd" + struct.pack("<H", value)
    if value <= 2**32 - 1:
        return b"\xfe" + struct.pack("<I", value)
    return b"\xff" + struct.pack("<Q", value)


SEMANTICS = tagged_hash("CPA/v0/Semantics", b"bool-nand-dag-v0")
TXCOMMIT_KEY = b"\x02" + sha256(
    b"BIPSpace/Keyless-CHECKSIG/TXCOMMIT-draft"
).digest()


@dataclass(frozen=True)
class Program:
    program_id: bytes
    encoding: bytes
    node_count: int
    output_hashes: tuple[bytes, ...]
    records: tuple[tuple[bytes, bytes], ...]


def canonical_program(n_inputs: int, nodes: Mapping[str, tuple],
                      outputs: Sequence[str]) -> Program:
    """Normalize a finite NAND DAG, preserving external input/output order.

    Node forms: ('input', i), ('const', 0 or 1), ('nand', name1, name2).
    Names and topological serialization order are ignored; duplicate structural
    nodes are merged. Unreachable declarations and cycles are rejected.
    The small reference model limits declarations to 4096 and depth to 256.
    These are model limits, not proposed Bitcoin consensus limits.
    """
    u32(n_inputs)
    if not outputs or len(nodes) > 4096:
        raise ValueError("empty outputs or reference-model size limit")
    memo: dict[str, tuple[bytes, int]] = {}
    active: set[str] = set()
    records: dict[bytes, tuple[int, bytes]] = {}

    def visit(name: str) -> tuple[bytes, int]:
        if name in memo:
            return memo[name]
        if name in active:
            raise ValueError("cyclic circuit")
        if name not in nodes:
            raise ValueError("missing node")
        if len(active) >= 256:
            raise ValueError("reference-model depth limit")
        active.add(name)
        node = nodes[name]
        if not isinstance(node, tuple) or not node:
            raise ValueError("invalid node")
        if node[0] == "input" and len(node) == 2:
            i = node[1]
            u32(i)
            if i >= n_inputs:
                raise ValueError("input index outside declared interface")
            payload = u32(i)
            h, depth = tagged_hash("CPA/v0/Input", payload), 0
            record = b"\x00" + payload
        elif node[0] == "const" and len(node) == 2:
            if type(node[1]) is not int or node[1] not in (0, 1):
                raise ValueError("invalid constant")
            payload = bytes([node[1]])
            h, depth = tagged_hash("CPA/v0/Const", payload), 0
            record = b"\x01" + payload
        elif node[0] == "nand" and len(node) == 3:
            (a, da), (b, db) = visit(node[1]), visit(node[2])
            a, b = sorted((a, b))
            payload = a + b
            h = tagged_hash("CPA/v0/NAND", payload)
            depth = 1 + max(da, db)
            record = b"\x02" + payload
        else:
            raise ValueError("unknown opcode or malformed node")
        if h in records and records[h] != (depth, record):
            raise ValueError("inconsistent node hash")
        records[h] = (depth, record)
        memo[name] = (h, depth)
        active.remove(name)
        return h, depth

    roots = tuple(visit(name)[0] for name in outputs)
    if len(memo) != len(nodes):
        raise ValueError("unreachable declared node")
    header = b"\x00\x00" + SEMANTICS + u32(n_inputs) + compact_size(len(roots))
    root_payload = header + b"".join(roots)
    pid = tagged_hash("CPA/v0/Program", root_payload)
    ordered = sorted(records, key=lambda h: (records[h][0], h))
    encoding = root_payload + compact_size(len(ordered)) + b"".join(
        records[h][1] for h in ordered
    )
    return Program(pid, encoding, len(ordered), roots,
                   tuple((h, records[h][1]) for h in ordered))


@dataclass(frozen=True)
class Descriptor:
    network_domain: bytes
    semantics_id: bytes
    program_id: bytes
    execution_profile: bytes
    verifier_suite_id: bytes
    verifier_body_hash: bytes
    statement_abi_id: bytes
    delegation_policy_id: bytes
    resource_profile_id: bytes

    def encode(self) -> bytes:
        return b"\x00\x00" + b"".join(
            hash32(getattr(self, f.name), f.name) for f in fields(self)
        )

    @classmethod
    def decode(cls, data: bytes) -> Descriptor:
        if not isinstance(data, bytes) or len(data) != 290 or data[:2] != b"\x00\x00":
            raise ValueError("unsupported or noncanonical descriptor")
        return cls(*(data[i:i+32] for i in range(2, 290, 32)))

    def authority_id(self) -> bytes:
        return tagged_hash("CPA/v0/Authority", self.encode())


def body_hash(body: bytes) -> bytes:
    return tagged_hash("CPA/v0/VerifierBody", body)


def state_root(canonical_state_bytes: bytes) -> bytes:
    return tagged_hash("CPA/v0/State", canonical_state_bytes)


def authority_script(descriptor: Descriptor, state: bytes, body: bytes) -> bytes:
    if body_hash(body) != descriptor.verifier_body_hash:
        raise ValueError("verifier-body mismatch")
    a = descriptor.authority_id()
    s = hash32(state, "state")
    return b"\x20" + a + b"\x20" + s + body + b"\x21" + TXCOMMIT_KEY + b"\xad\x51"


def tapleaf(script: bytes) -> bytes:
    return tagged_hash("TapLeaf", b"\xc0" + compact_size(len(script)) + script)


def tapbranch(a: bytes, b: bytes) -> bytes:
    a, b = sorted((hash32(a), hash32(b)))
    return tagged_hash("TapBranch", a + b)


def output_commitment(descriptor: Descriptor, state: bytes, body: bytes) -> dict:
    script = authority_script(descriptor, state, body)
    leaf = tapleaf(script)
    sibling = tapleaf(b"\x6a")
    root = tapbranch(leaf, sibling)
    return {
        "authority_id": descriptor.authority_id().hex(),
        "state_root": state.hex(),
        "script": script.hex(),
        "tapleaf_hash": leaf.hex(),
        "sibling_hash": sibling.hex(),
        "merkle_root": root.hex(),
        "script_pubkey": (b"\x52\x20" + root).hex(),
        "control_block": (b"\xc1" + sibling).hex(),
    }


def proof_public_input(authority: bytes, state: bytes, digest: bytes) -> bytes:
    """96-byte public statement; no proof verification is performed."""
    return hash32(authority) + hash32(state) + hash32(digest)


def demo() -> dict:
    p = canonical_program(2, {
        "x": ("input", 0), "y": ("input", 1),
        "n": ("nand", "x", "y"), "and": ("nand", "n", "n"),
    }, ["and"])
    body = b"\x6a"
    def fixture(label: str) -> bytes:
        return tagged_hash("CPA/v0/TestOnly", label.encode("ascii"))
    d = Descriptor(
        fixture("isolated-research-network"), SEMANTICS, p.program_id,
        fixture("p2mr-kcs-research-profile"), fixture("always-reject-suite"),
        body_hash(body), fixture("statement-abi-96-byte-v0"),
        fixture("no-delegation-test-policy"), fixture("test-resource-profile"),
    )
    s = state_root(b"CPA test state 0")
    return {
        "warning": "Research commitments only. NO ZK verifier. NEVER FUND.",
        "program_id": p.program_id.hex(), "canonical_program": p.encoding.hex(),
        "descriptor": d.encode().hex(), "descriptor_bytes": len(d.encode()),
        "node_count": p.node_count,
        **output_commitment(d, s, body),
    }


if __name__ == "__main__":
    print(json.dumps(demo(), indent=2))
