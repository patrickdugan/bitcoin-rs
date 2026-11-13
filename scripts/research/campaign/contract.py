"""The funded arithmetic-claim contract from muladdmod_dispute_rpc.py, rebuilt
with raw-byte overrides so admission checks can be bypassed for adversarial
fixtures. The leaf bytes are byte-identical to the reference fixture when no
override is used (checked by test_campaign_contract.py).
"""
from __future__ import annotations

from dataclasses import dataclass, field

from btc import (NUMS_X, SIGHASH_DEFAULT, TapTree, Tx, TxIn, TxOut, push, schnorr_sign, script_num, sha,
                 tapleaf_hash, taproot_sighash, xonly)

RECOVERY_SECRET = 3
OPERATOR_SECRET = 5
OP_MULADDMOD = 0xf0


def le(value: int, width: int) -> bytes:
    return value.to_bytes(width, 'little')


def width_of(modulus: int) -> int:
    return (modulus.bit_length() + 7) // 8


@dataclass
class Claim:
    instance: bytes
    a: int
    b: int
    c: int
    claimed: int
    modulus: int
    delay: int = 6
    recovery_secret: int = RECOVERY_SECRET
    operator_secret: int = OPERATOR_SECRET
    # raw overrides (bypass admission): bytes committed by SHA256 / pushed as modulus
    raw_values: list | None = None
    raw_modulus: bytes | None = None
    internal_x: bytes = NUMS_X
    extra_leaves: list = field(default_factory=list)

    def values(self) -> list:
        if self.raw_values is not None:
            return list(self.raw_values)
        w = width_of(self.modulus)
        return [le(v, w) for v in (self.a, self.b, self.c, self.claimed)]

    def modulus_bytes(self) -> bytes:
        return self.raw_modulus if self.raw_modulus is not None else le(self.modulus, width_of(self.modulus))

    def script(self) -> bytes:
        vals = self.values()
        s = push(self.instance) + b'\x75\x63' + push(xonly(self.recovery_secret)) + b'\xad'
        for v in reversed(vals[1:]):
            s += b'\x76\xa8' + push(sha(v)) + b'\x88\x6b'
        s += b'\x76\xa8' + push(sha(vals[0])) + b'\x88'
        s += b'\x6c\x6c' + push(self.modulus_bytes()) + bytes([OP_MULADDMOD]) + b'\x6c\x87\x91\x67'
        s += push(script_num(self.delay)) + b'\xb2\x75'
        s += push(xonly(self.operator_secret)) + b'\xac\x68'
        return s

    def tree(self) -> TapTree:
        return TapTree(self.internal_x, [(self.script(), 0xc0)] + list(self.extra_leaves))

    def spk(self) -> bytes:
        return self.tree().spk()

    def leaf_hash(self) -> bytes:
        return tapleaf_hash(self.script())

    def honest(self) -> bool:
        return (self.a * self.b + self.c) % self.modulus == self.claimed


def p2tr_key_spk(secret: int) -> bytes:
    return b'\x51\x20' + xonly(secret)


def spend_claim(claim: Claim, txid: str, vout: int, amount: int, recover: bool, fee: int = 2000,
                outputs: list | None = None, sequence: int | None = None, version: int = 2,
                locktime: int = 0, hash_type: int = SIGHASH_DEFAULT, signer: int | None = None,
                sign_leaf: bytes | None = None, annex: bytes | None = None, values: list | None = None,
                selector: bytes | None = None, extra_inputs: list | None = None,
                spent_override: list | None = None) -> Tx:
    """Construct a recovery (recover=True) or settlement transaction."""
    secret = signer if signer is not None else (claim.recovery_secret if recover else claim.operator_secret)
    if outputs is None:
        payee = claim.recovery_secret if recover else claim.operator_secret
        outputs = [TxOut(amount - fee, p2tr_key_spk(payee))]
    if sequence is None:
        sequence = 0xffffffff if recover else claim.delay
    vin = [TxIn(txid, vout, b'', sequence)]
    spent = [(amount, claim.spk())]
    for (etxid, evout, eamount, espk, eseq) in (extra_inputs or []):
        vin.append(TxIn(etxid, evout, b'', eseq))
        spent.append((eamount, espk))
    tx = Tx(vin, outputs, version, locktime)
    leaf = sign_leaf if sign_leaf is not None else claim.leaf_hash()
    msg = taproot_sighash(tx, 0, spent_override or spent, hash_type, leaf_hash=leaf, annex=annex)
    sig = schnorr_sign(msg, secret)
    if hash_type != SIGHASH_DEFAULT:
        sig += bytes([hash_type])
    if recover:
        stack = list(values if values is not None else claim.values()) + [sig, b'\x01' if selector is None else selector]
    else:
        stack = [sig, b'' if selector is None else selector]
    tree = claim.tree()
    tx.vin[0].witness = stack + [claim.script(), tree.control(0)] + ([annex] if annex is not None else [])
    return tx
