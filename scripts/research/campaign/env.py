"""Shared regtest campaign environment: funding wallet, submission paths and
result recording."""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from decimal import Decimal
from pathlib import Path

from btc import (SIGHASH_DEFAULT, Tx, TxIn, TxOut, bech32m_address, block_bytes, schnorr_sign, taproot_sighash,
                 tweak_secret, xonly, taproot_output)
from node import Node, RpcError

WALLET_SECRET = 11
CSV_HEIGHT = 432  # this fork activates CSV at regtest height 432


def sats(value) -> int:
    return int(Decimal(str(value)) * 100_000_000)


class Wallet:
    """Key-path P2TR wallet for one test key (BIP86-style tweak, no script tree)."""

    def __init__(self, secret: int = WALLET_SECRET):
        self.secret = secret
        self.out_x, _ = taproot_output(xonly(secret), None)
        self.spk = b'\x51\x20' + self.out_x
        self.address = bech32m_address(self.out_x)
        self.tweaked = tweak_secret(secret, None)

    def sign_keypath(self, tx: Tx, index: int, spent: list, hash_type=SIGHASH_DEFAULT) -> None:
        msg = taproot_sighash(tx, index, spent, hash_type)
        sig = schnorr_sign(msg, self.tweaked)
        tx.vin[index].witness = [sig if hash_type == SIGHASH_DEFAULT else sig + bytes([hash_type])]


@dataclass
class Outcome:
    name: str
    path: str
    accepted: bool
    reason: object = None
    txid: str | None = None
    detail: dict = field(default_factory=dict)

    def as_dict(self):
        return {'name': self.name, 'path': self.path, 'accepted': self.accepted, 'reason': self.reason,
                'txid': self.txid, **self.detail}


class Env:
    def __init__(self, node: Node, wallet: Wallet | None = None):
        self.node = node
        self.wallet = wallet or Wallet()
        self.coins = []  # list of (txid, vout, value)
        self.time = None

    @property
    def rpc(self):
        return self.node.rpc

    def bootstrap(self, height: int = CSV_HEIGHT):
        blocks = self.node.mine(height - self.node.height(), self.wallet.address)
        self.refresh_coins(blocks)
        return blocks

    def refresh_coins(self, block_hashes):
        for bh in block_hashes:
            blk = self.rpc('getblock', bh, 2)
            cb = blk['tx'][0]
            for v in cb['vout']:
                if v['scriptPubKey']['hex'] == self.wallet.spk.hex():
                    self.coins.append((cb['txid'], v['n'], sats(v['value']), blk['height']))

    def take_coin(self, min_value: int = 0):
        tip = self.node.height()
        i = 0
        while i < len(self.coins):
            txid, vout, value, h = self.coins[i]
            if value < min_value:
                i += 1
                continue
            if tip + 1 - h >= 100:
                if self.rpc('gettxout', txid, vout) is not None:
                    return self.coins.pop(i)
                # stale/spent entry
                self.coins.pop(i)
                continue
            i += 1
        raise RuntimeError('no mature wallet coin')

    def funding_tx(self, outputs: list, fee: int = 3000) -> Tx:
        total = sum(v for v, _ in outputs)
        txid, vout, value, _ = self.take_coin(total + fee + 1000)
        change = value - total - fee
        outs = [TxOut(v, s) for v, s in outputs] + [TxOut(change, self.wallet.spk)]
        tx = Tx([TxIn(txid, vout, b'', 0xffffffff)], outs)
        self.wallet.sign_keypath(tx, 0, [(value, self.wallet.spk)])
        # Non-coinbase change output is immediately spendable once confirmed/in-mempool
        self.coins.insert(0, (tx.txid(), len(outputs), change, -200))
        return tx

    def fund(self, outputs: list, confirm: bool = True) -> Tx:
        tx = self.funding_tx(outputs)
        assert self.rpc('sendrawtransaction', tx.hex()) == tx.txid()
        if confirm:
            self.mine(1)
        return tx

    def mine(self, n=1):
        return self.node.mine(n, self.wallet.address)

    # ------------------------------------------------------------- submission paths
    def try_mempool(self, name: str, tx: Tx, expect: bool | None = None) -> Outcome:
        dry = self.rpc('testmempoolaccept', [tx.hex()])[0]
        ok, res = self.node.try_rpc('sendrawtransaction', tx.hex())
        reason = None if ok else res
        retained = None
        if ok:
            # Core-compatible RPC: an existing txid returns success even when the submitted
            # witness differs. Treat that as a rejection of *this* witness.
            entry_ok, entry = self.node.try_rpc('getmempoolentry', tx.txid())
            if entry_ok and entry.get('wtxid') not in (None, tx.wtxid()):
                ok = False
                retained = entry.get('wtxid')
                reason = {'message': 'same txid already in mempool with a different witness; submission ignored',
                          'retained_wtxid': retained}
        out = Outcome(name, 'mempool', ok, reason, tx.txid(), {'testmempoolaccept': dry, 'wtxid': tx.wtxid(),
                                                             'hex': tx.hex(), 'weight': tx.weight()})
        if dry.get('allowed') != ok:
            out.detail['dry_run_disagreement'] = True
        if expect is not None:
            assert ok == expect, (name, out.as_dict())
        return out

    def try_block(self, name: str, txs: list, expect: bool | None = None) -> Outcome:
        """Block-validation path: mine a block containing exactly txs via generateblock."""
        before = self.node.height()
        ok, res = self.node.try_rpc('generateblock', self.wallet.address, [t.hex() for t in txs])
        after = self.node.height()
        out = Outcome(name, 'block', ok and after == before + 1, None if ok else res,
                      txs[-1].txid() if txs else None, {'height_before': before, 'height_after': after,
                                                         'hex': [t.hex() for t in txs]})
        if ok:
            out.detail['block'] = res['hash'] if isinstance(res, dict) else res
        if expect is not None:
            assert out.accepted == expect, (name, out.as_dict())
        return out

    def try_submitblock(self, name: str, txs: list, prev: str | None = None, time_: int | None = None,
                        height: int | None = None, expect: bool | None = None, fees: int = 0) -> Outcome:
        """Raw block path built locally (independent of the node's block assembler)."""
        if prev is None:
            prev = self.node.tip()
        hdr = self.rpc('getblockheader', prev)
        if height is None:
            height = hdr['height'] + 1
        if time_ is None:
            time_ = max(hdr['time'] + 1, hdr.get('mediantime', hdr['time']) + 1)
        raw, bh = block_bytes(prev, height, txs, time_, self.wallet.spk, fees=fees)
        ok, res = self.node.try_rpc('submitblock', raw.hex())
        accepted = ok and res is None
        tip_moved = self.node.tip() == bh
        out = Outcome(name, 'submitblock', accepted, res, bh, {'tip_is_block': tip_moved, 'height': height,
                                                              'block_hex_len': len(raw)})
        if expect is not None:
            assert accepted == expect, (name, out.as_dict())
        return out


def write_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=False, default=str) + '\n')
