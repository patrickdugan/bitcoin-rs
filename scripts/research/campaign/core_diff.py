#!/usr/bin/env python3
"""Phase 3: live consensus and mempool differential testing between experimental
bitcoin-rs (with OP_MULADDMOD active on regtest) and Bitcoin Core 31.1 across
ordinary Bitcoin transactions (Legacy, P2PKH, P2SH, SegWit v0 P2WPKH/P2WSH,
Taproot key-path, and non-0xf0 Taproot script-path including adjacent
OP_SUCCESS239/OP_SUCCESS241, CHECKSIGADD, CSV/CLTV, MINIMALIF, stack limits,
and validation-weight budgets).

Usage: core_diff.py --exp <bitcoin-rs-exp> --core <bitcoind> [--off <bitcoin-rs-off>] --out <dir>
"""
from __future__ import annotations

import argparse
import tempfile
import time
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))

from btc import (
    NUMS_X, SIGHASH_ALL, SIGHASH_DEFAULT, TapTree, Tx, TxIn, TxOut,
    bip143_sighash, block_bytes, compressed_pubkey, ecdsa_sign, hash160,
    legacy_sighash, push, push_int, schnorr_sign, sha, tapleaf_hash,
    taproot_output, taproot_sighash, tweak_secret, xonly,
)
from env import Env, write_json
from node import Node
import refinterp

SK1, SK2, SK3 = 21, 22, 23
PK1, PK2, PK3 = compressed_pubkey(SK1), compressed_pubkey(SK2), compressed_pubkey(SK3)
X1, X2, X3 = xonly(SK1), xonly(SK2), xonly(SK3)
OUT_SPK = b'\x00\x14' + bytes([0x42]) * 20
FUND_VAL = 50_000
SPEND_VAL = 48_000


def non_der_ecdsa(sig_der: bytes) -> bytes:
    """Insert a non-minimal leading 0x00 into r so strict DER fails (BIP66)."""
    assert sig_der[0] == 0x30 and sig_der[2] == 0x02
    r_len = sig_der[3]
    r_bytes = sig_der[4:4 + r_len]
    rest = sig_der[4 + r_len:]
    body = b'\x02' + bytes([r_len + 1]) + b'\x00' + r_bytes + rest
    return b'\x30' + bytes([len(body)]) + body


def build_cases():
    """Returns a list of case dicts. First pass defines each prevout spk;
    second pass (after funding txid is known) constructs the spending Tx."""
    specs = []

    def add(name, family, spk, make_tx, expect_block, expect_mempool=None):
        specs.append({
            'name': name,
            'family': family,
            'spk': spk,
            'make_tx': make_tx,
            'expect_block': expect_block,
            'expect_mempool': expect_block if expect_mempool is None else expect_mempool,
        })

    # --------------------------------------------------------- 1. Legacy P2PKH
    p2pkh_spk = b'\x76\xa9\x14' + hash160(PK1) + b'\x88\xac'

    def p2pkh_spend(txid, vout, mode):
        tx = Tx([TxIn(txid, vout, b'', 0xffffffff)], [TxOut(SPEND_VAL, OUT_SPK)])
        sigh = legacy_sighash(tx, 0, p2pkh_spk, SIGHASH_ALL)
        sig = ecdsa_sign(sigh, SK1)
        if mode == 'valid':
            ss = push(sig + b'\x01') + push(PK1)
        elif mode == 'bad_sig':
            bad = sig[:-1] + bytes([sig[-1] ^ 1])
            ss = push(bad + b'\x01') + push(PK1)
        elif mode == 'wrong_pk':
            ss = push(sig + b'\x01') + push(PK2)
        elif mode == 'non_der':
            ss = push(non_der_ecdsa(sig) + b'\x01') + push(PK1)
        else:
            raise ValueError(mode)
        tx.vin[0].script_sig = ss
        return tx

    add('legacy_p2pkh_valid', 'legacy', p2pkh_spk, lambda t, v: p2pkh_spend(t, v, 'valid'), True)
    add('legacy_p2pkh_bad_sig', 'legacy', p2pkh_spk, lambda t, v: p2pkh_spend(t, v, 'bad_sig'), False)
    add('legacy_p2pkh_wrong_pubkey', 'legacy', p2pkh_spk, lambda t, v: p2pkh_spend(t, v, 'wrong_pk'), False)
    add('legacy_p2pkh_non_der_bip66', 'legacy', p2pkh_spk, lambda t, v: p2pkh_spend(t, v, 'non_der'), False)

    # --------------------------------------------------------- 2. Legacy P2SH
    ms_redeem = b'\x52' + push(PK1) + push(PK2) + b'\x52\xae'
    ms_spk = b'\xa9\x14' + hash160(ms_redeem) + b'\x87'

    def p2sh_ms(txid, vout, dummy):
        tx = Tx([TxIn(txid, vout, b'', 0xffffffff)], [TxOut(SPEND_VAL, OUT_SPK)])
        sigh = legacy_sighash(tx, 0, ms_redeem, SIGHASH_ALL)
        s1 = ecdsa_sign(sigh, SK1) + b'\x01'
        s2 = ecdsa_sign(sigh, SK2) + b'\x01'
        tx.vin[0].script_sig = dummy + push(s1) + push(s2) + push(ms_redeem)
        return tx

    add('p2sh_2of2_multisig_valid', 'p2sh', ms_spk, lambda t, v: p2sh_ms(t, v, b'\x00'), True)
    add('p2sh_2of2_nulldummy_reject', 'p2sh', ms_spk, lambda t, v: p2sh_ms(t, v, b'\x51'), False)

    for label, lt, tx_lt, seq, ok in [
        ('p2sh_cltv_mature', 1300, 1300, 0xfffffffe, True),
        ('p2sh_cltv_unsatisfied', 1900, 1300, 0xfffffffe, False),
        ('p2sh_cltv_final_seq_reject', 1300, 1300, 0xffffffff, False),
    ]:
        redeem = push_int(lt) + b'\xb1\x75' + push(PK1) + b'\xac'
        spk = b'\xa9\x14' + hash160(redeem) + b'\x87'

        def mk_cltv(txid, vout, r=redeem, tl=tx_lt, sq=seq):
            tx = Tx([TxIn(txid, vout, b'', sq)], [TxOut(SPEND_VAL, OUT_SPK)], version=2, locktime=tl)
            s = ecdsa_sign(legacy_sighash(tx, 0, r, SIGHASH_ALL), SK1) + b'\x01'
            tx.vin[0].script_sig = push(s) + push(r)
            return tx

        add(label, 'p2sh', spk, mk_cltv, ok)

    for label, delay, seq, ok in [
        ('p2sh_csv_mature', 2, 2, True),
        ('p2sh_csv_script_unsatisfied', 200, 2, False),
        ('p2sh_csv_bip68_premature', 2, 200, False),
    ]:
        redeem = push_int(delay) + b'\xb2\x75' + push(PK1) + b'\xac'
        spk = b'\xa9\x14' + hash160(redeem) + b'\x87'

        def mk_csv(txid, vout, r=redeem, sq=seq):
            tx = Tx([TxIn(txid, vout, b'', sq)], [TxOut(SPEND_VAL, OUT_SPK)], version=2)
            s = ecdsa_sign(legacy_sighash(tx, 0, r, SIGHASH_ALL), SK1) + b'\x01'
            tx.vin[0].script_sig = push(s) + push(r)
            return tx

        add(label, 'p2sh', spk, mk_csv, ok)

    for label, branch_op, ok in [
        ('p2sh_0xf0_skipped_branch_valid', b'\x00', True),
        ('p2sh_0xf0_executed_bad_opcode', b'\x51', False),
    ]:
        redeem = branch_op + b'\x63\xf0\x68' + push(PK1) + b'\xac'
        spk = b'\xa9\x14' + hash160(redeem) + b'\x87'

        def mk_0xf0_p2sh(txid, vout, r=redeem):
            tx = Tx([TxIn(txid, vout, b'', 0xffffffff)], [TxOut(SPEND_VAL, OUT_SPK)])
            s = ecdsa_sign(legacy_sighash(tx, 0, r, SIGHASH_ALL), SK1) + b'\x01'
            tx.vin[0].script_sig = push(s) + push(r)
            return tx

        add(label, 'p2sh', spk, mk_0xf0_p2sh, ok)

    # --------------------------------------------------------- 3. SegWit v0
    wpkh_spk = b'\x00\x14' + hash160(PK1)
    wpkh_code = b'\x76\xa9\x14' + hash160(PK1) + b'\x88\xac'

    def p2wpkh_spend(txid, vout, mode):
        ss = b'\x00' if mode == 'malleated_scriptsig' else b''
        tx = Tx([TxIn(txid, vout, ss, 0xffffffff)], [TxOut(SPEND_VAL, OUT_SPK)])
        sig = ecdsa_sign(bip143_sighash(tx, 0, wpkh_code, FUND_VAL, SIGHASH_ALL), SK1) + b'\x01'
        if mode == 'nullfail':
            sig = bytes([sig[0]]) + sig[1:-2] + bytes([sig[-2] ^ 1]) + sig[-1:]
        tx.vin[0].witness = [sig, PK1]
        return tx

    add('segwit_v0_p2wpkh_valid', 'segwit_v0', wpkh_spk, lambda t, v: p2wpkh_spend(t, v, 'valid'), True)
    add('segwit_v0_p2wpkh_nullfail', 'segwit_v0', wpkh_spk, lambda t, v: p2wpkh_spend(t, v, 'nullfail'), False)
    add('segwit_v0_p2wpkh_scriptsig_malleated', 'segwit_v0', wpkh_spk,
        lambda t, v: p2wpkh_spend(t, v, 'malleated_scriptsig'), False)

    preimage = b'ordinary-bitcoin-witness-v0-preimage'
    wsh_hash_script = b'\xa8' + push(sha(preimage)) + b'\x88' + push(PK1) + b'\xac'
    wsh_hash_spk = b'\x00\x20' + sha(wsh_hash_script)

    def p2wsh_hash(txid, vout, pre):
        tx = Tx([TxIn(txid, vout, b'', 0xffffffff)], [TxOut(SPEND_VAL, OUT_SPK)])
        sig = ecdsa_sign(bip143_sighash(tx, 0, wsh_hash_script, FUND_VAL, SIGHASH_ALL), SK1) + b'\x01'
        tx.vin[0].witness = [sig, pre, wsh_hash_script]
        return tx

    add('segwit_v0_p2wsh_sha256_valid', 'segwit_v0', wsh_hash_spk, lambda t, v: p2wsh_hash(t, v, preimage), True)
    add('segwit_v0_p2wsh_sha256_wrong', 'segwit_v0', wsh_hash_spk, lambda t, v: p2wsh_hash(t, v, b'wrong'), False)

    wsh_if_script = b'\x63' + push(PK1) + b'\xac\x68'
    wsh_if_spk = b'\x00\x20' + sha(wsh_if_script)

    def p2wsh_if(txid, vout, sel):
        tx = Tx([TxIn(txid, vout, b'', 0xffffffff)], [TxOut(SPEND_VAL, OUT_SPK)])
        sig = ecdsa_sign(bip143_sighash(tx, 0, wsh_if_script, FUND_VAL, SIGHASH_ALL), SK1) + b'\x01'
        tx.vin[0].witness = [sig, sel, wsh_if_script]
        return tx

    add('segwit_v0_p2wsh_if_minimal_valid', 'segwit_v0', wsh_if_spk, lambda t, v: p2wsh_if(t, v, b'\x01'), True)
    # In SegWit v0, MINIMALIF is policy-only (mempool rejects, consensus block accepts)
    add('segwit_v0_p2wsh_nonminimal_if_policy_only', 'segwit_v0', wsh_if_spk,
        lambda t, v: p2wsh_if(t, v, b'\x02'), True, expect_mempool=False)

    for label, branch_op, ok in [
        ('segwit_v0_p2wsh_0xf0_skipped_valid', b'\x00', True),
        ('segwit_v0_p2wsh_0xf0_executed_bad_opcode', b'\x51', False),
    ]:
        ws = branch_op + b'\x63\xf0\x68' + push(PK1) + b'\xac'
        spk = b'\x00\x20' + sha(ws)

        def mk_0xf0_wsh(txid, vout, s=ws):
            tx = Tx([TxIn(txid, vout, b'', 0xffffffff)], [TxOut(SPEND_VAL, OUT_SPK)])
            sig = ecdsa_sign(bip143_sighash(tx, 0, s, FUND_VAL, SIGHASH_ALL), SK1) + b'\x01'
            tx.vin[0].witness = [sig, s]
            return tx

        add(label, 'segwit_v0', spk, mk_0xf0_wsh, ok)

    # --------------------------------------------------------- 4. Taproot key-path
    kp_out_x, _ = taproot_output(X1, None)
    kp_spk = b'\x51\x20' + kp_out_x
    kp_tweaked = tweak_secret(SK1, None)

    def tr_keypath(txid, vout, mode):
        tx = Tx([TxIn(txid, vout, b'', 0xffffffff)], [TxOut(SPEND_VAL, OUT_SPK)])
        spent = [(FUND_VAL, kp_spk)]
        if mode == 'default':
            sig = schnorr_sign(taproot_sighash(tx, 0, spent, SIGHASH_DEFAULT), kp_tweaked)
            tx.vin[0].witness = [sig]
        elif mode == 'sighash_all':
            sig = schnorr_sign(taproot_sighash(tx, 0, spent, SIGHASH_ALL), kp_tweaked) + b'\x01'
            tx.vin[0].witness = [sig]
        elif mode == 'explicit_zero_hashtype':
            sig = schnorr_sign(taproot_sighash(tx, 0, spent, SIGHASH_DEFAULT), kp_tweaked) + b'\x00'
            tx.vin[0].witness = [sig]
        elif mode == 'invalid_hashtype_0x04':
            sig = schnorr_sign(taproot_sighash(tx, 0, spent, SIGHASH_DEFAULT), kp_tweaked) + b'\x04'
            tx.vin[0].witness = [sig]
        elif mode == 'bad_sig':
            sig = schnorr_sign(taproot_sighash(tx, 0, spent, SIGHASH_DEFAULT), kp_tweaked)
            tx.vin[0].witness = [bytes([sig[0] ^ 1]) + sig[1:]]
        return tx

    add('taproot_keypath_default_valid', 'taproot_keypath', kp_spk, lambda t, v: tr_keypath(t, v, 'default'), True)
    add('taproot_keypath_sighash_all_valid', 'taproot_keypath', kp_spk, lambda t, v: tr_keypath(t, v, 'sighash_all'), True)
    add('taproot_keypath_explicit_0x00_reject', 'taproot_keypath', kp_spk,
        lambda t, v: tr_keypath(t, v, 'explicit_zero_hashtype'), False)
    add('taproot_keypath_hashtype_0x04_reject', 'taproot_keypath', kp_spk,
        lambda t, v: tr_keypath(t, v, 'invalid_hashtype_0x04'), False)
    add('taproot_keypath_bad_schnorr_reject', 'taproot_keypath', kp_spk, lambda t, v: tr_keypath(t, v, 'bad_sig'), False)

    # --------------------------------------------------------- 5. Taproot script-path (non-0xf0)
    def add_tapscript(name, leaf, make_wit, expect_block, expect_mempool=None, seq=0xffffffff, locktime=0):
        tree = TapTree(NUMS_X, [(leaf, 0xc0)])
        spk = tree.spk()
        ctrl = tree.control(0)

        def mk(txid, vout):
            tx = Tx([TxIn(txid, vout, b'', seq)], [TxOut(SPEND_VAL, OUT_SPK)], version=2, locktime=locktime)
            spent = [(FUND_VAL, spk)]
            wit, annex = make_wit(tx, spent, tapleaf_hash(leaf))
            tx.vin[0].witness = [*wit, leaf, ctrl] + ([annex] if annex else [])
            return tx

        add(name, 'tapscript', spk, mk, expect_block, expect_mempool)

    cs_leaf = push(X1) + b'\xac'
    add_tapscript('tapscript_checksig_valid', cs_leaf,
                  lambda tx, sp, lh: ([schnorr_sign(taproot_sighash(tx, 0, sp, leaf_hash=lh), SK1)], None), True)
    add_tapscript('tapscript_checksig_empty_eval_false', cs_leaf,
                  lambda tx, sp, lh: ([b''], None), False)

    cs_not_leaf = push(X1) + b'\xac\x91'  # <X1> CHECKSIG NOT: empty sig -> TRUE; bad non-empty sig -> abort!
    add_tapscript('tapscript_checksig_empty_not_valid', cs_not_leaf,
                  lambda tx, sp, lh: ([b''], None), True)
    add_tapscript('tapscript_checksig_bad_sig_aborts_before_not', cs_not_leaf,
                  lambda tx, sp, lh: ([b'\x11' * 64], None), False)

    csa_leaf = push(X1) + b'\xac' + push(X2) + b'\xba' + push(X3) + b'\xba\x52\x9c'
    add_tapscript(
        'tapscript_checksigadd_2of3_valid', csa_leaf,
        lambda tx, sp, lh: ([
            b'',
            schnorr_sign(taproot_sighash(tx, 0, sp, leaf_hash=lh), SK2),
            schnorr_sign(taproot_sighash(tx, 0, sp, leaf_hash=lh), SK1),
        ], None),
        True,
    )
    add_tapscript(
        'tapscript_checksigadd_1of3_reject', csa_leaf,
        lambda tx, sp, lh: ([
            b'',
            b'',
            schnorr_sign(taproot_sighash(tx, 0, sp, leaf_hash=lh), SK1),
        ], None),
        False,
    )

    add_tapscript('tapscript_csv_mature', push_int(2) + b'\xb2\x75' + push(X1) + b'\xac',
                  lambda tx, sp, lh: ([schnorr_sign(taproot_sighash(tx, 0, sp, leaf_hash=lh), SK1)], None),
                  True, seq=2)
    add_tapscript('tapscript_csv_unsatisfied', push_int(200) + b'\xb2\x75' + push(X1) + b'\xac',
                  lambda tx, sp, lh: ([schnorr_sign(taproot_sighash(tx, 0, sp, leaf_hash=lh), SK1)], None),
                  False, seq=2)
    add_tapscript('tapscript_cltv_mature', push_int(1300) + b'\xb1\x75' + push(X1) + b'\xac',
                  lambda tx, sp, lh: ([schnorr_sign(taproot_sighash(tx, 0, sp, leaf_hash=lh), SK1)], None),
                  True, seq=0xfffffffe, locktime=1300)
    add_tapscript('tapscript_cltv_unsatisfied', push_int(1900) + b'\xb1\x75' + push(X1) + b'\xac',
                  lambda tx, sp, lh: ([schnorr_sign(taproot_sighash(tx, 0, sp, leaf_hash=lh), SK1)], None),
                  False, seq=0xfffffffe, locktime=1300)

    h_pre = b'tapscript-hash-gadget'
    hash_leaf = b'\x76\xa8' + push(sha(h_pre)) + b'\x88\xa9' + push(hash160(h_pre)) + b'\x87'
    add_tapscript('tapscript_sha256_hash160_valid', hash_leaf, lambda tx, sp, lh: ([h_pre], None), True)
    add_tapscript('tapscript_sha256_hash160_wrong', hash_leaf, lambda tx, sp, lh: ([b'nope'], None), False)

    # In Tapscript, MINIMALIF is a consensus rule (unlike SegWit v0!)
    add_tapscript('tapscript_minimalif_consensus_reject', b'\x63\x51\x68',
                  lambda tx, sp, lh: ([b'\x02'], None), False)
    # Disabled legacy multisig opcode in Tapscript
    add_tapscript('tapscript_checkmultisig_disabled_reject', b'\x00\x00\xae',
                  lambda tx, sp, lh: ([], None), False)
    # Cleanstack is consensus in Tapscript
    add_tapscript('tapscript_cleanstack_consensus_reject', b'\x51\x51',
                  lambda tx, sp, lh: ([], None), False)

    # Adjacent OP_SUCCESSx opcodes (0x50, 0xef, 0xf1) must retain early-success bypass in consensus
    # and DISCOURAGE_OP_SUCCESS rejection in mempool even when 0xf0 is activated!
    add_tapscript('tapscript_op_success80_1001_stack_bypass', b'\x50',
                  lambda tx, sp, lh: ([b''] * 1001, None), True, expect_mempool=False)
    add_tapscript('tapscript_op_success239_adjacent_low', b'\xef\x4c',
                  lambda tx, sp, lh: ([], None), True, expect_mempool=False)
    add_tapscript('tapscript_op_success241_adjacent_high_521b', b'\xf1\x4c',
                  lambda tx, sp, lh: ([b'\xaa' * 521], None), True, expect_mempool=False)

    # Stack limit without OP_SUCCESSx: 1000 initial witness stack elements ok, 1001 rejected
    # Note: Bitcoin Core standardness caps tapscript witness stack item count (<1000), so mempool may differ from block;
    # we check exact Core==bitcoin-rs agreement on block consensus and record mempool verdicts.
    stack1000_leaf = b'\x6d' * 500 + b'\x51'  # 500 x 2DROP consumes 1000 items, then OP_1
    add_tapscript('tapscript_initial_stack_1000_valid', stack1000_leaf,
                  lambda tx, sp, lh: ([b''] * 1000, None), True, expect_mempool=None)
    stack1001_leaf = b'\x75' + b'\x6d' * 500 + b'\x51'
    add_tapscript('tapscript_initial_stack_1001_reject', stack1001_leaf,
                  lambda tx, sp, lh: ([b''] * 1001, None), False)

    # Tapscript validation weight budget boundary with 6 x (2DUP CHECKSIGVERIFY) => 300 units needed => witness_size >= 250
    k_sig = 6
    budget_leaf = b'\x6e\xad' * k_sig + b'\x6d\x51'
    budget_tree = TapTree(NUMS_X, [(budget_leaf, 0xc0)])
    base_items = [b'S' * 64, X1, budget_leaf, budget_tree.control(0)]
    base_wsize = refinterp.witness_size(base_items)

    def annex_for_total_wsize(target_wsize):
        need = target_wsize - base_wsize
        for L in range(max(1, need - 4), need + 3):
            cand = b'\x50' + bytes(L - 1)
            if refinterp.witness_size([*base_items, cand]) == target_wsize:
                return cand
        raise RuntimeError(f'cannot hit target_wsize={target_wsize} from {base_wsize}')

    annex_exact = annex_for_total_wsize(50 * k_sig - 50)      # budget = 50 + 250 = 300 == 300
    annex_short = annex_for_total_wsize(50 * k_sig - 50 - 1)  # budget = 50 + 249 = 299 < 300

    add_tapscript(
        'tapscript_sig_budget_exact_valid', budget_leaf,
        lambda tx, sp, lh: ([schnorr_sign(taproot_sighash(tx, 0, sp, leaf_hash=lh, annex=annex_exact), SK1), X1], annex_exact),
        True, expect_mempool=False,  # annex is non-standard in mempool policy!
    )
    add_tapscript(
        'tapscript_sig_budget_minus1_reject', budget_leaf,
        lambda tx, sp, lh: ([schnorr_sign(taproot_sighash(tx, 0, sp, leaf_hash=lh, annex=annex_short), SK1), X1], annex_short),
        False,
    )

    return specs


def run(exp_bin: Path, core_bin: Path, off_bin: Path | None, out: Path):
    out.mkdir(parents=True, exist_ok=True)
    specs = build_cases()
    t0 = time.time()
    with tempfile.TemporaryDirectory(prefix='muladdmod-corediff-') as tmp:
        root = Path(tmp)
        nodes = {
            'rs_exp': Node(exp_bin, root, 'rs_exp', 'bitcoin-rs'),
            'core': Node(core_bin, root, 'core', 'core'),
        }
        if off_bin:
            nodes['rs_off'] = Node(off_bin, root, 'rs_off', 'bitcoin-rs')
        try:
            for n in nodes.values():
                n.start()
            # Connect all nodes to rs_exp to sync bootstrap + funding chain
            for k, n in nodes.items():
                if k != 'rs_exp':
                    nodes['rs_exp'].rpc('addnode', f'127.0.0.1:{n.p2p_port}', 'onetry')
            nodes['rs_exp'].wait_for(lambda: len(nodes['rs_exp'].rpc('getpeerinfo')) >= len(nodes) - 1,
                                     what='peer handshake')

            env = Env(nodes['rs_exp'])
            # Bootstrap past bitcoin-rs regtest buried activation heights (BIP34=500, BIP66=1251, BIP65=1351, CSV=432)
            env.bootstrap(1360)
            fund = env.funding_tx([(FUND_VAL, s['spk']) for s in specs], fee=10_000)
            nodes['rs_exp'].rpc('generateblock', env.wallet.address, [fund.hex()])
            env.mine(2)  # height 438: CSV(2) mature on all funded outputs
            base_tip = nodes['rs_exp'].tip()
            for n in nodes.values():
                n.wait_for(lambda n=n: n.tip() == base_tip, what='sync funding tip')

            # Disconnect peers so every node validates independently!
            for n in nodes.values():
                for p in n.rpc('getpeerinfo'):
                    addr = p.get('addr', '')
                    if addr:
                        n.try_rpc('disconnectnode', addr)
            time.sleep(0.5)

            txs = [s['make_tx'](fund.txid(), i) for i, s in enumerate(specs)]

            # 1) Dry-run mempool check across all nodes (does not mutate mempool or chain)
            mempool_rows = {}
            for k, n in nodes.items():
                mempool_rows[k] = [n.rpc('testmempoolaccept', [tx.hex()])[0] for tx in txs]

            # 2) Independent raw submitblock across all nodes
            results = []
            consensus_mismatches = []
            mempool_differences = []
            for i, (s, tx) in enumerate(zip(specs, txs)):
                prev = nodes['rs_exp'].tip()
                hdr = nodes['rs_exp'].rpc('getblockheader', prev)
                height = hdr['height'] + 1
                ntime = max(hdr['time'] + 1, hdr.get('mediantime', hdr['time']) + 1)
                raw_blk, bh = block_bytes(prev, height, [tx], ntime, env.wallet.spk, fees=FUND_VAL - SPEND_VAL)

                block_verdicts = {}
                block_reasons = {}
                for k, n in nodes.items():
                    assert n.tip() == prev, f'{k} tip diverged before {s["name"]}'
                    ok, res = n.try_rpc('submitblock', raw_blk.hex())
                    accepted = ok and res is None and n.tip() == bh
                    block_verdicts[k] = accepted
                    block_reasons[k] = res

                mp_verdicts = {k: bool(mempool_rows[k][i].get('allowed')) for k in nodes}
                mp_reasons = {k: mempool_rows[k][i].get('reject-reason') for k in nodes}

                row = {
                    'name': s['name'],
                    'family': s['family'],
                    'expect_block': s['expect_block'],
                    'block_verdicts': block_verdicts,
                    'block_reasons': block_reasons,
                    'mempool_verdicts': mp_verdicts,
                    'mempool_reasons': mp_reasons,
                    'txid': tx.txid(),
                }
                results.append(row)

                if len(set(block_verdicts.values())) != 1 or block_verdicts['core'] != s['expect_block']:
                    consensus_mismatches.append(row)
                if len(set(mp_verdicts.values())) != 1:
                    mempool_differences.append(row)

            final_tips = {k: n.tip() for k, n in nodes.items()}
        finally:
            for n in nodes.values():
                n.stop()

    summary = {
        'cases': len(results),
        'by_family': {f: sum(1 for r in results if r['family'] == f)
                      for f in sorted({r['family'] for r in results})},
        'block_accepted': sum(1 for r in results if r['block_verdicts']['core']),
        'block_rejected': sum(1 for r in results if not r['block_verdicts']['core']),
        'consensus_mismatches_vs_core': len(consensus_mismatches),
        'all_final_tips_identical': len(set(final_tips.values())) == 1,
        'final_tips': final_tips,
        'mempool_policy_differences_vs_core': len(mempool_differences),
        'elapsed_s': round(time.time() - t0, 2),
    }
    write_json(out / 'phase3-core-differential.json', {
        'summary': summary,
        'consensus_mismatches': consensus_mismatches,
        'mempool_policy_differences': mempool_differences,
        'results': results,
    })
    print(summary)
    if consensus_mismatches:
        raise SystemExit(f'CONSENSUS MISMATCHES: {consensus_mismatches}')


if __name__ == '__main__':
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--exp', type=Path, required=True)
    ap.add_argument('--core', type=Path, required=True)
    ap.add_argument('--off', type=Path)
    ap.add_argument('--out', type=Path, required=True)
    a = ap.parse_args()
    run(a.exp, a.core, a.off, a.out)
