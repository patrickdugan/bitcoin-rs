#!/usr/bin/env python3
"""Phase 2: adversarial transactions against the funded arithmetic-claim
contract, submitted through the native node's mempool and block-validation
paths on an isolated regtest network.

Every attempt records: the transaction (hex, txid, wtxid), the path used,
the node verdict and reject reason, the expected verdict, and the verdict of
the independent Python reference interpreter for the claim input.

Usage: attacks.py <bitcoin-rs-binary> --out <dir>
"""
from __future__ import annotations

import argparse
import sys
import tempfile
import time
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from btc import (SIGHASH_ALL, SIGHASH_ANYONECANPAY, SIGHASH_DEFAULT, SIGHASH_NONE, SIGHASH_SINGLE, G, N, P,
                 TapTree, Tx, TxIn, TxOut, schnorr_sign, sha, tapleaf_hash, taproot_sighash, tweak_secret, xonly)
from contract import Claim, le, p2tr_key_spk, spend_claim
from env import Env, Outcome, sats, write_json
from node import Node
import refinterp

AMOUNT = 100_000
THIRD_PARTY = 7


class Campaign:
    def __init__(self, env: Env):
        self.env = env
        self.results = []
        self.claims = {}   # name -> (claim, txid, vout, amount)

    def ref(self, tx: Tx, spent: list, index: int = 0) -> str:
        return refinterp.verify_taproot_input(tx, index, spent, muladdmod=True)

    def record(self, out: Outcome, category: str, expect: bool, rule: str, tx: Tx | None = None,
               spent: list | None = None, note: str = ''):
        d = out.as_dict()
        d.update(category=category, expected_accept=expect, expected_rule=rule, note=note,
                 as_expected=None if expect is None else (out.accepted == expect))
        if tx is not None and spent is not None:
            d['reference_interpreter'] = self.ref(tx, spent)
            d['spent'] = [[v, s.hex()] for v, s in spent]
            d['claim_tx_hex'] = tx.hex()
        self.results.append(d)
        flag = 'obs' if expect is None else ('ok ' if out.accepted == expect else 'UNEXPECTED')
        print(f'[{flag}] {category:28s} {out.name:48s} path={out.path:11s} accepted={out.accepted} '
              f'reason={str(out.reason)[:110]}', flush=True)
        return d

    def spent_for(self, name: str, tx: Tx | None = None):
        claim, txid, vout, amount = self.claims[name]
        return [(amount, claim.spk())]

    # ------------------------------------------------------------------ setup
    def fund_claims(self, specs: dict):
        outputs = [(AMOUNT, c.spk()) for c in specs.values()]
        tx = self.env.fund(outputs)
        for i, (name, c) in enumerate(specs.items()):
            self.claims[name] = (c, tx.txid(), i, AMOUNT)
        return tx

    def mp(self, name, tx, category, expect, rule, claim_name=None, note=''):
        out = self.env.try_mempool(name, tx)
        spent = self.spent_for(claim_name) if claim_name else None
        return self.record(out, category, expect, rule, tx, spent, note)

    def blk(self, name, txs, category, expect, rule, claim_name=None, note=''):
        out = self.env.try_block(name, txs)
        spent = self.spent_for(claim_name) if claim_name else None
        return self.record(out, category, expect, rule, txs[-1], spent, note)

    def sub(self, name, txs, category, expect, rule, claim_name=None, note='', **kw):
        out = self.env.try_submitblock(name, txs, **kw)
        spent = self.spent_for(claim_name) if claim_name else None
        return self.record(out, category, expect, rule, txs[-1] if txs else None, spent, note)

    def both(self, name, tx, category, rule, claim_name, note=''):
        """Rejection must hold in the mempool AND in block validation."""
        self.mp(name, tx, category, False, rule, claim_name, note)
        self.blk(name + '/block', [tx], category, False, rule, claim_name, note)


def small(i, claimed=None, **kw):
    a, b, c, m = 7, 11, 3, 17
    return Claim(sha(b'campaign-claim' + bytes([i])), a, b, c, (a * b + c) % m if claimed is None else claimed, m, **kw)


def wide(i, claimed=None, **kw):
    m = 2**255 - 19
    a = b = c = m - 1
    return Claim(sha(b'campaign-wide' + bytes([i])), a, b, c, (a * b + c) % m if claimed is None else claimed, m, **kw)


def run(binary: Path, out_dir: Path):
    t0 = time.time()
    with tempfile.TemporaryDirectory(prefix='muladdmod-attacks-') as tmp:
        node = Node(binary, Path(tmp), 'attack')
        node.start()
        env = Env(node)
        cam = Campaign(env)
        try:
            env.bootstrap()
            false0 = small(0, 13)
            honest1 = small(1)
            false2 = small(2, 13)
            dup0 = small(0, 13)                        # identical script to false0 (duplicate funding)
            wide4 = wide(4, 1)
            # admission-bypass instances (script built from raw bytes)
            noncanon_d = small(5, raw_values=[b'\x07', b'\x0b', b'\x03', bytes([12 + 17])])
            oversized_a_false = small(6, raw_values=[bytes([7 + 17]), b'\x0b', b'\x03', b'\x0d'])
            nonminimal_mod_false = small(7, raw_values=[b'\x07\x00', b'\x0b\x00', b'\x03\x00', b'\x0d\x00'],
                                         raw_modulus=b'\x11\x00')
            backdoor_leaf = small(8, 13, extra_leaves=[(bytes([0x20]) + xonly(5) + b'\xac', 0xc0)])
            operator_internal = small(9, 13, internal_x=xonly(5))
            delay1 = small(10, 13, delay=1)
            settle_race = small(11, 13)
            rbf_target = small(12, 13)
            honest13 = small(13)
            reorg14 = small(14, 13)
            weak_sighash = small(15, 13)
            specs = {'false0': false0, 'honest1': honest1, 'false2': false2, 'dup0': dup0, 'wide4': wide4,
                     'noncanon_d': noncanon_d, 'oversized_a_false': oversized_a_false,
                     'nonminimal_mod_false': nonminimal_mod_false, 'backdoor_leaf': backdoor_leaf,
                     'operator_internal': operator_internal, 'delay1': delay1, 'settle_race': settle_race,
                     'rbf_target': rbf_target, 'honest13': honest13, 'reorg14': reorg14,
                     'weak_sighash': weak_sighash}
            assert false0.spk() == dup0.spk()
            fund = cam.fund_claims({k: v for k, v in specs.items() if k != 'delay1'})
            funding_height = node.height()

            def args(name):
                c, txid, vout, amt = cam.claims[name]
                return c, txid, vout, amt

            # ============================================================ operand / output substitution
            c, txid, vout, amt = args('false0')
            good = spend_claim(c, txid, vout, amt, True)
            assert node.rpc('testmempoolaccept', [good.hex()])[0]['allowed'] is True
            for i, label in enumerate(['operand_a', 'operand_b', 'operand_c', 'claimed_result_d']):
                vals = c.values()
                vals[i] = bytes([(vals[i][0] + 1) % 17])
                bad = spend_claim(c, txid, vout, amt, True, values=vals)
                cam.both(f'replace_{label}', bad, 'operand-substitution',
                         'SHA256 commitment: OP_EQUALVERIFY (SCRIPT_ERR_EQUALVERIFY)', 'false0')
            vals = c.values(); vals[0], vals[1] = vals[1], vals[0]
            cam.both('swap_a_b_slots', spend_claim(c, txid, vout, amt, True, values=vals), 'operand-substitution',
                     'SCRIPT_ERR_EQUALVERIFY (slot-bound hash)', 'false0')
            vals = c.values(); vals[3] = b'\x0c'  # replace claimed with the correct residue: recovery must fail
            cam.both('replace_d_with_correct_residue', spend_claim(c, txid, vout, amt, True, values=vals),
                     'output-substitution', 'SCRIPT_ERR_EQUALVERIFY', 'false0')
            # ============================================================ malformed encodings at witness level
            for label, v in [('a_width_plus_1', b'\x07\x00'), ('a_empty', b''), ('a_ge_modulus', bytes([7 + 17])),
                             ('a_negative_zero', b'\x80'), ('a_33_bytes', bytes(33))]:
                vals = c.values(); vals[0] = v
                cam.both(f'malformed_{label}', spend_claim(c, txid, vout, amt, True, values=vals), 'malformed-encoding',
                         'SCRIPT_ERR_EQUALVERIFY (hash of exact bytes)', 'false0')
            # modulus substitution: alternate script (m=19) signed correctly but not committed in the output
            alt = replace(c, modulus=19)
            alt_tx = spend_claim(c, txid, vout, amt, True, sign_leaf=alt.leaf_hash())
            alt_tx.vin[0].witness[-2] = alt.script()
            alt_tx.vin[0].witness[-1] = TapTree(c.internal_x, [(alt.script(), 0xc0)]).control(0)
            cam.both('modulus_substitution_m19', alt_tx, 'modulus-substitution',
                     'SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH (taproot commitment)', 'false0')
            # admission-bypass instances: the script itself cannot enforce canonical commitments
            c5, t5, v5, a5 = args('noncanon_d')
            cam.mp('noncanonical_d_congruent_claim_confiscated', spend_claim(c5, t5, v5, a5, True),
                   'admission-bypass', True, 'ACCEPTED: d=29 = 12 mod 17 is integer-correct, bytes differ',
                   'noncanon_d', note='COUNTEREXAMPLE (conditional): safety requires canonical admission of d')
            env.mine(1)
            c6, t6, v6, a6 = args('oversized_a_false')
            cam.both('false_claim_with_oversized_operand_unchallengeable', spend_claim(c6, t6, v6, a6, True),
                     'admission-bypass', 'SCRIPT_ERR_MULADDMOD_ENCODING aborts the recovery branch', 'oversized_a_false',
                     note='COUNTEREXAMPLE (conditional): completeness fails; false claim cannot be recovered')
            c7, t7, v7, a7 = args('nonminimal_mod_false')
            cam.both('false_claim_with_nonminimal_modulus_unchallengeable', spend_claim(c7, t7, v7, a7, True),
                     'admission-bypass', 'SCRIPT_ERR_MULADDMOD_ENCODING (modulus top byte zero)', 'nonminimal_mod_false',
                     note='COUNTEREXAMPLE (conditional): completeness fails for malformed modulus commitments')
            # ============================================================ signatures
            other_c, other_t, other_v, other_a = args('false2')
            replay = spend_claim(other_c, other_t, other_v, other_a, True)
            replay.vin[0].witness[4] = good.vin[0].witness[4]
            cam.both('signature_replay_cross_instance', replay, 'signature-replay', 'SCRIPT_ERR_SCHNORR_SIG', 'false2')
            dc, dt, dv, da = args('dup0')
            dup_tx = spend_claim(dc, dt, dv, da, True)
            dup_tx.vin[0].witness = list(good.vin[0].witness)
            cam.both('signature_replay_identical_script_other_outpoint', dup_tx, 'signature-replay',
                     'SCRIPT_ERR_SCHNORR_SIG (outpoint committed by sighash)', 'dup0')
            subst = spend_claim(other_c, other_t, other_v, other_a, True)
            subst.vin[0].witness = list(good.vin[0].witness)
            cam.both('cross_instance_full_witness_substitution', subst, 'cross-instance',
                     'SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH', 'false2')
            redirected = good.copy(); redirected.vout[0] = TxOut(amt - 2000, p2tr_key_spk(THIRD_PARTY))
            cam.both('redirect_output_reuse_signature', redirected, 'signature-replay', 'SCRIPT_ERR_SCHNORR_SIG', 'false0')
            fee_change = good.copy(); fee_change.vout[0] = TxOut(amt - 1000, good.vout[0].spk)
            cam.both('change_amount_reuse_signature', fee_change, 'signature-replay', 'SCRIPT_ERR_SCHNORR_SIG', 'false0')
            third = spend_claim(c, txid, vout, amt, True, signer=THIRD_PARTY)
            cam.both('third_party_recovery_signature', third, 'invalid-schnorr', 'SCRIPT_ERR_SCHNORR_SIG', 'false0')
            op_sig = spend_claim(c, txid, vout, amt, True, signer=c.operator_secret)
            cam.both('operator_key_on_recovery_branch', op_sig, 'invalid-schnorr', 'SCRIPT_ERR_SCHNORR_SIG', 'false0')

            def with_sig(sig, base=good):
                t = base.copy(); t.vin[0].witness[4] = sig; return t
            s = good.vin[0].witness[4]
            mutations = {
                'sig_R_bitflip': bytes([s[0] ^ 1]) + s[1:],
                'sig_s_bitflip': s[:63] + bytes([s[63] ^ 1]),
                'sig_s_equals_n': s[:32] + N.to_bytes(32, 'big'),
                'sig_R_ge_p': P.to_bytes(32, 'big') + s[32:],
                'sig_R_not_on_curve': (5).to_bytes(32, 'big') + s[32:],
                'sig_63_bytes': s[:63],
                'sig_66_bytes': s + b'\x01\x01',
                'sig_explicit_hashtype_00': s + b'\x00',
                'sig_default_plus_01_byte': s + b'\x01',
                'sig_hashtype_04': s + b'\x04',
                'sig_hashtype_84': s + b'\x84',
                'sig_empty': b'',
                'sig_all_zero': bytes(64),
            }
            for label, sig in mutations.items():
                cam.both(label, with_sig(sig), 'invalid-schnorr',
                         'SCHNORR_SIG / SCHNORR_SIG_SIZE / SCHNORR_SIG_HASHTYPE / CHECKSIGVERIFY', 'false0')
            # altered sighash contexts (valid key, wrong message)
            spent0 = [(amt, c.spk())]
            contexts = {
                'ctx_keypath_message_ext0': dict(leaf_hash=None),
                'ctx_wrong_leaf_hash': dict(leaf_hash=other_c.leaf_hash()),
                'ctx_wrong_amount': dict(spent=[(amt + 1, c.spk())]),
                'ctx_wrong_spk': dict(spent=[(amt, other_c.spk())]),
                'ctx_annex_committed_absent': dict(annex=b'\x50\x01'),
                'ctx_codesep_pos_0': dict(codesep_pos=0),
                'ctx_key_version_1': dict(key_version=1),
            }
            for label, kw in contexts.items():
                t = good.copy()
                msg = taproot_sighash(t, 0, kw.pop('spent', spent0), SIGHASH_DEFAULT,
                                      leaf_hash=kw.pop('leaf_hash', c.leaf_hash()), **kw)
                t.vin[0].witness[4] = schnorr_sign(msg, c.recovery_secret)
                cam.both(label, t, 'altered-sighash', 'SCRIPT_ERR_SCHNORR_SIG', 'false0')
            # annex present but not committed in the signature
            t = good.copy(); t.vin[0].witness.append(b'\x50\xaa')
            cam.both('annex_appended_not_committed', t, 'altered-sighash', 'SCRIPT_ERR_SCHNORR_SIG', 'false0')
            # ============================================================ branch selector / script malleation
            for label, sel in [('selector_02', b'\x02'), ('selector_0100', b'\x01\x00'), ('selector_81', b'\x81')]:
                t = good.copy(); t.vin[0].witness[5] = sel
                cam.both(f'nonminimal_{label}', t, 'witness-malleation', 'SCRIPT_ERR_TAPSCRIPT_MINIMALIF', 'false0')
            t = good.copy(); t.vin[0].witness.insert(0, b'\x01')
            cam.both('extra_bottom_stack_item', t, 'witness-malleation', 'SCRIPT_ERR_CLEANSTACK', 'false0')
            t = good.copy(); t.vin[0].witness[5] = b''
            cam.both('settlement_selector_with_recovery_witness', t, 'witness-malleation',
                     'CSV/stack failure on ELSE branch', 'false0')
            # ============================================================ taproot bypass
            kp = good.copy()
            kp.vin[0].witness = [schnorr_sign(taproot_sighash(kp, 0, spent0), THIRD_PARTY)]
            cam.both('keypath_spend_unknown_key', kp, 'taproot-bypass', 'SCRIPT_ERR_SCHNORR_SIG (NUMS internal key)', 'false0')
            kp2 = good.copy()
            kp2.vin[0].witness = [schnorr_sign(taproot_sighash(kp2, 0, spent0), tweak_secret(c.operator_secret, c.tree().merkle_root()))]
            cam.both('keypath_operator_tweaked_key', kp2, 'taproot-bypass', 'SCRIPT_ERR_SCHNORR_SIG', 'false0')
            t = good.copy(); cb = t.vin[0].witness[-1]; t.vin[0].witness[-1] = bytes([cb[0] ^ 1]) + cb[1:]
            cam.both('control_parity_flip', t, 'taproot-bypass', 'SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH', 'false0')
            t = good.copy(); t.vin[0].witness[-1] = bytes([0xc2 | (cb[0] & 1)]) + cb[1:]
            cam.both('control_leaf_version_c2', t, 'taproot-bypass', 'SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH', 'false0')
            t = good.copy(); t.vin[0].witness[-1] = cb + bytes(32)
            cam.both('control_extra_path_node', t, 'taproot-bypass', 'SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH', 'false0')
            t = good.copy(); t.vin[0].witness[-1] = cb[:32]
            cam.both('control_truncated', t, 'taproot-bypass', 'SCRIPT_ERR_TAPROOT_WRONG_CONTROL_SIZE', 'false0')
            t = good.copy(); t.vin[0].witness = [b'\x51', cb]
            cam.both('alternate_leaf_op_true', t, 'taproot-bypass', 'SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH', 'false0')
            t = good.copy(); t.vin[0].witness = [bytes([0x50]), cb]  # OP_SUCCESS80 leaf
            cam.both('alternate_leaf_op_success', t, 'taproot-bypass', 'SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH', 'false0')
            # misconfigured outputs: the funder must verify the complete output key
            bc, bt, bv, ba = args('backdoor_leaf')
            bd = Tx([TxIn(bt, bv, b'', 0xffffffff)], [TxOut(ba - 2000, p2tr_key_spk(5))])
            tree = bc.tree()
            bd.vin[0].witness = [schnorr_sign(taproot_sighash(bd, 0, [(ba, bc.spk())], leaf_hash=tapleaf_hash(tree.leaves[1][0])), 5),
                                 tree.leaves[1][0], tree.control(1)]
            cam.mp('operator_backdoor_leaf_in_unverified_tree', bd, 'taproot-bypass', True,
                   'ACCEPTED: a second leaf lets the operator spend a false claim at once', 'backdoor_leaf',
                   note='COUNTEREXAMPLE (conditional): funders must verify the full tap tree, not only the claim leaf')
            oc, ot, ov, oa = args('operator_internal')
            ok_tx = Tx([TxIn(ot, ov, b'', 0xffffffff)], [TxOut(oa - 2000, p2tr_key_spk(5))])
            ok_tx.vin[0].witness = [schnorr_sign(taproot_sighash(ok_tx, 0, [(oa, oc.spk())]),
                                                 tweak_secret(5, oc.tree().merkle_root()))]
            cam.mp('operator_internal_key_keypath_bypass', ok_tx, 'taproot-bypass', True,
                   'ACCEPTED: non-NUMS internal key enables key-path settlement of a false claim', 'operator_internal',
                   note='COUNTEREXAMPLE (conditional): funders must verify the NUMS internal key')
            env.mine(1)
            # ============================================================ honest-claim confiscation
            hc, ht, hv, ha = args('honest1')
            cam.both('recover_honest_claim', spend_claim(hc, ht, hv, ha, True), 'safety',
                     'SCRIPT_ERR_EVAL_FALSE (EQUAL NOT on correct residue)', 'honest1')
            # ============================================================ CSV manipulation (honest1 settlement)
            depth = node.height() - funding_height + 1  # confirmations of funding at next block
            assert depth < hc.delay, depth
            premature = spend_claim(hc, ht, hv, ha, False)
            cam.mp('settlement_before_delay', premature, 'csv', False, 'BIP68 non-final (sequence lock)', 'honest1')
            cam.blk('settlement_before_delay/block', [premature], 'csv', False, 'BIP68 non-final in block', 'honest1')
            cam.sub('settlement_before_delay/submitblock', [premature], 'csv', False, 'BIP68 non-final in block', 'honest1')
            variants = {
                'sequence_delay_minus_1': dict(sequence=hc.delay - 1),
                'version_1': dict(version=1),
                'sequence_disable_flag': dict(sequence=(1 << 31) | hc.delay),
                'sequence_time_type': dict(sequence=(1 << 22) | hc.delay),
                'sequence_final': dict(sequence=0xffffffff),
                'empty_operator_signature': None,
            }
            variant_txs = {}
            for label, kw in variants.items():
                if kw is None:
                    t = spend_claim(hc, ht, hv, ha, False); t.vin[0].witness[0] = b''
                else:
                    t = spend_claim(hc, ht, hv, ha, False, **kw)
                variant_txs[label] = t
            # mine until settlement is valid in the NEXT block, then retry every variant (rule must be the script, not BIP68)
            env.mine(funding_height + hc.delay - 1 - node.height())
            assert node.height() == funding_height + hc.delay - 1
            for label, t in variant_txs.items():
                cam.both(f'settlement_{label}_at_maturity', t, 'csv',
                         'CSV script rule (SCRIPT_ERR_UNSATISFIED_LOCKTIME) or CHECKSIG false', 'honest1')
            mature = spend_claim(hc, ht, hv, ha, False)
            cam.mp('settlement_at_exact_maturity', mature, 'csv', True, 'valid at funding_height+delay', 'honest1')
            # admission-bypass instances: the unchallengeable false claims now settle
            cam.mp('false_claim_oversized_operand_settles', spend_claim(c6, t6, v6, a6, False), 'admission-bypass', True,
                   'ACCEPTED: operator settles a false claim whose recovery branch always aborts', 'oversized_a_false',
                   note='COUNTEREXAMPLE (conditional): completes the completeness failure')
            cam.mp('false_claim_nonminimal_modulus_settles', spend_claim(c7, t7, v7, a7, False), 'admission-bypass', True,
                   'ACCEPTED: operator settles a false claim with a malformed modulus commitment', 'nonminimal_mod_false',
                   note='COUNTEREXAMPLE (conditional): completes the completeness failure')
            env.mine(1)
            cam.mp('recovery_after_settlement_honest', spend_claim(hc, ht, hv, ha, True), 'exclusivity', False,
                   'missing inputs (outpoint spent)', 'honest1')
            # ============================================================ exclusivity: same-block double spend
            sc, st, sv, sa = args('settle_race')
            rec = spend_claim(sc, st, sv, sa, True)
            setl = spend_claim(sc, st, sv, sa, False)
            cam.blk('recovery_and_settlement_same_block', [rec, setl], 'exclusivity', False,
                    'bad-txns-inputs-missingorspent (in-block double spend)', 'settle_race')
            cam.sub('recovery_and_settlement_same_block/submitblock', [rec, setl], 'exclusivity', False,
                    'in-block double spend', 'settle_race')
            # ============================================================ mempool conflicts / pinning (settle_race now mature)
            cam.mp('recovery_enters_mempool', rec, 'mempool-conflict', True, 'valid recovery', 'settle_race')
            cam.mp('settlement_conflicts_lower_fee', setl, 'mempool-conflict', False, 'RBF: insufficient fee', 'settle_race')
            setl_hi = spend_claim(sc, st, sv, sa, False, fee=20_000)
            r = cam.mp('settlement_outbids_recovery_rbf', setl_hi, 'mempool-conflict', None,
                       'policy question: can the operator replace a pending recovery after the window opens?', 'settle_race')
            r['note'] = 'LIVENESS: records whether a higher-fee settlement evicts a pending recovery once both are valid'
            in_pool = node.mempool()
            r['mempool_after'] = {'recovery': rec.txid() in in_pool, 'settlement': setl_hi.txid() in in_pool}
            env.mine(1)
            winner = 'recovery' if node.rpc('gettxout', rec.txid(), 0) else (
                'settlement' if node.rpc('gettxout', setl_hi.txid(), 0) else 'none')
            r['confirmed_winner'] = winner
            # RBF of recovery by beneficiary and malleation attempts on a pending recovery
            rc, rt, rv, ra = args('rbf_target')
            r1 = spend_claim(rc, rt, rv, ra, True, fee=2000)
            cam.mp('rbf_target_recovery_low_fee', r1, 'mempool-conflict', True, 'valid', 'rbf_target')
            for label, mut in [('append_annex', lambda w: w + [b'\x50']),
                               ('pad_sig_hashtype_00', lambda w: w[:4] + [w[4] + b'\x00'] + w[5:]),
                               ('selector_02', lambda w: w[:5] + [b'\x02'] + w[6:]),
                               ('widen_d', lambda w: w[:3] + [w[3] + b'\x00'] + w[4:])]:
                t = r1.copy(); t.vin[0].witness = mut(list(t.vin[0].witness))
                cam.mp(f'third_party_witness_malleation_{label}', t, 'pinning', False,
                       'invalid witness (no third-party wtxid malleation)', 'rbf_target')
                cam.blk(f'third_party_witness_malleation_{label}/block', [t], 'pinning', False,
                        'invalid witness in block validation', 'rbf_target')
            r2 = spend_claim(rc, rt, rv, ra, True, fee=2000, outputs=[TxOut(ra - 2000, p2tr_key_spk(rc.recovery_secret + 100))])
            cam.mp('rbf_recovery_same_fee', r2, 'mempool-conflict', False, 'RBF insufficient fee', 'rbf_target')
            r3 = spend_claim(rc, rt, rv, ra, True, fee=6000)
            out = cam.mp('rbf_recovery_higher_fee_nonsignaling', r3, 'mempool-conflict', None,
                         'full-RBF replaces a non-signaling recovery', 'rbf_target')
            out['note'] = 'records the node RBF policy for sequence=0xffffffff recoveries'
            # descendant CPFP on the pending recovery (only the recovery key can spend its output)
            pending = r3 if r3.txid() in node.mempool() else r1
            child = Tx([TxIn(pending.txid(), 0, b'', 0xfffffffd)], [TxOut(pending.vout[0].value - 5000, p2tr_key_spk(1))])
            # recovery output pays to the raw x-only key of the recovery secret (no tweak)
            child.vin[0].witness = [schnorr_sign(taproot_sighash(child, 0, [(pending.vout[0].value, pending.vout[0].spk)]),
                                                 rc.recovery_secret)]
            cam.mp('cpfp_child_of_recovery', child, 'mempool-conflict', True, 'recovery output spendable by beneficiary')
            env.mine(1)
            # ============================================================ weak sighash: third party redirection
            wc, wt, wv, wa = args('weak_sighash')
            weak = spend_claim(wc, wt, wv, wa, True, hash_type=SIGHASH_NONE | SIGHASH_ANYONECANPAY)
            stolen = weak.copy(); stolen.vout = [TxOut(wa - 3000, p2tr_key_spk(THIRD_PARTY))]
            cam.mp('third_party_redirects_sighash_none_recovery', stolen, 'signature-replay', True,
                   'ACCEPTED: SIGHASH_NONE|ACP recovery signature does not bind outputs', 'weak_sighash',
                   note='COUNTEREXAMPLE (signer misuse): the contract does not restrict the recovery sighash type')
            env.mine(1)
            # ============================================================ wide field
            wcl, wtx, wvo, wam = args('wide4')
            wgood = spend_claim(wcl, wtx, wvo, wam, True)
            vals = wcl.values(); vals[0] = vals[0][:-1] + bytes([vals[0][-1] ^ 0x40])
            cam.both('wide_replace_a', spend_claim(wcl, wtx, wvo, wam, True, values=vals), 'operand-substitution',
                     'SCRIPT_ERR_EQUALVERIFY', 'wide4')
            cam.mp('wide_recovery_valid', wgood, 'safety', True, 'false wide claim (d=1, correct=0) recovered', 'wide4')
            env.mine(1)
            # ============================================================ delay=1 boundary
            dfund = env.funding_tx([(AMOUNT, delay1.spk())])
            node.rpc('sendrawtransaction', dfund.hex()); env.mine(1)
            cam.claims['delay1'] = (delay1, dfund.txid(), 0, AMOUNT)
            drec = spend_claim(delay1, dfund.txid(), 0, AMOUNT, True)
            dset = spend_claim(delay1, dfund.txid(), 0, AMOUNT, False, fee=50_000)
            cam.mp('delay1_settlement_valid_next_block', dset, 'liveness', True,
                   'delay=1: settlement is valid in the block after funding', 'delay1',
                   note='LIVENESS: with delay=1 the operator competes in the very first block')
            o = cam.mp('delay1_recovery_after_settlement_broadcast', drec, 'liveness', False,
                       'conflict: settlement already pending with higher fee', 'delay1')
            env.mine(1)
            # ============================================================ reorg around the deadline (single node)
            gc, gt, gv, ga = args('reorg14')
            grec = spend_claim(gc, gt, gv, ga, True)
            gset = spend_claim(gc, gt, gv, ga, False, fee=10_000)
            cam.mp('reorg14_recovery_confirmed', grec, 'reorg', True, 'valid', 'reorg14')
            rb = env.mine(1)[0]
            assert node.rpc('gettxout', gt, gv) is None
            node.rpc('invalidateblock', rb)
            back = grec.txid() in node.mempool()
            cam.results.append({'name': 'reorg14_recovery_returns_to_mempool', 'category': 'reorg', 'path': 'invalidateblock',
                                'accepted': back, 'expected_accept': True, 'as_expected': back,
                                'note': 'a disconnected recovery must be re-admitted to the mempool'})
            print(f'[{"ok " if back else "UNEXPECTED"}] reorg recovery returns to mempool: {back}')
            # operator builds a private fork without the recovery until settlement is valid
            fork_parent = node.rpc('getblockheader', rb)['previousblockhash']
            tip_h = node.rpc('getblockheader', fork_parent)['height']
            prev = fork_parent
            h = tip_h
            fork = []
            while h + 1 < funding_height + gc.delay:
                o = env.try_submitblock(f'fork_empty_{h+1}', [], prev=prev)
                assert o.accepted, o.as_dict()
                prev = o.txid; h += 1; fork.append(prev)
            o = cam.sub('reorg14_settlement_on_fork_after_recovery_was_disconnected', [gset], 'reorg', True,
                        'valid on the fork: recovery is not on this chain', 'reorg14', prev=prev)
            fork.append(o['txid'])
            o2 = env.try_submitblock('fork_extension', [], prev=o['txid'])
            assert o2.accepted, o2.as_dict()
            fork.append(o2.txid)
            state_rec = node.rpc('gettxout', grec.txid(), 0)
            state_set = node.rpc('gettxout', gset.txid(), 0)
            cam.results.append({'name': 'reorg14_exclusivity_after_reorg', 'category': 'reorg', 'path': 'state',
                                'accepted': bool(state_set) and not state_rec, 'expected_accept': True,
                                'as_expected': bool(state_set) and not state_rec,
                                'recovery_in_mempool': grec.txid() in node.mempool(),
                                'note': 'after the reorg exactly one terminal spend exists; the honest challenger lost a confirmed recovery'})
            ok_rc, rc_res = node.try_rpc('reconsiderblock', rb)
            if not ok_rc:
                cam.results.append({'name': 'reconsiderblock_rpc', 'category': 'reorg', 'path': 'rpc',
                                    'accepted': False, 'expected_accept': None, 'as_expected': None,
                                    'reason': rc_res, 'note': 'reconsiderblock is not implemented; multi-node '
                                    'reorgs (phase 6) exercise most-work selection instead'})
            final_rec = node.rpc('gettxout', grec.txid(), 0)
            final_set = node.rpc('gettxout', gset.txid(), 0)
            cam.results.append({'name': 'reorg14_reconsider_shorter_branch', 'category': 'reorg', 'path': 'state',
                                'accepted': bool(final_set) and not final_rec, 'expected_accept': True,
                                'as_expected': bool(final_set) and not final_rec,
                                'note': 'reconsidering the shorter recovery branch must not resurrect it (most-work rule)'})
            # restart persistence of the final state
            node.stop()
            node.start()
            persisted = bool(node.rpc('gettxout', gset.txid(), 0)) and not node.rpc('gettxout', grec.txid(), 0)
            cam.results.append({'name': 'restart_preserves_post_reorg_state', 'category': 'persistence', 'path': 'restart',
                                'accepted': persisted, 'expected_accept': True, 'as_expected': persisted})
            print(f'[{"ok " if persisted else "UNEXPECTED"}] restart preserves post-reorg state: {persisted}')
            summary = {
                'total_attempts': len(cam.results),
                'node_accepted': sum(1 for r in cam.results if r.get('accepted')),
                'node_rejected': sum(1 for r in cam.results if r.get('accepted') is False),
                'unexpected': [r['name'] for r in cam.results if r.get('as_expected') is False],
                'policy_observations': [r['name'] for r in cam.results if r.get('as_expected') is None],
                'reference_disagreements': [r['name'] for r in cam.results if 'reference_interpreter' in r and r['path'] in ('mempool',) and
                                            ((r['reference_interpreter'] == 'OK') != bool(r['accepted'])) and
                                            'missing' not in str(r.get('reason')) and 'conflict' not in str(r.get('reason')).lower()],
                'elapsed_s': round(time.time() - t0, 1),
            }
            report = {'binary_sha256': sha(Path(binary).read_bytes()).hex(), 'funding_txid': fund.txid(),
                      'funding_height': funding_height, 'summary': summary, 'results': cam.results}
            write_json(out_dir / 'phase2-attacks.json', report)
            print(summary)
            return report
        finally:
            node.stop()
            (out_dir / 'phase2-attacks.node.log').write_bytes(node.log_path.read_bytes())


if __name__ == '__main__':
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('binary', type=Path)
    ap.add_argument('--out', type=Path, required=True)
    a = ap.parse_args()
    a.out.mkdir(parents=True, exist_ok=True)
    run(a.binary, a.out)
