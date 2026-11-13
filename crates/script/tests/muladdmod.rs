#![expect(
    clippy::expect_used,
    reason = "independent rust-bitcoin Taproot fixtures"
)]

use bitcoin::hashes::Hash as _;
use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};
use bitcoin::taproot::{LeafVersion, TaprootBuilder};
use bitcoin::{ScriptBuf, Transaction};
use bitcoin_rs_primitives::{Amount, Script, Tx, TxOut, deserialize};
use bitcoin_rs_script::opcode::OP_MULADDMOD_EXPERIMENTAL as OP;
use bitcoin_rs_script::{
    Interpreter, PreparedTransaction, ScriptErrCode, ScriptError, VerifyFlags,
};

fn spend(script: &[u8], args: &[Vec<u8>], annex: Option<Vec<u8>>) -> (Tx, TxOut) {
    let secp = Secp256k1::new();
    let secret = SecretKey::from_slice(&[37; 32]).expect("test key");
    let key = Keypair::from_secret_key(&secp, &secret);
    let leaf = ScriptBuf::from_bytes(script.to_vec());
    let tree = TaprootBuilder::new()
        .add_leaf(0, leaf.clone())
        .expect("leaf")
        .finalize(&secp, key.x_only_public_key().0)
        .expect("complete tree");
    let control = tree
        .control_block(&(leaf.clone(), LeafVersion::TapScript))
        .expect("control");
    let prevout = TxOut {
        value: Amount::from_sat(100_000),
        script_pubkey: Script::from_bytes(
            ScriptBuf::new_p2tr_tweaked(tree.output_key()).to_bytes(),
        ),
    };
    let mut witness = args.to_vec();
    witness.extend([leaf.to_bytes(), control.serialize()]);
    if let Some(annex) = annex {
        witness.push(annex);
    }
    let tx = Transaction {
        version: bitcoin::transaction::Version(2),
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![bitcoin::TxIn {
            previous_output: bitcoin::OutPoint::new(bitcoin::Txid::from_byte_array([17; 32]), 0),
            script_sig: ScriptBuf::new(),
            sequence: bitcoin::Sequence::MAX,
            witness: bitcoin::Witness::from_slice(&witness),
        }],
        output: vec![bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(90_000),
            script_pubkey: ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array([42; 20])),
        }],
    };
    (
        deserialize(&bitcoin::consensus::serialize(&tx)).expect("native transaction"),
        prevout,
    )
}

fn verify(tx: &Tx, prevout: &TxOut, flags: VerifyFlags) -> Result<bool, ScriptError> {
    let result = PreparedTransaction::new(tx, &[(tx.inputs[0].previous_output, prevout.clone())])
        .expect("complete prevouts")
        .verify_input(0, flags, None);
    let direct = Interpreter.execute_with_prevouts(
        &prevout.script_pubkey,
        &tx.inputs[0].script_sig,
        &tx.inputs[0].witness,
        flags,
        std::slice::from_ref(prevout),
        tx,
        0,
    );
    assert_eq!(result, direct);
    result
}

fn error(code: ScriptErrCode) -> Result<bool, ScriptError> {
    Err(ScriptError::Invalid { code })
}

#[test]
fn flag_off_preserves_op_success_and_standard_policy() {
    let (tx, output) = spend(&[OP, 0x6a, 0x4c], &[vec![0; 521]], None);
    assert_eq!(verify(&tx, &output, VerifyFlags::MANDATORY), Ok(true));
    assert_eq!(
        verify(&tx, &output, VerifyFlags::STANDARD),
        error(ScriptErrCode::DiscourageOpSuccess)
    );
}

#[cfg(not(feature = "experimental-muladdmod"))]
#[test]
fn unsupported_build_refuses_an_explicit_experimental_flag() {
    let (tx, output) = spend(&[OP], &[], None);
    assert_eq!(
        verify(
            &tx,
            &output,
            VerifyFlags::MANDATORY.union(VerifyFlags::EXPERIMENTAL_MULADDMOD)
        ),
        error(ScriptErrCode::ExperimentalDisabled)
    );
}

#[cfg(feature = "experimental-muladdmod")]
mod active {
    use super::*;

    fn flags() -> VerifyFlags {
        VerifyFlags::MANDATORY.union(VerifyFlags::EXPERIMENTAL_MULADDMOD)
    }
    fn args() -> Vec<Vec<u8>> {
        vec![vec![7], vec![11], vec![3], vec![17]]
    }
    fn run(script: &[u8], args: &[Vec<u8>]) -> Result<bool, ScriptError> {
        let (tx, output) = spend(script, args, None);
        verify(&tx, &output, flags())
    }

    #[test]
    fn complete_taproot_spend_checks_fused_arithmetic() {
        let (tx, output) = spend(&[OP, 0x5c, 0x87], &args(), None);
        assert_eq!(verify(&tx, &output, flags()), Ok(true));
        assert_eq!(
            verify(
                &tx,
                &output,
                VerifyFlags::STANDARD.union(VerifyFlags::EXPERIMENTAL_MULADDMOD)
            ),
            Ok(true)
        );
        assert_eq!(
            run(&[OP, 0x5b, 0x87], &args()),
            error(ScriptErrCode::EvalFalse)
        );
    }

    #[test]
    fn residue_encoding_and_stack_underflow_fail_closed() {
        for size in 0..4 {
            assert_eq!(
                run(&[OP], &args()[..size]),
                error(ScriptErrCode::InvalidStackOperation)
            );
        }
        for i in 0..4 {
            let mut values = args();
            values[i] = Vec::new();
            assert_eq!(run(&[OP], &values), error(ScriptErrCode::MulAddModEncoding));
        }
        let mut values = args();
        values[0] = vec![17];
        assert_eq!(run(&[OP], &values), error(ScriptErrCode::MulAddModEncoding));
    }

    #[test]
    fn skipped_opcode_has_no_stack_effect_or_charge() {
        let mut script = vec![0, 0x63];
        script.extend(std::iter::repeat_n(OP, 200));
        script.extend([0x68, 0x51]);
        assert_eq!(run(&script, &[]), Ok(true));
    }

    #[test]
    fn bytes_in_pushes_remain_data_and_other_success_opcodes_remain_active() {
        assert_eq!(run(&[1, OP, 0x75, 0x51], &[]), Ok(true));
        assert_eq!(run(&[OP, 0xf1, 0x4c], &[vec![0; 521]]), Ok(true));
        let (tx, output) = spend(&[OP, 0xf1], &[], None);
        assert_eq!(
            verify(
                &tx,
                &output,
                VerifyFlags::STANDARD.union(VerifyFlags::EXPERIMENTAL_MULADDMOD)
            ),
            error(ScriptErrCode::DiscourageOpSuccess)
        );
    }

    #[test]
    fn activated_opcode_loses_early_success_bypass() {
        assert_eq!(run(&[OP, 0x4c], &args()), error(ScriptErrCode::BadOpcode));
        assert_eq!(run(&[OP], &[vec![0; 521]]), error(ScriptErrCode::PushSize));
        assert_eq!(
            run(&[OP], &vec![vec![]; 1001]),
            error(ScriptErrCode::StackSize)
        );
        assert_eq!(run(&[0x4c, 0xff, OP], &[]), error(ScriptErrCode::BadOpcode));
    }

    #[test]
    fn stack_effect_cleanstack_and_final_truth_are_preserved() {
        let mut values = vec![vec![42]];
        values.extend(args());
        assert_eq!(run(&[OP, 0x5c, 0x88, 1, 42, 0x87], &values), Ok(true));
        assert_eq!(run(&[OP], &values), error(ScriptErrCode::CleanStack));
        assert_eq!(
            run(&[OP], &[vec![0], vec![1], vec![0], vec![17]]),
            error(ScriptErrCode::EvalFalse)
        );
    }

    #[test]
    fn unsigned_negative_zero_requires_an_explicit_comparison() {
        let values = [vec![128], vec![1], vec![0], vec![251]];
        assert_eq!(run(&[OP], &values), error(ScriptErrCode::EvalFalse));
        assert_eq!(run(&[OP, 1, 128, 0x87], &values), Ok(true));
    }

    #[test]
    fn fixed_width_one_does_not_bypass_minimalif() {
        let values = [vec![1, 0], vec![1, 0], vec![0, 0], vec![1, 1]];
        assert_eq!(
            run(&[OP, 0x63, 0x51, 0x68], &values),
            error(ScriptErrCode::TapscriptMinimalIf)
        );
    }

    #[test]
    fn legacy_and_witness_v0_keep_their_previous_opcode_rules() {
        let (mut tx, mut output) = spend(&[OP], &[], None);
        tx.inputs[0].witness = bitcoin_rs_primitives::Witness::new();
        output.script_pubkey = Script::from_bytes(vec![OP]);
        assert_eq!(
            verify(&tx, &output, flags()),
            error(ScriptErrCode::BadOpcode)
        );
        let leaf = ScriptBuf::from_bytes(vec![OP]);
        output.script_pubkey = Script::from_bytes(leaf.to_p2wsh().to_bytes());
        tx.inputs[0].witness = bitcoin_rs_primitives::Witness::from_stack(vec![leaf.to_bytes()]);
        assert_eq!(
            verify(&tx, &output, flags()),
            error(ScriptErrCode::BadOpcode)
        );
    }

    fn repeated(count: usize, signature: bool) -> Vec<u8> {
        let mut script = Vec::new();
        if signature {
            script.extend([0x51, 0xad]);
        }
        script.extend([1, 0]);
        for _ in 0..count {
            script.extend([0x51, 1, 0, 1, 17, OP]);
        }
        script.extend([1, 0, 0x87]);
        script
    }

    #[test]
    fn witness_serialization_and_annex_determine_the_shared_budget() {
        for signature in [false, true] {
            let script = repeated(8, signature);
            let values = if signature { vec![vec![1]] } else { vec![] };
            let charged = 50 * (8 + usize::from(signature));
            let mut successes = 0;
            let mut failures = 0;
            for size in [0, 1, 200, 252, 253, 300, 400] {
                let annex = if size == 0 {
                    None
                } else {
                    let mut a = vec![0; size];
                    a[0] = 0x50;
                    Some(a)
                };
                let (tx, output) = spend(&script, &values, annex);
                let wire: bitcoin::Transaction =
                    bitcoin::consensus::deserialize(&bitcoin_rs_primitives::consensus_bytes(&tx))
                        .expect("independent decode");
                let budget = 50 + bitcoin::consensus::serialize(&wire.input[0].witness).len();
                let expected = if budget >= charged {
                    successes += 1;
                    Ok(true)
                } else {
                    failures += 1;
                    error(ScriptErrCode::TapscriptValidationWeight)
                };
                assert_eq!(
                    verify(&tx, &output, flags()),
                    expected,
                    "size={size}, signature={signature}, budget={budget}"
                );
            }
            assert!(successes > 0 && failures > 0);
        }
    }

    #[test]
    fn commitment_mutation_and_input_script_sig_are_still_rejected() {
        let (mut tx, output) = spend(&[OP, 0x5c, 0x87], &args(), None);
        let mut items: Vec<Vec<u8>> = tx.inputs[0].witness.iter().map(<[u8]>::to_vec).collect();
        let last = items.len() - 1;
        items[last][1] ^= 1;
        tx.inputs[0].witness = bitcoin_rs_primitives::Witness::from_stack(items);
        assert_eq!(
            verify(&tx, &output, flags()),
            error(ScriptErrCode::WitnessProgramMismatch)
        );
        let (mut tx, output) = spend(&[OP, 0x5c, 0x87], &args(), None);
        tx.inputs[0].script_sig = Script::from_bytes(vec![0]);
        assert_eq!(
            verify(&tx, &output, flags()),
            error(ScriptErrCode::WitnessMalleated)
        );
    }

    mod dispute_properties {
        //! Property-based verification of the funded arithmetic dispute
        //! contract invariants (Safety, Completeness, Replay isolation) across
        //! random canonical claims of widths 1..=32.
        use bitcoin::hashes::{Hash as _, sha256};
        use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey, XOnlyPublicKey};
        use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
        use bitcoin::taproot::{LeafVersion, TapLeafHash, TaprootBuilder};
        use bitcoin::{ScriptBuf, Transaction};
        use bitcoin_rs_primitives::{Amount, Script, Tx, TxOut, deserialize};
        use bitcoin_rs_script::opcode::OP_MULADDMOD_EXPERIMENTAL as OP;
        use bitcoin_rs_script::{ScriptErrCode, VerifyFlags};
        use proptest::prelude::*;

        use super::{error, flags, verify};

        const NUMS_HEX: [u8; 32] = [
            0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9,
            0x7a, 0x5e, 0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a,
            0xce, 0x80, 0x3a, 0xc0,
        ];

        fn push_minimal(out: &mut Vec<u8>, data: &[u8]) {
            if data.is_empty() {
                out.push(0x00);
                return;
            }
            if data.len() == 1 {
                let b = data[0];
                if (1..=16).contains(&b) {
                    out.push(0x50 + b);
                    return;
                }
                if b == 0x81 {
                    out.push(0x4f);
                    return;
                }
            }
            let len = data.len();
            if let Ok(short) = u8::try_from(len) {
                if len <= 75 {
                    out.push(short);
                } else {
                    out.push(0x4c);
                    out.push(short);
                }
            }
            out.extend_from_slice(data);
        }

        fn dispute_leaf(
            instance: &[u8; 32],
            values: &[Vec<u8>; 4],
            modulus: &[u8],
            delay: u8,
            recovery_x: &[u8; 32],
            operator_x: &[u8; 32],
        ) -> Vec<u8> {
            let mut s = Vec::new();
            push_minimal(&mut s, instance);
            s.extend_from_slice(&[0x75, 0x63]); // DROP IF
            push_minimal(&mut s, recovery_x);
            s.push(0xad); // CHECKSIGVERIFY
            for v in values[1..].iter().rev() {
                s.extend_from_slice(&[0x76, 0xa8]); // DUP SHA256
                push_minimal(&mut s, sha256::Hash::hash(v).as_byte_array());
                s.extend_from_slice(&[0x88, 0x6b]); // EQUALVERIFY TOALTSTACK
            }
            s.extend_from_slice(&[0x76, 0xa8]); // DUP SHA256
            push_minimal(&mut s, sha256::Hash::hash(&values[0]).as_byte_array());
            s.push(0x88); // EQUALVERIFY
            s.extend_from_slice(&[0x6c, 0x6c]); // FROMALTSTACK FROMALTSTACK
            push_minimal(&mut s, modulus);
            s.push(OP);
            s.extend_from_slice(&[0x6c, 0x87, 0x91, 0x67]); // FROMALTSTACK EQUAL NOT ELSE
            push_minimal(&mut s, &[delay]);
            s.extend_from_slice(&[0xb2, 0x75]); // CSV DROP
            push_minimal(&mut s, operator_x);
            s.extend_from_slice(&[0xac, 0x68]); // CHECKSIG ENDIF
            s
        }

        fn build_claim_spend(
            txid_tag: u8,
            leaf_bytes: &[u8],
            witness_prefix: &[Vec<u8>],
            signer: &Keypair,
            recover: bool,
            delay: u8,
        ) -> (Tx, TxOut) {
            let secp = Secp256k1::new();
            let internal = XOnlyPublicKey::from_slice(&NUMS_HEX).expect("BIP341 NUMS");
            let leaf = ScriptBuf::from_bytes(leaf_bytes.to_vec());
            let tree = TaprootBuilder::new()
                .add_leaf(0, leaf.clone())
                .expect("leaf")
                .finalize(&secp, internal)
                .expect("tree");
            let control = tree
                .control_block(&(leaf.clone(), LeafVersion::TapScript))
                .expect("control");
            let prev_btc = bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(200_000),
                script_pubkey: ScriptBuf::new_p2tr_tweaked(tree.output_key()),
            };
            let seq = if recover {
                bitcoin::Sequence::MAX
            } else {
                bitcoin::Sequence::from_consensus(u32::from(delay))
            };
            let mut tx = Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: bitcoin::absolute::LockTime::ZERO,
                input: vec![bitcoin::TxIn {
                    previous_output: bitcoin::OutPoint::new(
                        bitcoin::Txid::from_byte_array([txid_tag; 32]),
                        0,
                    ),
                    script_sig: ScriptBuf::new(),
                    sequence: seq,
                    witness: bitcoin::Witness::new(),
                }],
                output: vec![bitcoin::TxOut {
                    value: bitcoin::Amount::from_sat(198_000),
                    script_pubkey: ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array(
                        [9; 20],
                    )),
                }],
            };
            let sighash = SighashCache::new(&tx)
                .taproot_signature_hash(
                    0,
                    &Prevouts::All(std::slice::from_ref(&prev_btc)),
                    None,
                    Some((
                        TapLeafHash::from_script(&leaf, LeafVersion::TapScript),
                        0xffff_ffff,
                    )),
                    TapSighashType::Default,
                )
                .expect("sighash");
            let sig = secp
                .sign_schnorr_no_aux_rand(&Message::from_digest(sighash.to_byte_array()), signer);
            let mut items = witness_prefix.to_vec();
            items.push(sig.as_ref().to_vec());
            items.push(if recover { vec![1] } else { Vec::new() });
            items.push(leaf.to_bytes());
            items.push(control.serialize());
            tx.input[0].witness = bitcoin::Witness::from_slice(&items);
            let native: Tx =
                deserialize(&bitcoin::consensus::serialize(&tx)).expect("native decode");
            let native_prev = TxOut {
                value: Amount::from_sat(prev_btc.value.to_sat()),
                script_pubkey: Script::from_bytes(prev_btc.script_pubkey.to_bytes()),
            };
            (native, native_prev)
        }

        fn canonical_modulus(width: usize, raw: &[u8; 32]) -> Vec<u8> {
            let mut m = raw[..width].to_vec();
            if let Some(last) = m.last_mut() {
                if *last == 0 {
                    *last = 1;
                }
            }
            if width == 1 && m[0] < 2 {
                m[0] = 2;
            }
            m
        }

        fn clamp_below(raw: &[u8; 32], m: &[u8]) -> Vec<u8> {
            let mut x = raw[..m.len()].to_vec();
            // Compare big-endian from top byte; if x >= m, clear/decrement top byte where m > 0
            let ge = x
                .iter()
                .rev()
                .zip(m.iter().rev())
                .find(|(a, b)| a != b)
                .is_none_or(|(a, b)| a > b);
            if ge {
                if let Some((idx, byte)) = m.iter().enumerate().rfind(|(_, b)| **b > 0) {
                    x[idx] = byte - 1;
                    for low in &mut x[..idx] {
                        *low &= 0x7f;
                    }
                }
            }
            x
        }

        fn increment_mod(val: &[u8], m: &[u8]) -> Vec<u8> {
            let mut out = val.to_vec();
            let mut carry = 1_u16;
            for b in &mut out {
                let s = u16::from(*b) + carry;
                *b = u8::try_from(s & 0xff).unwrap_or(0);
                carry = s >> 8;
            }
            if carry > 0 || out == m {
                out.fill(0);
            }
            out
        }

        fn cases() -> ProptestConfig {
            ProptestConfig {
                cases: std::env::var("PROPTEST_CASES")
                    .ok()
                    .and_then(|value| value.parse().ok())
                    .unwrap_or(512),
                ..ProptestConfig::default()
            }
        }

        proptest! {
            #![proptest_config(cases())]

            #[test]
            fn canonical_dispute_safety_completeness_and_replay_isolation(
                width in 1_usize..=32,
                inst1 in any::<[u8; 32]>(),
                inst2_xor in 1_u8..=255,
                m_raw in any::<[u8; 32]>(),
                a_raw in any::<[u8; 32]>(),
                b_raw in any::<[u8; 32]>(),
                c_raw in any::<[u8; 32]>(),
            ) {
                let secp = Secp256k1::new();
                let rec_kp = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[3; 32]).expect("sk"));
                let op_kp = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[5; 32]).expect("sk"));
                let rec_x = rec_kp.x_only_public_key().0.serialize();
                let op_x = op_kp.x_only_public_key().0.serialize();

                let m = canonical_modulus(width, &m_raw);
                let a = clamp_below(&a_raw, &m);
                let b = clamp_below(&b_raw, &m);
                let c = clamp_below(&c_raw, &m);

                let honest_d = {
                    let limbs = |bytes: &[u8]| -> [u64; 4] {
                        let mut out = [0_u64; 4];
                        for (idx, ch) in bytes.chunks(8).enumerate() {
                            let mut buf = [0_u8; 8];
                            buf[..ch.len()].copy_from_slice(ch);
                            out[idx] = u64::from_le_bytes(buf);
                        }
                        out
                    };
                    let la = limbs(&a);
                    let lb = limbs(&b);
                    let lc = limbs(&c);
                    let lm = limbs(&m);
                    let mut prod = [0_u64; 8];
                    for (i, &la_i) in la.iter().enumerate() {
                        let mut carry = 0_u128;
                        for (j, &lb_j) in lb.iter().enumerate() {
                            let cur = u128::from(prod[i + j]) + u128::from(la_i) * u128::from(lb_j) + carry;
                            prod[i + j] = u64::try_from(cur & u128::from(u64::MAX)).unwrap_or(0);
                            carry = cur >> 64;
                        }
                        prod[i + 4] = u64::try_from(carry).unwrap_or(0);
                    }
                    let mut add_c = 0_u128;
                    for (i, slot) in prod.iter_mut().enumerate() {
                        let c_i = lc.get(i).copied().map_or(0, u128::from);
                        let s = u128::from(*slot) + c_i + add_c;
                        *slot = u64::try_from(s & u128::from(u64::MAX)).unwrap_or(0);
                        add_c = s >> 64;
                    }
                    let mut rem = [0_u64; 5];
                    let mut mod5 = [0_u64; 5];
                    mod5[..4].copy_from_slice(&lm);
                    for limb in prod.iter().rev() {
                        for bit in (0..64_u32).rev() {
                            let mut sh_c = 0_u64;
                            for slot in &mut rem {
                                let next = *slot >> 63;
                                *slot = (*slot << 1) | sh_c;
                                sh_c = next;
                            }
                            rem[0] |= (*limb >> bit) & 1;
                            let ge = (0..5).rev().find(|&k| rem[k] != mod5[k]).is_none_or(|k| rem[k] > mod5[k]);
                            if ge {
                                let mut brw = 0_u64;
                                for (slot, &m_k) in rem.iter_mut().zip(&mod5) {
                                    let (d1, b1) = slot.overflowing_sub(m_k);
                                    let (d2, b2) = d1.overflowing_sub(brw);
                                    *slot = d2;
                                    brw = u64::from(b1) + u64::from(b2);
                                }
                            }
                        }
                    }
                    let mut raw = [0_u8; 32];
                    for (idx, limb) in rem[..4].iter().enumerate() {
                        raw[idx * 8..(idx + 1) * 8].copy_from_slice(&limb.to_le_bytes());
                    }
                    raw[..width].to_vec()
                };
                let false_d = increment_mod(&honest_d, &m);
                let std_flags = VerifyFlags::STANDARD.union(VerifyFlags::EXPERIMENTAL_MULADDMOD);

                let honest_vals = [a.clone(), b.clone(), c.clone(), honest_d];
                let honest_leaf = dispute_leaf(&inst1, &honest_vals, &m, 6, &rec_x, &op_x);
                let (honest_rec_tx, honest_prev) = build_claim_spend(0x11, &honest_leaf, &honest_vals, &rec_kp, true, 6);
                prop_assert_eq!(verify(&honest_rec_tx, &honest_prev, flags()), error(ScriptErrCode::EvalFalse));

                let forged_wit = [a.clone(), b.clone(), c.clone(), false_d.clone()];
                let (forged_tx, _) = build_claim_spend(0x11, &honest_leaf, &forged_wit, &rec_kp, true, 6);
                prop_assert_eq!(verify(&forged_tx, &honest_prev, flags()), error(ScriptErrCode::EqualVerify));

                let false_vals = [a, b, c, false_d];
                let false_leaf = dispute_leaf(&inst1, &false_vals, &m, 6, &rec_x, &op_x);
                let (false_rec_tx, false_prev) = build_claim_spend(0x22, &false_leaf, &false_vals, &rec_kp, true, 6);
                prop_assert_eq!(verify(&false_rec_tx, &false_prev, flags()), Ok(true));
                prop_assert_eq!(verify(&false_rec_tx, &false_prev, std_flags), Ok(true));

                let mut inst2 = inst1;
                inst2[0] ^= inst2_xor;
                let other_leaf = dispute_leaf(&inst2, &false_vals, &m, 6, &rec_x, &op_x);
                let (_, other_prev) = build_claim_spend(0x22, &other_leaf, &false_vals, &rec_kp, true, 6);
                prop_assert_eq!(
                    verify(&false_rec_tx, &other_prev, flags()),
                    error(ScriptErrCode::WitnessProgramMismatch)
                );

                let (mut replay_outpoint_tx, _) = build_claim_spend(0x33, &false_leaf, &false_vals, &rec_kp, true, 6);
                replay_outpoint_tx.inputs[0].witness = false_rec_tx.inputs[0].witness.clone();
                prop_assert_eq!(
                    verify(&replay_outpoint_tx, &false_prev, flags()),
                    error(ScriptErrCode::SchnorrSig)
                );
            }
        }
    }
}
