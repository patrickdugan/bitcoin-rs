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
}
