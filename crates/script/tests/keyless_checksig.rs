#![expect(clippy::expect_used)]

#[cfg(feature = "experimental-keyless-checksig")]
use bitcoin::hashes::HashEngine as _;
use bitcoin::hashes::{Hash as _, sha256};
use bitcoin::secp256k1::{Secp256k1, XOnlyPublicKey};
#[cfg(feature = "experimental-keyless-checksig")]
use bitcoin::sighash::{Annex, Prevouts, SighashCache, TapSighashType};
#[cfg(feature = "experimental-keyless-checksig")]
use bitcoin::taproot::TapLeafHash;
use bitcoin::taproot::{LeafVersion, TaprootBuilder};
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};
use bitcoin_rs_script::{
    Interpreter, PreparedTransaction, ScriptErrCode, ScriptError, VerifyFlags,
};

fn selector() -> Vec<u8> {
    let mut key = vec![2];
    key.extend_from_slice(
        sha256::Hash::hash(b"BIPSpace/Keyless-CHECKSIG/TXCOMMIT-draft").as_byte_array(),
    );
    key
}

fn selected_script(prefix: &[u8], opcode: u8, suffix: &[u8]) -> Vec<u8> {
    let mut script = prefix.to_vec();
    script.extend_from_slice(&bitcoin_rs_script::push_data(&selector()));
    script.push(opcode);
    script.extend_from_slice(suffix);
    script
}

struct Spend {
    tx: Transaction,
    prevouts: Vec<TxOut>,
    script: ScriptBuf,
    control: Vec<u8>,
    annex: Option<Vec<u8>>,
    index: usize,
}

impl Spend {
    fn new(script: Vec<u8>) -> Self {
        let script = ScriptBuf::from_bytes(script);
        let nums = XOnlyPublicKey::from_slice(&[
            0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9,
            0x7a, 0x5e, 0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a,
            0xce, 0x80, 0x3a, 0xc0,
        ])
        .expect("BIP341 NUMS point");
        let info = TaprootBuilder::new()
            .add_leaf(0, script.clone())
            .expect("single research leaf")
            .finalize(&Secp256k1::verification_only(), nums)
            .expect("complete tree");
        let control = info
            .control_block(&(script.clone(), LeafVersion::TapScript))
            .expect("committed script")
            .serialize();
        let prevouts = vec![
            TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: ScriptBuf::new_p2tr_tweaked(info.output_key()),
            },
            TxOut {
                value: Amount::from_sat(20_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            },
        ];
        let tx = Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: [31, 32]
                .map(|seed| TxIn {
                    previous_output: OutPoint::new(Txid::from_byte_array([seed; 32]), 0),
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                })
                .to_vec(),
            output: vec![
                TxOut {
                    value: Amount::from_sat(90_000),
                    script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
                },
                TxOut {
                    value: Amount::from_sat(29_000),
                    script_pubkey: ScriptBuf::from_bytes(vec![0x52]),
                },
            ],
        };
        Self {
            tx,
            prevouts,
            script,
            control,
            annex: None,
            index: 0,
        }
    }

    fn witness(&mut self, mut stack: Vec<Vec<u8>>) {
        stack.push(self.script.to_bytes());
        stack.push(self.control.clone());
        if let Some(annex) = &self.annex {
            stack.push(annex.clone());
        }
        self.tx.input[self.index].witness = Witness::from_slice(&stack);
    }

    #[cfg(feature = "experimental-keyless-checksig")]
    fn digest(&self, key_version: u8, codesep: u32) -> Vec<u8> {
        let mut message = Vec::new();
        SighashCache::new(&self.tx)
            .taproot_encode_signing_data_to(
                &mut message,
                self.index,
                &Prevouts::All(&self.prevouts),
                self.annex
                    .as_deref()
                    .map(|annex| Annex::new(annex).expect("annex tag")),
                Some((
                    TapLeafHash::from_script(&self.script, LeafVersion::TapScript),
                    codesep,
                )),
                TapSighashType::Default,
            )
            .expect("rust-bitcoin BIP341 message");
        let version_position = message.len() - 5;
        assert_eq!(message[version_position], 0);
        message[version_position] = key_version;
        let tag = sha256::Hash::hash(b"TapSighash");
        let mut engine = sha256::Hash::engine();
        engine.input(tag.as_byte_array());
        engine.input(tag.as_byte_array());
        engine.input(&message);
        sha256::Hash::from_engine(engine).to_byte_array().to_vec()
    }

    fn verify(&self, flags: VerifyFlags) -> Result<bool, ScriptError> {
        let tx: bitcoin_rs_primitives::Tx =
            bitcoin_rs_primitives::deserialize(&bitcoin::consensus::serialize(&self.tx))
                .expect("native transaction");
        let prevouts: Vec<bitcoin_rs_primitives::TxOut> = self
            .prevouts
            .iter()
            .map(|prevout| bitcoin_rs_primitives::TxOut {
                value: bitcoin_rs_primitives::Amount::from_sat(prevout.value.to_sat()),
                script_pubkey: bitcoin_rs_primitives::Script::from_bytes(
                    prevout.script_pubkey.to_bytes(),
                ),
            })
            .collect();
        let rows: Vec<_> = tx
            .inputs
            .iter()
            .zip(&prevouts)
            .map(|(input, prevout)| (input.previous_output, prevout.clone()))
            .collect();
        let result = PreparedTransaction::new(&tx, &rows)
            .expect("complete ordered prevouts")
            .verify_input(self.index, flags, None);
        assert_eq!(
            result,
            Interpreter.execute_with_prevouts(
                &prevouts[self.index].script_pubkey,
                &tx.inputs[self.index].script_sig,
                &tx.inputs[self.index].witness,
                flags,
                &prevouts,
                &tx,
                self.index,
            )
        );
        result
    }
}

fn error(code: ScriptErrCode) -> Result<bool, ScriptError> {
    Err(ScriptError::Invalid { code })
}

#[test]
fn research_flags_are_explicit_and_separate_from_deployed_defaults() {
    for (name, flag) in [
        ("EXPERIMENTAL_TXCOMMIT", VerifyFlags::EXPERIMENTAL_TXCOMMIT),
        ("EXPERIMENTAL_OP_CAT", VerifyFlags::EXPERIMENTAL_OP_CAT),
    ] {
        assert_eq!(VerifyFlags::from_core_names(name), Ok(flag));
        assert!(!VerifyFlags::MANDATORY.contains(flag));
        assert!(!VerifyFlags::STANDARD.contains(flag));
    }
}

// VAL-02
#[test]
fn inactive_selector_keeps_bip342_unknown_key_behavior() {
    let mut spend = Spend::new(selected_script(&[], 0xac, &[]));
    spend.witness(vec![vec![7]]);
    assert_eq!(spend.verify(VerifyFlags::MANDATORY), Ok(true));
    assert_eq!(
        spend.verify(VerifyFlags::STANDARD),
        error(ScriptErrCode::DiscourageUpgradablePubkeyType)
    );
}

#[test]
#[cfg(not(feature = "experimental-keyless-checksig"))]
fn txcommit_flag_requires_compiled_support() {
    let mut spend = Spend::new(vec![0x50]);
    spend.witness(vec![]);
    assert_eq!(
        spend.verify(VerifyFlags::MANDATORY.union(VerifyFlags::EXPERIMENTAL_TXCOMMIT)),
        error(ScriptErrCode::ExperimentalDisabled)
    );
}

#[test]
#[cfg(not(feature = "experimental-op-cat"))]
fn cat_flag_requires_its_independent_compiled_support() {
    let mut spend = Spend::new(vec![0x50]);
    spend.witness(vec![]);
    assert_eq!(
        spend.verify(VerifyFlags::MANDATORY.union(VerifyFlags::EXPERIMENTAL_OP_CAT)),
        error(ScriptErrCode::ExperimentalDisabled)
    );
}

#[cfg(feature = "experimental-keyless-checksig")]
mod txcommit {
    use super::*;

    fn flags() -> VerifyFlags {
        VerifyFlags::STANDARD.union(VerifyFlags::EXPERIMENTAL_TXCOMMIT)
    }

    // VAL-02
    #[test]
    fn each_signature_opcode_accepts_the_independent_transaction_commitment() {
        for script in [
            selected_script(&[], 0xac, &[]),
            selected_script(&[], 0xad, &[0x51]),
            selected_script(&[0x00], 0xba, &[0x51, 0x9c]),
        ] {
            let mut spend = Spend::new(script);
            spend.witness(vec![spend.digest(2, u32::MAX)]);
            assert_eq!(spend.verify(flags()), Ok(true));
        }
    }

    #[test]
    fn nonempty_mismatch_and_wrong_sizes_abort_in_all_three_opcodes() {
        for script in [
            selected_script(&[], 0xac, &[0x91]),
            selected_script(&[], 0xad, &[0x51]),
            selected_script(&[0x00], 0xba, &[0x00, 0x9c]),
        ] {
            let mut spend = Spend::new(script);
            let mut wrong = spend.digest(2, u32::MAX);
            wrong[0] ^= 1;
            spend.witness(vec![wrong]);
            assert_eq!(
                spend.verify(flags()),
                error(ScriptErrCode::TxCommitMismatch)
            );
            for length in [1, 31, 33, 64, 65, 520] {
                spend.witness(vec![vec![1; length]]);
                assert_eq!(spend.verify(flags()), error(ScriptErrCode::TxCommitSize));
            }
        }
    }

    #[test]
    fn empty_candidate_keeps_each_opcode_result() {
        for (script, expected) in [
            (selected_script(&[], 0xac, &[0x91]), Ok(true)),
            (
                selected_script(&[], 0xad, &[0x51]),
                error(ScriptErrCode::CheckSigVerify),
            ),
            (selected_script(&[0x57], 0xba, &[0x57, 0x9c]), Ok(true)),
        ] {
            let mut spend = Spend::new(script);
            spend.witness(vec![vec![]]);
            assert_eq!(spend.verify(flags()), expected);
        }
    }

    #[test]
    fn commitment_binds_every_input_component_and_ordered_output() {
        for field in 0..12 {
            let mut spend = Spend::new(selected_script(&[], 0xac, &[]));
            spend.witness(vec![spend.digest(2, u32::MAX)]);
            assert_eq!(spend.verify(flags()), Ok(true));
            match field {
                0 => spend.tx.version = bitcoin::transaction::Version(3),
                1 => spend.tx.lock_time = bitcoin::absolute::LockTime::from_consensus(1),
                2 => spend.tx.input[0].previous_output.vout = 1,
                3 => spend.tx.input[1].previous_output.txid = Txid::from_byte_array([99; 32]),
                4 => spend.tx.input[0].sequence = Sequence(1),
                5 => spend.tx.input[1].sequence = Sequence(2),
                6 => spend.prevouts[0].value = Amount::from_sat(99_999),
                7 => spend.prevouts[1].value = Amount::from_sat(19_999),
                8 => spend.prevouts[1].script_pubkey = ScriptBuf::from_bytes(vec![0x52]),
                9 => spend.tx.output[0].value = Amount::from_sat(89_999),
                10 => spend.tx.output[1].script_pubkey = ScriptBuf::from_bytes(vec![0x53]),
                _ => spend.tx.output.swap(0, 1),
            }
            assert_eq!(
                spend.verify(flags()),
                error(ScriptErrCode::TxCommitMismatch),
                "field {field}"
            );
        }
    }

    #[test]
    fn a_candidate_cannot_be_replayed_at_a_different_input_index() {
        let mut spend = Spend::new(selected_script(&[], 0xac, &[]));
        spend.prevouts[1] = spend.prevouts[0].clone();
        let first = spend.digest(2, u32::MAX);
        spend.index = 1;
        spend.witness(vec![first]);
        assert_eq!(
            spend.verify(flags()),
            error(ScriptErrCode::TxCommitMismatch)
        );
        spend.witness(vec![spend.digest(2, u32::MAX)]);
        assert_eq!(spend.verify(flags()), Ok(true));
    }

    // VAL-02
    #[test]
    fn annex_key_version_and_decoded_codeseparator_position_are_bound() {
        let prefix = [0x03, 0x01, 0x02, 0x03, 0x75, 0xab, 0x00, 0x63, 0xab, 0x68];
        for annex in [None, Some(vec![0x50, 0x41, 0x42])] {
            let mut spend = Spend::new(selected_script(&prefix, 0xac, &[]));
            spend.annex = annex;
            spend.witness(vec![spend.digest(2, 2)]);
            assert_eq!(spend.verify(flags()), Ok(true));
            for (version, separator) in [(0, 2), (1, 2), (2, 5), (2, u32::MAX)] {
                spend.witness(vec![spend.digest(version, separator)]);
                assert_eq!(
                    spend.verify(flags()),
                    error(ScriptErrCode::TxCommitMismatch)
                );
            }
            let valid = spend.digest(2, 2);
            spend.annex = Some(vec![0x50, 0x99]);
            spend.witness(vec![valid]);
            assert_eq!(
                spend.verify(flags()),
                error(ScriptErrCode::TxCommitMismatch)
            );
        }
    }

    #[test]
    fn unmatched_unknown_types_keep_their_consensus_and_policy_rules() {
        let mut script = selected_script(&[], 0xac, &[]);
        script[10] ^= 1;
        let mut spend = Spend::new(script);
        spend.witness(vec![vec![1]]);
        assert_eq!(
            spend.verify(VerifyFlags::MANDATORY.union(VerifyFlags::EXPERIMENTAL_TXCOMMIT)),
            Ok(true)
        );
        assert_eq!(
            spend.verify(flags()),
            error(ScriptErrCode::DiscourageUpgradablePubkeyType)
        );
    }

    // VAL-02
    #[test]
    fn active_txcommit_preserves_ordinary_schnorr_opcode_results() {
        use bitcoin_rs_e2e::helpers::taproot;

        let prevout = TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: taproot::codeseparator_funding_script(),
        };
        let outpoint = OutPoint::new(Txid::from_byte_array([17; 32]), 0);
        for case in taproot::codeseparator_cases(outpoint, &prevout) {
            let spend = Spend {
                tx: case.tx,
                prevouts: vec![prevout.clone()],
                script: ScriptBuf::new(),
                control: vec![],
                annex: None,
                index: 0,
            };
            assert_eq!(
                spend.verify(flags()).is_ok(),
                case.accepted,
                "{}",
                case.name
            );
        }
    }

    #[test]
    fn legacy_and_witness_v0_do_not_use_txcommit() {
        for witness_v0 in [false, true] {
            let script = selected_script(&[], 0xac, &[]);
            let mut spend = Spend::new(script.clone());
            if witness_v0 {
                spend.prevouts[0].script_pubkey = spend.script.to_p2wsh();
                spend.tx.input[0].witness = Witness::from_slice(&[vec![1; 32], script]);
            } else {
                spend.prevouts[0].script_pubkey = spend.script.clone();
                spend.tx.input[0].script_sig =
                    ScriptBuf::from_bytes(bitcoin_rs_script::push_data(&[1; 32]));
            }
            let active = spend.verify(flags());
            assert_eq!(active, spend.verify(VerifyFlags::STANDARD));
            assert!(active.is_err());
        }
    }
}

#[cfg(feature = "experimental-op-cat")]
mod cat {
    use super::*;

    fn flags() -> VerifyFlags {
        VerifyFlags::STANDARD.union(VerifyFlags::EXPERIMENTAL_OP_CAT)
    }

    #[test]
    fn concatenation_is_tapscript_only_and_preserves_byte_order() {
        let mut spend = Spend::new(vec![0x7e, 0x02, 0x12, 0x34, 0x87]);
        spend.witness(vec![vec![0x12], vec![0x34]]);
        assert_eq!(spend.verify(flags()), Ok(true));
        spend.witness(vec![vec![0x34], vec![0x12]]);
        assert_eq!(spend.verify(flags()), error(ScriptErrCode::EvalFalse));
        assert_eq!(spend.verify(VerifyFlags::MANDATORY), Ok(true));
        assert_eq!(
            spend.verify(VerifyFlags::STANDARD),
            error(ScriptErrCode::DiscourageOpSuccess)
        );
        for witness_v0 in [false, true] {
            let mut legacy = Spend::new(vec![0x00, 0x63, 0x7e, 0x68, 0x51]);
            if witness_v0 {
                legacy.prevouts[0].script_pubkey = legacy.script.to_p2wsh();
                legacy.tx.input[0].witness = Witness::from_slice(&[legacy.script.to_bytes()]);
            } else {
                legacy.prevouts[0].script_pubkey = legacy.script.clone();
            }
            assert_eq!(legacy.verify(flags()), error(ScriptErrCode::DisabledOpcode));
        }
    }

    #[test]
    fn cat_checks_stack_underflow_and_the_520_byte_boundary() {
        let mut spend = Spend::new(vec![0x7e, 0x75, 0x51]);
        for stack in [vec![], vec![vec![1]]] {
            spend.witness(stack);
            assert_eq!(
                spend.verify(flags()),
                error(ScriptErrCode::InvalidStackOperation)
            );
        }
        for (left, right, expected) in [
            (260, 260, Ok(true)),
            (520, 0, Ok(true)),
            (520, 1, error(ScriptErrCode::PushSize)),
        ] {
            spend.witness(vec![vec![1; left], vec![2; right]]);
            assert_eq!(spend.verify(flags()), expected);
        }
    }

    #[test]
    fn skipped_cat_and_other_success_opcodes_keep_their_rules() {
        let mut skipped = Spend::new(vec![0x00, 0x63, 0x7e, 0x68, 0x51]);
        skipped.witness(vec![]);
        assert_eq!(skipped.verify(flags()), Ok(true));
        let mut other_success = Spend::new(vec![0x50, 0x7e]);
        other_success.witness(vec![vec![1; 521]]);
        assert_eq!(
            other_success.verify(VerifyFlags::MANDATORY.union(VerifyFlags::EXPERIMENTAL_OP_CAT)),
            Ok(true)
        );
        assert_eq!(
            other_success.verify(flags()),
            error(ScriptErrCode::DiscourageOpSuccess)
        );
        let mut cat_only = Spend::new(vec![0x7e]);
        cat_only.witness(vec![vec![1; 521]]);
        assert_eq!(cat_only.verify(flags()), error(ScriptErrCode::PushSize));
    }
}
