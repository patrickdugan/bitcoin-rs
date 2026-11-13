#![expect(clippy::expect_used)]

use bitcoin_rs_primitives::{Network, Sighash, SighashCache};

use super::*;

fn run(
    budget: Option<i64>,
    empty: bool,
    second_check: bool,
) -> (Result<(), ScriptError>, Option<i64>) {
    let tx = Network::Regtest.genesis_block().txs[0].clone();
    let prevouts = vec![tx.outputs[0].clone()];
    let cache = SighashCache::new(&tx);
    let leaf = Hash256::default();
    let candidate = cache
        .taproot_signature_hash_with_key_version(
            0,
            &prevouts,
            None,
            Some((leaf, u32::MAX)),
            Sighash::Default,
            2,
        )
        .expect("budget fixture digest");
    let checker = TxSignatureChecker::new(&tx, 0, prevouts[0].value, &prevouts, &cache, None);
    let mut stack = Stack::new();
    let bytes: &[u8] = if empty {
        &[]
    } else {
        candidate.as_byte_array()
    };
    push_bytes(&mut stack, bytes).expect("candidate");
    let mut script = push_data(&TXCOMMIT_KEY);
    script.push(OP_CHECKSIG);
    if second_check {
        script.extend_from_slice(&[OP_DROP, OP_PUSHNUM_1, OP_PUSHNUM_1, OP_CHECKSIG]);
    }
    let mut left = budget;
    let result = eval_script(
        &mut stack,
        &script,
        VerifyFlags::MANDATORY.union(VerifyFlags::EXPERIMENTAL_TXCOMMIT),
        &checker,
        SigVersion::Tapscript,
        &mut left,
        Some(&leaf),
    );
    (result, left)
}

#[test]
fn txcommit_uses_exactly_fifty_units_and_requires_a_counter() {
    assert_eq!(run(Some(50), false, false), (Ok(()), Some(0)));
    for budget in [None, Some(49)] {
        assert_eq!(
            run(budget, false, false).0,
            Err(ScriptError::Invalid {
                code: ScriptErrCode::TapscriptValidationWeight
            })
        );
    }
    assert_eq!(run(Some(0), true, false), (Ok(()), Some(0)));
}

#[test]
fn txcommit_and_other_signature_checks_share_one_counter() {
    assert_eq!(run(Some(100), false, true), (Ok(()), Some(0)));
    assert_eq!(
        run(Some(99), false, true).0,
        Err(ScriptError::Invalid {
            code: ScriptErrCode::TapscriptValidationWeight
        })
    );
}
