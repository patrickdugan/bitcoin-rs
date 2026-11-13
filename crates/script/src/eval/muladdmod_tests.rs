#![expect(clippy::expect_used, reason = "exact interpreter budget fixtures")]

use super::*;
use bitcoin_rs_primitives::{Network, SighashCache};

fn run(budget: Option<i64>, script: &[u8]) -> (Result<(), ScriptError>, Option<i64>, Stack) {
    let tx = Network::Regtest.genesis_block().txs[0].clone();
    let prevouts = vec![tx.outputs[0].clone()];
    let cache = SighashCache::new(&tx);
    let checker = TxSignatureChecker::new(&tx, 0, prevouts[0].value, &prevouts, &cache, None);
    let mut left = budget;
    let mut stack = Stack::new();
    for data in [[7], [11], [3], [17]] {
        push_bytes(&mut stack, &data).expect("fixture stack");
    }
    let result = eval_script(
        &mut stack,
        script,
        VerifyFlags::MANDATORY.union(VerifyFlags::EXPERIMENTAL_MULADDMOD),
        &checker,
        SigVersion::Tapscript,
        &mut left,
        None,
    );
    (result, left, stack)
}

#[test]
fn exact_budget_is_debited_and_missing_budget_fails() {
    let (result, left, stack) = run(Some(50), &[OP_MULADDMOD_EXPERIMENTAL]);
    assert_eq!(result, Ok(()));
    assert_eq!(left, Some(0));
    assert_eq!(stack.len(), 1);
    assert_eq!(item_bytes(stack.peek().expect("result")).as_ref(), &[12]);
    for budget in [None, Some(49), Some(i64::MIN)] {
        assert_eq!(
            run(budget, &[OP_MULADDMOD_EXPERIMENTAL]).0,
            Err(ScriptError::Invalid {
                code: ScriptErrCode::TapscriptValidationWeight
            })
        );
    }
}

#[test]
fn signatures_and_arithmetic_debit_one_counter() {
    let script = [
        OP_MULADDMOD_EXPERIMENTAL,
        OP_DROP,
        OP_PUSHNUM_1,
        OP_PUSHNUM_1,
        OP_CHECKSIG,
    ];
    assert_eq!(run(Some(100), &script).0, Ok(()));
    assert_eq!(run(Some(100), &script).1, Some(0));
    assert_eq!(
        run(Some(99), &script).0,
        Err(ScriptError::Invalid {
            code: ScriptErrCode::TapscriptValidationWeight
        })
    );
}

#[test]
fn three_item_stack_underflow_precedes_budget_exhaustion() {
    let script = [OP_DROP, OP_MULADDMOD_EXPERIMENTAL];
    let (result, left, stack) = run(Some(49), &script);
    assert_eq!(
        result,
        Err(ScriptError::Invalid {
            code: ScriptErrCode::InvalidStackOperation
        })
    );
    assert_eq!(left, Some(49));
    assert_eq!(stack.len(), 3);
}
