use bitcoin::{Transaction, TxOut};
use bitcoin_rs_primitives::{
    Amount as NativeAmount, OutPoint as NativeOutPoint, Script as NativeScript, Tx,
    TxOut as NativeTxOut,
};
use bitcoin_rs_script::{PreparedTransaction, VerifyFlags};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum NativeError {
    #[error("bitcoin-rs could not decode the transaction: {0}")]
    Decode(String),
    #[error("prevout count {prevouts} differs from input count {inputs}")]
    Prevouts { inputs: usize, prevouts: usize },
    #[error("bitcoin-rs rejected input {input}: {detail}")]
    Script { input: usize, detail: String },
}

/// Executes every input under the bitcoin-rs interpreter with standard flags,
/// which include the mandatory consensus flags.
pub fn verify_all_inputs(tx: &Transaction, prevouts: &[TxOut]) -> Result<usize, NativeError> {
    verify_with_flags(tx, prevouts, true)
}

/// `standard` selects bitcoin-rs's standard flags; otherwise only the
/// mandatory consensus flags apply.
pub fn verify_with_flags(
    tx: &Transaction,
    prevouts: &[TxOut],
    standard: bool,
) -> Result<usize, NativeError> {
    let flags = if standard {
        VerifyFlags::STANDARD
    } else {
        VerifyFlags::MANDATORY
    };
    if tx.input.len() != prevouts.len() {
        return Err(NativeError::Prevouts {
            inputs: tx.input.len(),
            prevouts: prevouts.len(),
        });
    }
    let native: Tx = bitcoin_rs_primitives::deserialize(&bitcoin::consensus::serialize(tx))
        .map_err(|error| NativeError::Decode(format!("{error:?}")))?;
    let rows: Vec<(NativeOutPoint, NativeTxOut)> = native
        .inputs
        .iter()
        .zip(prevouts)
        .map(|(input, prevout)| {
            (
                input.previous_output,
                NativeTxOut {
                    value: NativeAmount::from_sat(prevout.value.to_sat()),
                    script_pubkey: NativeScript::from_bytes(prevout.script_pubkey.to_bytes()),
                },
            )
        })
        .collect();
    let prepared = PreparedTransaction::new(&native, &rows)
        .map_err(|error| NativeError::Decode(format!("{error:?}")))?;
    for input in 0..native.inputs.len() {
        match prepared.verify_input(input, flags, None) {
            Ok(true) => {}
            Ok(false) => {
                return Err(NativeError::Script {
                    input,
                    detail: "script evaluated to false".to_owned(),
                });
            }
            Err(error) => {
                return Err(NativeError::Script {
                    input,
                    detail: format!("{error:?}"),
                });
            }
        }
    }
    Ok(native.inputs.len())
}
