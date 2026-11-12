//! Line-oriented script verification oracle for differential campaigns.
//!
//! Each stdin line is
//! `<FLAG,NAMES|NONE> <input-index> <tx-hex> <prevout-count> (<value-sats> <spk-hex|->)*`.
//! Each stdout line is `OK`, `FALSE`, `ERR <SCRIPT_ERR name>`, or `BAD <reason>`.
//! The prevouts must cover every input in order (BIP341 needs all of them).
//!
//! Research tooling only: it reads untrusted fixtures and never touches a
//! node, wallet or network.

use std::io::{self, BufRead, Write};

use bitcoin_rs_primitives::{Amount, Script, TxOut, deserialize};
use bitcoin_rs_script::{PreparedTransaction, ScriptError, VerifyFlags};

fn decode_hex(text: &str) -> Option<Vec<u8>> {
    if text == "-" {
        return Some(Vec::new());
    }
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| {
            text.get(i..i + 2)
                .and_then(|pair| u8::from_str_radix(pair, 16).ok())
        })
        .collect()
}

fn evaluate(line: &str) -> String {
    let fields: Vec<&str> = line.split_whitespace().collect();
    let [flags, index, tx_hex, count, rest @ ..] = fields.as_slice() else {
        return "BAD fields".to_owned();
    };
    let flags = match VerifyFlags::from_core_names(&flags.replace('|', ",")) {
        Ok(flags) => flags,
        Err(error) => return format!("BAD flags {error:?}"),
    };
    let Ok(index) = index.parse::<usize>() else {
        return "BAD index".to_owned();
    };
    let Some(raw) = decode_hex(tx_hex) else {
        return "BAD tx-hex".to_owned();
    };
    let Ok(tx) = deserialize::<bitcoin_rs_primitives::Tx>(&raw) else {
        return "BAD tx-decode".to_owned();
    };
    let Ok(count) = count.parse::<usize>() else {
        return "BAD count".to_owned();
    };
    if rest.len() != count * 2 || count != tx.inputs.len() {
        return "BAD prevout-count".to_owned();
    }
    let mut prevouts = Vec::with_capacity(count);
    for (pair, input) in rest.as_chunks::<2>().0.iter().zip(&tx.inputs) {
        let [value, spk] = pair;
        let (Ok(value), Some(spk)) = (value.parse::<u64>(), decode_hex(spk)) else {
            return "BAD prevout".to_owned();
        };
        prevouts.push((
            input.previous_output,
            TxOut {
                value: Amount::from_sat(value),
                script_pubkey: Script::from_bytes(spk),
            },
        ));
    }
    let prepared = match PreparedTransaction::new(&tx, &prevouts) {
        Ok(prepared) => prepared,
        Err(error) => return format!("BAD prevouts {error:?}"),
    };
    match prepared.verify_input(index, flags, None) {
        Ok(true) => "OK".to_owned(),
        Ok(false) => "FALSE".to_owned(),
        Err(ScriptError::Invalid { code }) => format!("ERR {code}"),
        Err(other) => format!("BAD {other:?}"),
    }
}

fn main() -> io::Result<()> {
    let stdin = io::stdin();
    let mut out = io::BufWriter::new(io::stdout().lock());
    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        writeln!(out, "{}", evaluate(&line))?;
        out.flush()?;
    }
    Ok(())
}
