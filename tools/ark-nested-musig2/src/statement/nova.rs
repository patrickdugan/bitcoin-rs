use std::path::Path;
use std::process::Command;
use std::time::Instant;

use bitcoin::hashes::Hash as _;
use bitcoin::hex::DisplayHex as _;
use bitcoin::{OutPoint, TxOut};
use serde::{Deserialize, Serialize};

use super::check::transaction_list;
use super::{ArkTransitionV1, Coverage, CoverageMethod, tagged_hash};
use crate::keys::KeyNetwork;
use crate::{Error, Result};

pub(super) const WITNESS_SCHEMA: &str = "ark-transition-nova-witness-v1";
pub(super) const PUBLIC_SCHEMA: &str = "ark-transition-nova-public-v1";
pub(super) const VERDICT_SCHEMA: &str = "ark-transition-nova-verdict-v1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum NovaItem {
    Input { spend_id: String, value_sat: u64 },
    Output { value_sat: u64, commit: String },
    Close { fee_sat: u64 },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NovaExpect {
    pub tx_count: u64,
    pub input_count: u64,
    pub sum_in_sat: u64,
    pub sum_out_sat: u64,
    pub sum_fee_sat: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NovaWitness {
    pub schema: String,
    pub statement_digest: String,
    pub fee_bound_sat: u64,
    pub items: Vec<NovaItem>,
    pub expect: NovaExpect,
}

pub fn spend_id(outpoint: &OutPoint) -> [u8; 32] {
    let mut data = Vec::with_capacity(36);
    data.extend_from_slice(&outpoint.txid.to_byte_array());
    data.extend_from_slice(&outpoint.vout.to_le_bytes());
    tagged_hash(b"ArkTransitionV1/spend", &data)
}

pub(super) fn output_commit(output: &TxOut) -> [u8; 32] {
    let mut data = Vec::with_capacity(8 + output.script_pubkey.len());
    data.extend_from_slice(&output.value.to_sat().to_le_bytes());
    data.extend_from_slice(output.script_pubkey.as_bytes());
    tagged_hash(b"ArkTransitionV1/output", &data)
}

/// Items follow the statement's graph order: the commitment, tree transactions
/// by index, then forfeits; each transaction lists its inputs, outputs and fee.
pub fn nova_witness(statement: &ArkTransitionV1) -> Result<NovaWitness> {
    let mut items = Vec::new();
    let mut expect = NovaExpect {
        tx_count: 0,
        input_count: 0,
        sum_in_sat: 0,
        sum_out_sat: 0,
        sum_fee_sat: 0,
    };
    for (tx, prevouts) in transaction_list(statement)? {
        let mut inputs = 0_u64;
        for (input, prevout) in tx.input.iter().zip(&prevouts) {
            let value = prevout.value.to_sat();
            inputs = crate::add_sat(inputs, value, "witness inputs")?;
            items.push(NovaItem::Input {
                spend_id: spend_id(&input.previous_output).to_lower_hex_string(),
                value_sat: value,
            });
            expect.input_count += 1;
        }
        let mut outputs = 0_u64;
        for output in &tx.output {
            outputs = crate::add_sat(outputs, output.value.to_sat(), "witness outputs")?;
            items.push(NovaItem::Output {
                value_sat: output.value.to_sat(),
                commit: output_commit(output).to_lower_hex_string(),
            });
        }
        let fee = crate::sub_sat(inputs, outputs, "witness fee")?;
        items.push(NovaItem::Close { fee_sat: fee });
        expect.tx_count += 1;
        expect.sum_in_sat = crate::add_sat(expect.sum_in_sat, inputs, "witness total in")?;
        expect.sum_out_sat = crate::add_sat(expect.sum_out_sat, outputs, "witness total out")?;
        expect.sum_fee_sat = crate::add_sat(expect.sum_fee_sat, fee, "witness total fee")?;
    }
    Ok(NovaWitness {
        schema: WITNESS_SCHEMA.to_owned(),
        statement_digest: statement.digest()?.to_lower_hex_string(),
        fee_bound_sat: statement.policy.fee_bound_sat,
        items,
        expect,
    })
}

#[derive(Clone, Debug, Deserialize)]
pub(super) struct NovaPublic {
    pub schema: String,
    pub statement_digest: String,
    pub fee_bound_sat: u64,
    pub steps: u64,
    pub vk_digest: String,
}

#[derive(Clone, Debug, Deserialize)]
struct NovaVerdict {
    schema: String,
    accepted: bool,
    vk_digest: String,
}

pub struct ProofEnvelope<'a> {
    pub expected_network: KeyNetwork,
    pub pinned_vk_digest: &'a str,
    pub public_json: &'a str,
    pub public_path: &'a Path,
    pub proof_path: &'a Path,
    pub witness_path: &'a Path,
    pub verifier: &'a Path,
}

#[derive(Clone, Debug, Serialize)]
pub struct VerificationResult {
    pub schema: &'static str,
    pub backend: &'static str,
    pub accepted: bool,
    pub rejected_at: Option<&'static str>,
    pub checks: Vec<(&'static str, bool)>,
    pub verify_seconds: f64,
    pub coverage: Vec<Coverage>,
}

fn rejected(stage: &'static str, checks: Vec<(&'static str, bool)>) -> VerificationResult {
    VerificationResult {
        schema: "ark-transition-proof-verification-v1",
        backend: "nova-ark-transition-v1",
        accepted: false,
        rejected_at: Some(stage),
        checks,
        verify_seconds: 0.0,
        coverage: Vec::new(),
    }
}

/// Envelope checks run before the cryptographic verifier: schema, network,
/// statement digest, public inputs, verifier key pin and transcript
/// completeness. Acceptance covers only the arithmetic relation over the
/// committed records; it never establishes script validity or inclusion.
pub fn verify_proof_envelope(
    statement: &ArkTransitionV1,
    envelope: &ProofEnvelope<'_>,
) -> Result<VerificationResult> {
    let mut checks = Vec::new();
    let public: NovaPublic = match sonic_rs::from_str(envelope.public_json) {
        Ok(public) => public,
        Err(_) => return Ok(rejected("public-input-decoding", checks)),
    };
    let schema_ok = public.schema == PUBLIC_SCHEMA;
    checks.push(("schema", schema_ok));
    if !schema_ok {
        return Ok(rejected("unrecognized-schema", checks));
    }
    let network_ok = statement.network == envelope.expected_network;
    checks.push(("network", network_ok));
    if !network_ok {
        return Ok(rejected("network", checks));
    }
    let digest = statement.digest()?.to_lower_hex_string();
    let digest_ok = public.statement_digest == digest;
    checks.push(("statement-digest", digest_ok));
    if !digest_ok {
        return Ok(rejected("statement-digest", checks));
    }
    let fee_ok = public.fee_bound_sat == statement.policy.fee_bound_sat;
    checks.push(("public-inputs", fee_ok));
    if !fee_ok {
        return Ok(rejected("public-inputs", checks));
    }
    let vk_ok = public.vk_digest == envelope.pinned_vk_digest;
    checks.push(("verifier-key-pin", vk_ok));
    if !vk_ok {
        return Ok(rejected("verifier-key", checks));
    }
    let expected = nova_witness(statement)?;
    let supplied: NovaWitness = match std::fs::read_to_string(envelope.witness_path)
        .ok()
        .and_then(|text| sonic_rs::from_str(&text).ok())
    {
        Some(witness) => witness,
        None => return Ok(rejected("transcript-decoding", checks)),
    };
    let steps_expected = crate::to_u64(expected.items.len(), "items")?
        .checked_add(expected.expect.input_count)
        .ok_or(Error::Value("steps"))?;
    let transcript_ok = supplied == expected && public.steps == steps_expected;
    checks.push(("complete-transcript", transcript_ok));
    if !transcript_ok {
        return Ok(rejected("incomplete-transcript", checks));
    }
    let started = Instant::now();
    let output = Command::new(envelope.verifier)
        .arg("verify")
        .arg("--public")
        .arg(envelope.public_path)
        .arg("--proof")
        .arg(envelope.proof_path)
        .arg("--witness")
        .arg(envelope.witness_path)
        .output()?;
    let verify_seconds = started.elapsed().as_secs_f64();
    let verdict: Option<NovaVerdict> = std::str::from_utf8(&output.stdout)
        .ok()
        .and_then(|text| sonic_rs::from_str(text).ok());
    let proof_ok = output.status.success()
        && verdict.as_ref().is_some_and(|verdict| {
            verdict.schema == VERDICT_SCHEMA
                && verdict.accepted
                && verdict.vk_digest == envelope.pinned_vk_digest
        });
    checks.push(("nova-verifier", proof_ok));
    if !proof_ok {
        return Ok(rejected("nova-verifier", checks));
    }
    let coverage = vec![
        Coverage {
            property: "per-transaction value conservation and fee bound",
            method: CoverageMethod::NovaProof,
            established: true,
            detail: "over the records committed by the proof's Poseidon chain".to_owned(),
        },
        Coverage {
            property: "single-use spend identities inside the committed graph",
            method: CoverageMethod::NovaProof,
            established: true,
            detail:
                "sorted-list and grand-product permutation argument over 248-bit spend identifiers"
                    .to_owned(),
        },
        Coverage {
            property: "records equal the statement's transactions",
            method: CoverageMethod::NativeStatementRules,
            established: true,
            detail: "the verifier recomputed the witness from the statement bytes".to_owned(),
        },
        Coverage {
            property: "signatures and script execution",
            method: CoverageMethod::NotCovered,
            established: false,
            detail: "the circuit computes no sighash and checks no signature".to_owned(),
        },
        Coverage {
            property: "transaction inclusion, canonical chain and UTXO non-spentness",
            method: CoverageMethod::NotCovered,
            established: false,
            detail: "no SPV, header or UTXO-set relation is in this circuit".to_owned(),
        },
    ];
    Ok(VerificationResult {
        schema: "ark-transition-proof-verification-v1",
        backend: "nova-ark-transition-v1",
        accepted: true,
        rejected_at: None,
        checks,
        verify_seconds,
        coverage,
    })
}
