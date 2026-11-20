use std::collections::{BTreeMap, BTreeSet};

use bitcoin::hashes::Hash as _;
use bitcoin::hex::DisplayHex as _;
use bitcoin::{OutPoint, Transaction, TxOut};
use serde::Serialize;

use super::{ArkTransitionV1, FundingKind, split_point, strip_witness};
use crate::native;
use crate::scripts::key_path_script;
use crate::{Result, to_u32};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum CoverageMethod {
    BitcoinConsensusNodeAcceptance,
    NativeScriptEngine,
    NativeStatementRules,
    NodeObservation,
    NovaProof,
    NotCovered,
}

#[derive(Clone, Debug, Serialize)]
pub struct Coverage {
    pub property: &'static str,
    pub method: CoverageMethod,
    pub established: bool,
    pub detail: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct Finding {
    pub rule: &'static str,
    pub ok: bool,
    pub detail: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct CheckReport {
    pub schema: &'static str,
    pub statement_digest: String,
    pub accepted: bool,
    pub findings: Vec<Finding>,
    pub coverage: Vec<Coverage>,
}

struct Rules {
    findings: Vec<Finding>,
}

impl Rules {
    fn record(&mut self, rule: &'static str, ok: bool, detail: impl Into<String>) {
        self.findings.push(Finding {
            rule,
            ok,
            detail: detail.into(),
        });
    }

    fn passed(&self, rule: &str) -> bool {
        self.findings
            .iter()
            .filter(|finding| finding.rule == rule)
            .all(|finding| finding.ok)
    }
}

fn sum(outputs: &[TxOut]) -> Option<u64> {
    outputs.iter().try_fold(0_u64, |total, output| {
        total.checked_add(output.value.to_sat())
    })
}

/// Recomputes every rule from the statement bytes alone. Signed transactions,
/// when supplied, are matched to templates by txid and every input is executed
/// by the bitcoin-rs script interpreter under standard flags.
pub fn check_statement(statement: &ArkTransitionV1, signed: &[Transaction]) -> Result<CheckReport> {
    let digest = statement.digest()?;
    let mut rules = Rules {
        findings: Vec::new(),
    };
    let genesis = bitcoin::blockdata::constants::genesis_block(statement.network.bitcoin())
        .block_hash()
        .to_byte_array();
    rules.record(
        "network-genesis",
        genesis == statement.genesis,
        statement.network.name(),
    );
    let policy = &statement.policy;
    rules.record(
        "policy-bounds",
        policy.exit_delay > 0
            && policy.boarding_delay > 0
            && policy.batch_expiry > policy.exit_delay
            && policy.fee_bound_sat > 0,
        format!(
            "exit {} boarding {} expiry {} fee bound {}",
            policy.exit_delay, policy.boarding_delay, policy.batch_expiry, policy.fee_bound_sat
        ),
    );
    let count = statement.participants.len();
    rules.record(
        "participants",
        count >= 2 && statement.participants.iter().all(|p| p.amount_sat >= 330),
        format!("{count} VTXO leaves"),
    );
    let asp_script = key_path_script(statement.asp_xonly()?);
    let commitment_inputs: Vec<OutPoint> = statement
        .commitment
        .input
        .iter()
        .map(|input| input.previous_output)
        .collect();
    let funding_outpoints: Vec<OutPoint> = statement.funding.iter().map(|f| f.outpoint).collect();
    rules.record(
        "funding-matches-commitment",
        commitment_inputs == funding_outpoints,
        format!("{} commitment inputs", commitment_inputs.len()),
    );
    for funding in &statement.funding {
        let expected = match &funding.kind {
            FundingKind::Boarding { owner } => statement.boarding_script(owner)?.script_pubkey()?,
            FundingKind::Liquidity => asp_script.clone(),
        };
        rules.record(
            "funding-script",
            expected == funding.script_pubkey,
            funding.outpoint.to_string(),
        );
    }
    let count_u16 = crate::to_u16(count, "participants")?;
    let batch = usize::try_from(statement.batch_vout)
        .ok()
        .and_then(|vout| statement.commitment.output.get(vout));
    let batch_ok = match (batch, count >= 2) {
        (Some(output), true) => output.script_pubkey == statement.range_script(0, count_u16)?,
        _ => false,
    };
    rules.record(
        "batch-output-script",
        batch_ok,
        format!("vout {}", statement.batch_vout),
    );
    let mut expected_ranges = BTreeSet::new();
    if count >= 2 {
        let mut pending = vec![(0_u16, count_u16)];
        while let Some((lo, hi)) = pending.pop() {
            if hi - lo >= 2 {
                expected_ranges.insert((lo, hi));
                let mid = split_point(lo, hi);
                pending.push((lo, mid));
                pending.push((mid, hi));
            }
        }
    }
    let actual_ranges: BTreeSet<(u16, u16)> = statement.tree.iter().map(|n| (n.lo, n.hi)).collect();
    rules.record(
        "tree-ranges",
        actual_ranges == expected_ranges && actual_ranges.len() == statement.tree.len(),
        format!("{} tree transactions", statement.tree.len()),
    );
    let mut spends: BTreeMap<OutPoint, usize> = BTreeMap::new();
    let mut conservation_ok = true;
    let mut fee_ok = true;
    let mut transactions: Vec<(&Transaction, Vec<TxOut>)> = Vec::new();
    transactions.push((&statement.commitment, statement.commitment_prevouts()));
    for (index, node) in statement.tree.iter().enumerate() {
        let prevout = statement.tree_prevout(index)?;
        let parent_txid = match node.parent {
            None => statement.commitment.compute_txid(),
            Some(parent) => statement.tree[usize::from(parent)].tx.compute_txid(),
        };
        let parent_range_ok = match node.parent {
            None => {
                node.lo == 0 && node.hi == count_u16 && node.parent_vout == statement.batch_vout
            }
            Some(parent) => statement.tree.get(usize::from(parent)).is_some_and(|p| {
                let mid = split_point(p.lo, p.hi);
                (node.parent_vout == 0 && (node.lo, node.hi) == (p.lo, mid))
                    || (node.parent_vout == 1 && (node.lo, node.hi) == (mid, p.hi))
            }),
        };
        let mid = split_point(node.lo, node.hi);
        let shape_ok = node.tx.input.len() == 1
            && node.tx.input[0].previous_output == OutPoint::new(parent_txid, node.parent_vout)
            && node.tx.output.len() == 2
            && node.tx.output[0].script_pubkey == statement.range_script(node.lo, mid)?
            && node.tx.output[1].script_pubkey == statement.range_script(mid, node.hi)?;
        rules.record(
            "tree-transaction",
            parent_range_ok && shape_ok,
            format!("node {index} covers {}..{}", node.lo, node.hi),
        );
        for (vout, (lo, hi)) in [(node.lo, mid), (mid, node.hi)].into_iter().enumerate() {
            if hi - lo == 1 {
                let amount = statement.participants[usize::from(lo)].amount_sat;
                rules.record(
                    "vtxo-amount",
                    node.tx.output.get(vout).map(|o| o.value.to_sat()) == Some(amount),
                    format!("participant {lo}"),
                );
            }
        }
        transactions.push((&node.tx, vec![prevout]));
    }
    let asp_connector_ok = statement.connectors.iter().all(|vout| {
        usize::try_from(*vout)
            .ok()
            .and_then(|vout| statement.commitment.output.get(vout))
            .is_some_and(|o| {
                o.script_pubkey == asp_script && o.value.to_sat() == policy.connector_sat
            })
    });
    rules.record(
        "connectors",
        asp_connector_ok,
        format!("{} connector outputs", statement.connectors.len()),
    );
    for exit in &statement.coop_exits {
        let ok = usize::try_from(exit.vout)
            .ok()
            .and_then(|vout| statement.commitment.output.get(vout))
            .is_some_and(|o| {
                o.script_pubkey == exit.script_pubkey && o.value.to_sat() == exit.amount_sat
            });
        rules.record("cooperative-exit", ok, format!("vout {}", exit.vout));
    }
    let mut olds = BTreeSet::new();
    let mut connectors = BTreeSet::new();
    let commitment_txid = statement.commitment.compute_txid();
    for (index, forfeit) in statement.forfeits.iter().enumerate() {
        let prevouts = statement.forfeit_prevouts(index)?;
        let old = &statement.old_vtxos[usize::from(forfeit.old)];
        let connector_vout = statement.connectors[usize::from(forfeit.connector)];
        let expected_old = statement.owner_vtxo_script(&old.owner)?.script_pubkey()?;
        let ok = forfeit.tx.input.len() == 2
            && forfeit.tx.input[0].previous_output
                == OutPoint::new(commitment_txid, connector_vout)
            && forfeit.tx.input[1].previous_output == old.outpoint
            && forfeit.tx.output.len() == 1
            && forfeit.tx.output[0].script_pubkey == asp_script
            && old.script_pubkey == expected_old
            && olds.insert(forfeit.old)
            && connectors.insert(forfeit.connector);
        rules.record("forfeit-binding", ok, format!("forfeit {index}"));
        transactions.push((&forfeit.tx, prevouts));
    }
    rules.record(
        "forfeit-coverage",
        olds.len() == statement.old_vtxos.len() && connectors.len() == statement.connectors.len(),
        format!(
            "{} old VTXOs, {} connectors",
            statement.old_vtxos.len(),
            statement.connectors.len()
        ),
    );
    for (position, (tx, prevouts)) in transactions.iter().enumerate() {
        let inputs = sum(prevouts);
        let outputs = sum(&tx.output);
        match (inputs, outputs) {
            (Some(inputs), Some(outputs)) if inputs >= outputs => {
                if inputs - outputs > policy.fee_bound_sat {
                    fee_ok = false;
                }
            }
            _ => conservation_ok = false,
        }
        for input in &tx.input {
            if let Some(previous) = spends.insert(input.previous_output, position) {
                rules.record(
                    "single-use-spends",
                    false,
                    format!(
                        "{} spent by transactions {previous} and {position}",
                        input.previous_output
                    ),
                );
            }
        }
    }
    rules.record(
        "value-conservation",
        conservation_ok,
        format!("{} transactions", transactions.len()),
    );
    rules.record(
        "fee-bound",
        fee_ok,
        format!("bound {} sat", policy.fee_bound_sat),
    );
    rules.record(
        "single-use-spends",
        true,
        format!("{} distinct spends", spends.len()),
    );
    let mut verified_inputs = 0_usize;
    let mut matched = 0_usize;
    for signed_tx in signed {
        let template = strip_witness(signed_tx);
        let found = transactions
            .iter()
            .find(|(tx, _)| tx.compute_txid() == template.compute_txid() && **tx == template);
        match found {
            None => rules.record(
                "signed-matches-template",
                false,
                format!("{} is not a statement template", signed_tx.compute_txid()),
            ),
            Some((_, prevouts)) => {
                matched += 1;
                let outcome = native::verify_all_inputs(signed_tx, prevouts);
                let fee = sum(prevouts)
                    .zip(sum(&signed_tx.output))
                    .map(|(i, o)| i.saturating_sub(o));
                let vsize = crate::to_u64(signed_tx.vsize(), "vsize")?;
                let floor = vsize
                    .saturating_mul(policy.fee_rate_sat_per_kvb)
                    .div_ceil(1000);
                rules.record(
                    "fee-floor",
                    fee.is_some_and(|fee| fee >= floor),
                    format!("{} vsize {vsize} floor {floor}", signed_tx.compute_txid()),
                );
                match outcome {
                    Ok(count) => {
                        verified_inputs += count;
                        rules.record(
                            "script-verification",
                            true,
                            format!("{} inputs of {}", count, signed_tx.compute_txid()),
                        );
                    }
                    Err(error) => rules.record(
                        "script-verification",
                        false,
                        format!("{}: {error}", signed_tx.compute_txid()),
                    ),
                }
            }
        }
    }
    let accepted = rules.findings.iter().all(|finding| finding.ok);
    let structural = [
        "tree-ranges",
        "tree-transaction",
        "batch-output-script",
        "funding-script",
        "connectors",
    ]
    .iter()
    .all(|rule| rules.passed(rule));
    let coverage = vec![
        Coverage {
            property: "funding outputs exist, are confirmed and unspent",
            method: CoverageMethod::NodeObservation,
            established: false,
            detail: "established only by the harness's gettxout lookups on bitcoin-rs and Core at the anchor; the statement records the anchor".to_owned(),
        },
        Coverage {
            property: "tree structure, script templates and cosigner policy keys",
            method: CoverageMethod::NativeStatementRules,
            established: structural,
            detail: "recomputed from participants, policy and the BIP341 derivation".to_owned(),
        },
        Coverage {
            property: "per-transaction value conservation and fee bound",
            method: CoverageMethod::NativeStatementRules,
            established: rules.passed("value-conservation") && rules.passed("fee-bound"),
            detail: format!("{} transactions", transactions.len()),
        },
        Coverage {
            property: "single-use spend identities inside the committed graph",
            method: CoverageMethod::NativeStatementRules,
            established: rules.passed("single-use-spends"),
            detail: format!("{} spends", spends.len()),
        },
        Coverage {
            property: "signatures and script execution",
            method: CoverageMethod::NativeScriptEngine,
            established: !signed.is_empty() && matched == signed.len() && rules.passed("script-verification"),
            detail: format!("{verified_inputs} inputs verified by bitcoin-rs-script; node acceptance is recorded separately by the harness"),
        },
        Coverage {
            property: "transaction inclusion and canonical-chain acceptance",
            method: CoverageMethod::NotCovered,
            established: false,
            detail: "outside the statement checker; the harness records block hashes from both nodes".to_owned(),
        },
    ];
    Ok(CheckReport {
        schema: "ark-transition-check-v1",
        statement_digest: digest.to_lower_hex_string(),
        accepted,
        findings: rules.findings,
        coverage,
    })
}

pub(crate) fn transaction_list(
    statement: &ArkTransitionV1,
) -> Result<Vec<(Transaction, Vec<TxOut>)>> {
    let mut list = vec![(
        statement.commitment.clone(),
        statement.commitment_prevouts(),
    )];
    for index in 0..statement.tree.len() {
        list.push((
            statement.tree[index].tx.clone(),
            vec![statement.tree_prevout(index)?],
        ));
    }
    for index in 0..statement.forfeits.len() {
        list.push((
            statement.forfeits[index].tx.clone(),
            statement.forfeit_prevouts(index)?,
        ));
    }
    let _ = to_u32(list.len(), "transaction count")?;
    Ok(list)
}
