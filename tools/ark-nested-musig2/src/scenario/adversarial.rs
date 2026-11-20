use std::collections::BTreeMap;

use bitcoin::hex::DisplayHex as _;
use bitcoin::{Amount, OutPoint, Sequence, Witness};
use bitcoin_rs_nested_musig2::PlainPublicKey;
use serde::Serialize;

use super::{ScenarioInput, Session, key_file};
use crate::client::{Intent, Observed, RoleSigner, verify_funding_observed};
use crate::keys::Participant;
use crate::native;
use crate::policy::{AggTree, Shape, SignerId};
use crate::remote::ProcessCosigner;
use crate::round::{Params, RoundSpec, SignedRound, build_round, output, relink, template};
use crate::scripts::key_path_script;
use crate::signing::{Cosigner, Fault, NonceRequest, PartialRequest, SignTarget, sign_tree_tx};
use crate::statement::{ArkTransitionV1, OldVtxo, Participant as Leaf, check_statement};
use crate::{Error, Result};

#[derive(Clone, Debug, Serialize)]
pub struct AdversarialCase {
    pub name: &'static str,
    pub category: &'static str,
    pub expected_stage: &'static str,
    pub observed_stage: String,
    pub rejected: bool,
    pub executed_against: Vec<&'static str>,
    pub detail: String,
}

fn stage_of<T>(result: &Result<T>) -> String {
    match result {
        Ok(_) => "accepted".to_owned(),
        Err(Error::Rejected(rejection)) => rejection.stage.clone(),
        Err(Error::Signing { stage, .. }) => (*stage).to_owned(),
        Err(other) => format!("error: {other}"),
    }
}

fn case<T>(
    name: &'static str,
    category: &'static str,
    expected: &'static str,
    result: &Result<T>,
    against: &[&'static str],
    detail: impl Into<String>,
) -> AdversarialCase {
    let observed_stage = stage_of(result);
    AdversarialCase {
        name,
        category,
        expected_stage: expected,
        rejected: observed_stage == expected,
        observed_stage,
        executed_against: against.to_vec(),
        detail: detail.into(),
    }
}

fn failed_rule(statement: &ArkTransitionV1) -> Result<String> {
    let report = check_statement(statement, &[])?;
    Ok(report
        .findings
        .iter()
        .find(|finding| !finding.ok)
        .map(|finding| finding.rule.to_owned())
        .unwrap_or_else(|| "accepted".to_owned()))
}

fn rule_case(
    name: &'static str,
    category: &'static str,
    expected: &'static str,
    statement: &ArkTransitionV1,
    detail: impl Into<String>,
) -> Result<AdversarialCase> {
    let observed_stage = failed_rule(statement)?;
    Ok(AdversarialCase {
        name,
        category,
        expected_stage: expected,
        rejected: observed_stage == expected,
        observed_stage,
        executed_against: vec!["own-ark-fixture", "native-statement-checker"],
        detail: detail.into(),
    })
}

fn session_label(digest: [u8; 32], index: u16, leaf: usize, attempt: u32) -> String {
    format!(
        "{}:t{index}:n{leaf}:a{attempt}",
        digest[..6].to_lower_hex_string()
    )
}

/// Coordinator and signer faults on a validated statement: substituted
/// partials and nonces, nonce replay after disclosure, session reuse, a wrong
/// aggregate key, and a signer process killed after releasing a nonce.
pub(super) fn signer_faults(
    statement: &ArkTransitionV1,
    session: &mut Session,
    owners: &BTreeMap<[u8; 33], SignerId>,
    intents: &BTreeMap<SignerId, Intent>,
    input: &ScenarioInput<'_>,
) -> Result<Vec<AdversarialCase>> {
    let digest = statement.digest()?;
    for (id, intent) in intents {
        if let Some(cosigner) = session.cosigners.get_mut(id) {
            cosigner.load(statement, intent)?;
        }
    }
    let mut cases = Vec::new();
    let against = ["own-ark-fixture", "in-process-signers", "process-signers"];
    let result = sign_tree_tx(
        statement,
        digest,
        0,
        &mut session.cosigners,
        owners,
        11,
        Fault::SubstitutePartial,
    );
    cases.push(case(
        "partial-signature-substitution",
        "signing",
        "partial-verify",
        &result,
        &against,
        "coordinator receives a forged partial from the first leaf",
    ));
    let result = sign_tree_tx(
        statement,
        digest,
        0,
        &mut session.cosigners,
        owners,
        12,
        Fault::SubstituteAggregateNonce,
    );
    cases.push(case(
        "aggregate-nonce-substitution",
        "signing",
        "partial-verify",
        &result,
        &against,
        "first leaf is sent a root aggregate nonce that differs from everyone else's",
    ));
    let result = sign_tree_tx(
        statement,
        digest,
        0,
        &mut session.cosigners,
        owners,
        13,
        Fault::ReplayNonce,
    );
    cases.push(case(
        "nonce-replay-after-partial-disclosure",
        "nonce",
        "client-nonce-unavailable",
        &result,
        &against,
        "coordinator asks the same session for a second partial signature",
    ));
    let tree = statement.cosigner_tree(statement.tree[0].lo, statement.tree[0].hi)?;
    let first_leaf = tree.leaves()[0];
    let leaf_key = tree.nodes[first_leaf].key.serialize();
    let reused_id = owners.get(&leaf_key).copied().unwrap_or(SignerId::Asp);
    let node_script = statement.node_script(statement.tree[0].lo, statement.tree[0].hi)?;
    let reused = session_label(digest, 0, first_leaf, 13);
    let result = session
        .cosigners
        .get_mut(&reused_id)
        .ok_or_else(|| Error::Construction("leaf signer absent".to_owned()))?
        .nonce(&NonceRequest {
            session: reused,
            statement: digest,
            target: SignTarget::Tree(0),
            aggregate_key: node_script.output_key()?,
        });
    cases.push(case(
        "session-identifier-reuse",
        "nonce",
        "client-session-reuse",
        &result,
        &["own-ark-fixture", "in-process-signers"],
        "a consumed session identifier requests a fresh nonce",
    ));
    let mut wrong_key = node_script.output_key()?;
    wrong_key[31] ^= 1;
    let result = session
        .cosigners
        .get_mut(&SignerId::Asp)
        .ok_or_else(|| Error::Construction("operator absent".to_owned()))?
        .nonce(&NonceRequest {
            session: "wrong-aggregate".to_owned(),
            statement: digest,
            target: SignTarget::Tree(0),
            aggregate_key: wrong_key,
        });
    cases.push(case(
        "wrong-aggregate-key",
        "signing",
        "client-aggregate-key",
        &result,
        &["own-ark-fixture", "in-process-signers"],
        "nonce requested for an aggregate key other than the policy's",
    ));

    let crash_user = input.remote_users.last().copied().unwrap_or(3);
    let crash_id = SignerId::User(crash_user);
    let path = key_file(input.dir, crash_id);
    let mut process = ProcessCosigner::spawn(input.binary, crash_id, &path, input.network)?;
    let intent = intents.get(&crash_id).cloned().unwrap_or_default();
    process.load(statement, &intent)?;
    let crash_tree = statement.cosigner_tree(statement.tree[0].lo, statement.tree[0].hi)?;
    let crash_leaf = crash_tree
        .leaves()
        .into_iter()
        .find(|leaf| owners.get(&crash_tree.nodes[*leaf].key.serialize()) == Some(&crash_id))
        .ok_or_else(|| Error::Construction("crash user is not in the root session".to_owned()))?;
    let crash_session = session_label(digest, 0, crash_leaf, 21);
    let before = process.pid;
    process.nonce(&NonceRequest {
        session: crash_session.clone(),
        statement: digest,
        target: SignTarget::Tree(0),
        aggregate_key: node_script.output_key()?,
    })?;
    process.crash()?;
    process.restart()?;
    let after = process.pid;
    let result = process.partial(&PartialRequest {
        session: crash_session,
        statement: digest,
        target: SignTarget::Tree(0),
        nonce_path: Vec::new(),
        key_path: Vec::new(),
        tweak: node_script.tweak_bytes()?,
    });
    cases.push(case(
        "crash-after-nonce-generation",
        "nonce",
        "client-nonce-unavailable",
        &result,
        &["own-ark-fixture", "process-signers"],
        format!("signer pid {before} killed after releasing a nonce; restarted as pid {after}"),
    ));
    process.load(statement, &intent)?;
    let original = session.cosigners.insert(crash_id, Box::new(process));
    let result = sign_tree_tx(
        statement,
        digest,
        0,
        &mut session.cosigners,
        owners,
        22,
        Fault::None,
    );
    let restarted_ok = result.is_ok();
    if let Some(original) = original {
        session.cosigners.insert(crash_id, original);
    }
    cases.push(AdversarialCase {
        name: "session-restart-with-fresh-nonces",
        category: "nonce",
        expected_stage: "accepted",
        observed_stage: stage_of(&result),
        rejected: restarted_ok,
        executed_against: vec!["own-ark-fixture", "process-signers"],
        detail: "a new attempt with fresh nonces from the restarted process completes and verifies"
            .to_owned(),
    });
    Ok(cases)
}

pub(super) fn statement_cases(
    r1: &ArkTransitionV1,
    params: &Params,
    asp: PlainPublicKey,
    asp_key: &Participant,
    owners: &[[u8; 33]],
    observed: &[Observed],
    input: &ScenarioInput<'_>,
) -> Result<Vec<AdversarialCase>> {
    let mut cases = Vec::new();
    let boarding_a = r1.funding[0].outpoint;
    let mutate = |change: &dyn Fn(&mut Observed)| -> Vec<Observed> {
        observed
            .iter()
            .cloned()
            .map(|mut utxo| {
                if utxo.outpoint == boarding_a {
                    change(&mut utxo);
                }
                utxo
            })
            .collect()
    };
    let user_a = PlainPublicKey::from_slice(&owners[0])?;
    let user_only = key_path_script(crate::keys::xonly_of(user_a)?);
    let wrong_script = mutate(&|utxo| utxo.script_pubkey = user_only.clone());
    let result = verify_funding_observed(r1, &wrong_script, None);
    cases.push(case("boarding-funding-script-mismatch", "boarding-regression", "funding-observed-script", &result, &["own-ark-fixture", "observed-utxo-set"], "the funding output on chain pays the user's key alone, as in the 2026 Bark board exploit class"));
    let short = mutate(&|utxo| utxo.amount_sat -= 1_000);
    let result = verify_funding_observed(r1, &short, None);
    cases.push(case(
        "boarding-funding-value-short",
        "boarding-regression",
        "funding-observed-value",
        &result,
        &["own-ark-fixture", "observed-utxo-set"],
        "the funding output on chain holds 1,000 sat less than claimed",
    ));
    let unconfirmed = mutate(&|utxo| utxo.confirmations = 0);
    let result = verify_funding_observed(r1, &unconfirmed, None);
    cases.push(case(
        "boarding-funding-unconfirmed",
        "boarding-regression",
        "funding-observed-unconfirmed",
        &result,
        &["own-ark-fixture", "observed-utxo-set"],
        "funding output seen only in the mempool",
    ));

    let asp_script = key_path_script(asp_key.xonly()?);
    let mut server_batch = r1.clone();
    server_batch.commitment.output[0].script_pubkey = asp_script.clone();
    relink(&mut server_batch);
    cases.push(rule_case(
        "server-controlled-batch-output",
        "boarding-regression",
        "batch-output-script",
        &server_batch,
        "batch output pays the operator's key; a client that signs anyway loses its VTXO",
    )?);
    let batch_value = server_batch.commitment.output[0].value.to_sat();
    let mut steal = template(
        vec![crate::round::input(
            OutPoint::new(server_batch.commitment.compute_txid(), 0),
            Sequence::MAX,
        )],
        vec![output(batch_value - 1_000, asp_script.clone())],
    );
    let digest = crate::signing::sighash(&crate::signing::SpendTarget {
        tx: steal.clone(),
        prevouts: vec![output(batch_value, asp_script.clone())],
        input: 0,
        leaf: None,
    })?;
    steal.input[0].witness = Witness::from_slice(&[asp_key.sign_key_path(digest)?.to_vec()]);
    let theft = native::verify_all_inputs(&steal, &[output(batch_value, asp_script.clone())]);
    cases.push(AdversarialCase {
        name: "server-controlled-batch-theft-path",
        category: "boarding-regression",
        expected_stage: "accepted",
        observed_stage: match &theft {
            Ok(_) => "accepted".to_owned(),
            Err(error) => error.to_string(),
        },
        rejected: theft.is_ok(),
        executed_against: vec!["own-ark-fixture", "bitcoin-rs-script"],
        detail: "with the unchecked statement the operator alone can spend the batch output; a non-validating client would have authorized this".to_owned(),
    });

    let mut underfunded = r1.clone();
    underfunded.commitment.output[0].value =
        Amount::from_sat(underfunded.commitment.output[0].value.to_sat() - 1_000);
    relink(&mut underfunded);
    cases.push(rule_case(
        "batch-output-underfunded",
        "boarding-regression",
        "value-conservation",
        &underfunded,
        "batch output 1,000 sat below the tree it must fund",
    )?);

    let mut leaves: Vec<Leaf> = r1.participants.clone();
    leaves[0].amount_sat += 5_000;
    leaves[1].amount_sat -= 5_000;
    let spec = |participants: Vec<Leaf>, boarding: Vec<crate::statement::Funding>| RoundSpec {
        round: r1.round,
        sequence: r1.sequence,
        previous: r1.previous,
        participants,
        boarding,
        liquidity: r1.funding[r1.funding.len() - 1].clone(),
        old_vtxos: Vec::new(),
        coop_exits: Vec::new(),
        anchor: r1.anchor.clone(),
    };
    let boarding: Vec<_> = r1.funding[..r1.funding.len() - 1].to_vec();
    let equivocated = build_round(params, asp, &spec(leaves, boarding.clone()))?;
    let user_b = SignerId::User(1);
    let mut signer_b = RoleSigner::new(
        user_b,
        Participant::load(&key_file(input.dir, user_b), input.network)?,
    )?;
    let intent_b = Intent {
        receive: vec![r1.participants[1].amount_sat],
        boarding: vec![(r1.funding[1].outpoint, r1.funding[1].amount_sat)],
        observed: observed.to_vec(),
        ..Intent::default()
    };
    let result = signer_b.load(&equivocated, &intent_b);
    let same_prevout =
        equivocated.tree[0].tx.input[0].previous_output == r1.tree[0].tx.input[0].previous_output;
    cases.push(case(
        "asp-equivocation",
        "equivocation",
        "client-vtxo-amount",
        &result,
        &["own-ark-fixture", "in-process-signers"],
        format!(
            "operator shows a second tree moving 5,000 sat from B to A; digests differ ({} vs {}); both root transactions spend the same batch outpoint: {same_prevout}",
            r1.digest()?.to_lower_hex_string(),
            equivocated.digest()?.to_lower_hex_string()
        ),
    ));

    let omitted = build_round(
        params,
        asp,
        &spec(r1.participants[..3].to_vec(), boarding.clone()),
    )?;
    let user_d = SignerId::User(3);
    let mut signer_d = RoleSigner::new(
        user_d,
        Participant::load(&key_file(input.dir, user_d), input.network)?,
    )?;
    let intent_d = Intent {
        receive: vec![r1.participants[3].amount_sat],
        boarding: vec![(r1.funding[3].outpoint, r1.funding[3].amount_sat)],
        observed: observed.to_vec(),
        ..Intent::default()
    };
    let result = signer_d.load(&omitted, &intent_d);
    cases.push(case(
        "omitted-participant",
        "batch-composition",
        "client-vtxo-missing",
        &result,
        &["own-ark-fixture", "in-process-signers"],
        "D's boarding input is spent but D has no VTXO leaf",
    ));

    let keys: Vec<(SignerId, PlainPublicKey)> = r1.owner_keys(0, 4)?;
    let reordered = vec![keys[0], keys[2], keys[1], keys[3]];
    let nested_a = AggTree::build(Shape::Nested, &keys, asp)?
        .root_context()?
        .xonly_key();
    let nested_b = AggTree::build(Shape::Nested, &reordered, asp)?
        .root_context()?
        .xonly_key();
    let flat_a = AggTree::build(Shape::Flat, &keys, asp)?
        .root_context()?
        .xonly_key();
    let flat_b = AggTree::build(Shape::Flat, &reordered, asp)?
        .root_context()?
        .xonly_key();
    cases.push(AdversarialCase {
        name: "reordered-participants",
        category: "batch-composition",
        expected_stage: "nested-key-changes",
        observed_stage: if nested_a != nested_b && flat_a == flat_b {
            "nested-key-changes".to_owned()
        } else {
            format!("nested changed {} flat changed {}", nested_a != nested_b, flat_a != flat_b)
        },
        rejected: nested_a != nested_b && flat_a == flat_b,
        executed_against: vec!["own-ark-fixture"],
        detail: "swapping B and C across subgroups changes the nested aggregate key and statement; the flat BIP327 key is order invariant".to_owned(),
    });
    let _ = owners;
    Ok(cases)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn round2_cases(
    r2: &ArkTransitionV1,
    signed: &SignedRound,
    params: &Params,
    asp: PlainPublicKey,
    _asp_key: &Participant,
    owners: &[[u8; 33]],
    observed: &[Observed],
    input: &ScenarioInput<'_>,
) -> Result<Vec<AdversarialCase>> {
    let mut cases = Vec::new();
    let mut altered = r2.clone();
    let user_c_script = key_path_script(crate::keys::xonly_of(PlainPublicKey::from_slice(
        &owners[2],
    )?)?);
    let vout = usize::try_from(altered.coop_exits[0].vout).map_err(|_| Error::Range("vout"))?;
    altered.commitment.output[vout].script_pubkey = user_c_script.clone();
    altered.coop_exits[0].script_pubkey = user_c_script;
    relink(&mut altered);
    let user_b = SignerId::User(1);
    let mut signer_b = RoleSigner::new(
        user_b,
        Participant::load(&key_file(input.dir, user_b), input.network)?,
    )?;
    let intent_b = Intent {
        forfeit: r2
            .old_vtxos
            .iter()
            .filter(|old| old.owner == owners[1])
            .map(|old| (old.outpoint, old.amount_sat))
            .collect(),
        coop_exit: vec![(
            r2.coop_exits[0].script_pubkey.clone(),
            r2.coop_exits[0].amount_sat,
        )],
        observed: observed.to_vec(),
        ..Intent::default()
    };
    let result = signer_b.load(&altered, &intent_b);
    cases.push(case(
        "payout-altered-before-authorization",
        "payout",
        "client-coop-exit",
        &result,
        &["own-ark-fixture", "in-process-signers"],
        "operator redirects B's cooperative exit before B signs its forfeit",
    ));
    let mut tampered = signed.commitment.clone();
    tampered.output[vout].script_pubkey = key_path_script(crate::keys::xonly_of(asp)?);
    let result = native::verify_all_inputs(&tampered, &r2.commitment_prevouts());
    cases.push(AdversarialCase {
        name: "payout-altered-after-authorization",
        category: "payout",
        expected_stage: "script-verification",
        observed_stage: match &result {
            Ok(_) => "accepted".to_owned(),
            Err(_) => "script-verification".to_owned(),
        },
        rejected: result.is_err(),
        executed_against: vec!["own-ark-fixture", "bitcoin-rs-script"],
        detail: "the signed commitment's sighash covers every output; the node plays repeat this on bitcoin-rs and Core".to_owned(),
    });
    let duplicate = build_round(
        params,
        asp,
        &RoundSpec {
            round: r2.round,
            sequence: r2.sequence,
            previous: r2.previous,
            participants: r2.participants.clone(),
            boarding: Vec::new(),
            liquidity: r2.funding[0].clone(),
            old_vtxos: vec![r2.old_vtxos[0].clone(), r2.old_vtxos[0].clone()],
            coop_exits: Vec::new(),
            anchor: r2.anchor.clone(),
        },
    )?;
    cases.push(rule_case(
        "duplicate-vtxo-forfeit",
        "double-spend",
        "forfeit-binding",
        &duplicate,
        "the same old VTXO is forfeited against two connectors",
    )?);
    let _: Option<&OldVtxo> = None;
    Ok(cases)
}
