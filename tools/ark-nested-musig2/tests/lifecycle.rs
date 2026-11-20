use bitcoin::secp256k1::{Message, SECP256K1, XOnlyPublicKey, schnorr};
use bitcoin_rs_ark_nested_musig2::client::{Intent, RoleSigner};
use bitcoin_rs_ark_nested_musig2::native::verify_all_inputs;
use bitcoin_rs_ark_nested_musig2::policy::{Shape, SignerId};
use bitcoin_rs_ark_nested_musig2::round::{exit_tx, sign_round};
use bitcoin_rs_ark_nested_musig2::scripts::key_path_script;
use bitcoin_rs_ark_nested_musig2::signing::{
    Cosigner, Fault, SignTarget, sighash, sign_tree_tx, spend_target,
};

use super::support::{TestError, rejection_stage, round};

// Every tree signature must satisfy libsecp256k1's BIP340 verification for the
// BIP341 output key, and every input must pass the bitcoin-rs interpreter.
#[test]
fn nested_and_flat_rounds_produce_valid_key_path_spends() -> Result<(), TestError> {
    for shape in [Shape::Nested, Shape::Flat] {
        let mut fixture = round(8, shape)?;
        let signed = sign_round(
            &fixture.statement,
            &mut fixture.cosigners,
            &fixture.intents,
            &fixture.owners,
            0,
        )?;
        verify_all_inputs(&signed.commitment, &fixture.statement.commitment_prevouts()).map_err(
            |error| TestError::Unexpected {
                expected: "valid commitment".to_owned(),
                observed: error.to_string(),
            },
        )?;
        for (index, tx) in signed.tree.iter().enumerate() {
            let node = &fixture.statement.tree[index];
            let key = XOnlyPublicKey::from_slice(
                &fixture
                    .statement
                    .node_script(node.lo, node.hi)?
                    .output_key()?,
            )?;
            let digest = sighash(&spend_target(
                &fixture.statement,
                SignTarget::Tree(u16::try_from(index).unwrap_or(0)),
            )?)?;
            let signature = schnorr::Signature::from_slice(&tx.input[0].witness.to_vec()[0])?;
            SECP256K1.verify_schnorr(&signature, &Message::from_digest(digest), &key)?;
            verify_all_inputs(tx, &[fixture.statement.tree_prevout(index)?]).map_err(|error| {
                TestError::Unexpected {
                    expected: "valid tree tx".to_owned(),
                    observed: error.to_string(),
                }
            })?;
        }
    }
    Ok(())
}

#[test]
fn nested_root_has_lower_fan_in_and_more_hops_than_flat() -> Result<(), TestError> {
    let mut nested = round(16, Shape::Nested)?;
    let mut flat = round(16, Shape::Flat)?;
    let nested_signed = sign_round(
        &nested.statement,
        &mut nested.cosigners,
        &nested.intents,
        &nested.owners,
        0,
    )?;
    let flat_signed = sign_round(
        &flat.statement,
        &mut flat.cosigners,
        &flat.intents,
        &flat.owners,
        0,
    )?;
    assert_eq!(nested_signed.traffic.root_fan_in, 3);
    assert_eq!(flat_signed.traffic.root_fan_in, 17);
    assert!(nested_signed.traffic.max_depth > flat_signed.traffic.max_depth);
    assert_eq!(
        nested_signed.commitment.vsize(),
        flat_signed.commitment.vsize()
    );
    Ok(())
}

#[test]
fn unilateral_exit_needs_only_the_owner_after_the_delay() -> Result<(), TestError> {
    let mut fixture = round(4, Shape::Nested)?;
    sign_round(
        &fixture.statement,
        &mut fixture.cosigners,
        &fixture.intents,
        &fixture.owners,
        0,
    )?;
    let vtxos = fixture.statement.vtxo_outpoints()?;
    let script = fixture.statement.vtxo_script(3)?;
    let owner = &fixture.users[3];
    let amount = fixture.statement.participants[3].amount_sat;
    let tx = exit_tx(
        &script,
        vtxos[3],
        amount,
        key_path_script(owner.xonly()?),
        2_000,
        owner,
    )?;
    assert_eq!(
        tx.input[0].sequence.to_consensus_u32(),
        u32::from(fixture.params.exit_delay)
    );
    assert_eq!(tx.input[0].witness.len(), 3);
    verify_all_inputs(
        &tx,
        &[bitcoin_rs_ark_nested_musig2::round::output(
            amount,
            script.script_pubkey()?,
        )],
    )
    .map_err(|error| TestError::Unexpected {
        expected: "valid exit".to_owned(),
        observed: error.to_string(),
    })?;
    Ok(())
}

#[test]
fn signers_refuse_reuse_substitution_and_unfunded_promises() -> Result<(), TestError> {
    let mut fixture = round(4, Shape::Nested)?;
    let digest = fixture.statement.digest()?;
    for (id, intent) in &fixture.intents {
        if let Some(cosigner) = fixture.cosigners.get_mut(id) {
            cosigner.load(&fixture.statement, intent)?;
        }
    }
    let replay = sign_tree_tx(
        &fixture.statement,
        digest,
        0,
        &mut fixture.cosigners,
        &fixture.owners,
        1,
        Fault::ReplayNonce,
    );
    assert_eq!(rejection_stage(replay), "client-nonce-unavailable");
    let partial = sign_tree_tx(
        &fixture.statement,
        digest,
        0,
        &mut fixture.cosigners,
        &fixture.owners,
        2,
        Fault::SubstitutePartial,
    );
    assert_eq!(rejection_stage(partial), "partial-verify");
    let nonce = sign_tree_tx(
        &fixture.statement,
        digest,
        0,
        &mut fixture.cosigners,
        &fixture.owners,
        3,
        Fault::SubstituteAggregateNonce,
    );
    assert_eq!(rejection_stage(nonce), "partial-verify");
    let clean = sign_tree_tx(
        &fixture.statement,
        digest,
        0,
        &mut fixture.cosigners,
        &fixture.owners,
        4,
        Fault::None,
    );
    assert_eq!(rejection_stage(clean), "accepted");

    let user = SignerId::User(1);
    let mut greedy = RoleSigner::new(
        user,
        bitcoin_rs_ark_nested_musig2::keys::Participant::from_seed(
            &super::support::SEED,
            "user",
            1,
        )?,
    )?;
    let mut intent: Intent = fixture.intents.get(&user).cloned().unwrap_or_default();
    intent.receive = vec![intent.receive.first().copied().unwrap_or(0) + 1];
    assert_eq!(
        rejection_stage(greedy.load(&fixture.statement, &intent)),
        "client-vtxo-amount"
    );
    let mut lying = fixture
        .intents
        .get(&SignerId::Asp)
        .cloned()
        .unwrap_or_default();
    lying.observed[0].amount_sat -= 1;
    let mut asp = RoleSigner::new(
        SignerId::Asp,
        bitcoin_rs_ark_nested_musig2::keys::Participant::from_seed(
            &super::support::SEED,
            "asp",
            0,
        )?,
    )?;
    assert_eq!(
        rejection_stage(asp.load(&fixture.statement, &lying)),
        "funding-observed-value"
    );
    Ok(())
}

#[test]
fn boarding_and_forfeit_signatures_wait_for_the_signed_tree() -> Result<(), TestError> {
    let fixture = round(4, Shape::Nested)?;
    let mut signer = RoleSigner::new(
        SignerId::User(0),
        bitcoin_rs_ark_nested_musig2::keys::Participant::from_seed(
            &super::support::SEED,
            "user",
            0,
        )?,
    )?;
    let intent = fixture
        .intents
        .get(&SignerId::User(0))
        .cloned()
        .unwrap_or_default();
    let digest = signer.load(&fixture.statement, &intent)?;
    let early = signer.schnorr(&bitcoin_rs_ark_nested_musig2::signing::SchnorrRequest {
        statement: digest,
        target: SignTarget::Boarding(0),
    });
    assert_eq!(rejection_stage(early), "client-tree-unsigned");
    Ok(())
}
