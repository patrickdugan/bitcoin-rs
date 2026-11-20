use bitcoin::secp256k1::{Message, Secp256k1, XOnlyPublicKey, schnorr::Signature};
use bitcoin_rs_nested_musig2::{
    AggregateNonce, PartialSignature, PlainPublicKey, PublicNonce, RootSessionContext,
    aggregate_intermediate, aggregate_root, apply_tweaks, import_secret_nonce, key_agg, nonce_agg,
    nonce_agg_ext, nonce_gen_with_randomness, partial_sig_verify, public_key, schnorr_verify, sign,
};

use crate::support::{TestError, bytes, case, fixed, fixtures, keys, session, tweaks};

#[test]
fn bip327_optional_nonce_inputs_match_reference() -> Result<(), TestError> {
    for case in fixtures()?.nonce_generation {
        let secret = case.secret_key.as_deref().map(fixed::<32>).transpose()?;
        let aggregate = case.aggregate_key.as_deref().map(fixed::<32>).transpose()?;
        let message = case.message.as_deref().map(bytes).transpose()?;
        let extra = case.extra_input.as_deref().map(bytes).transpose()?;
        let (_, public_nonce) = nonce_gen_with_randomness(
            fixed(&case.randomness)?,
            secret.as_ref(),
            PlainPublicKey::from_slice(&bytes(&case.public_key)?)?,
            aggregate,
            message.as_deref(),
            extra.as_deref(),
        )?;
        assert_eq!(
            public_nonce.serialize(),
            fixed::<66>(&case.public_nonce)?,
            "{}",
            case.name
        );
    }
    Ok(())
}

#[test]
fn reference_sessions_match_leaf_and_root_signatures() -> Result<(), TestError> {
    let fixtures = fixtures()?;
    let mut flat_sessions = 0;
    let mut nested_sessions = 0;
    for case in &fixtures.sessions {
        let untweaked = key_agg(&keys(&case.root_public_keys)?)?;
        assert_eq!(
            untweaked.plain_key().serialize(),
            fixed::<33>(&case.untweaked_key)?,
            "{}",
            case.name
        );
        let aggregate = apply_tweaks(&untweaked, &tweaks(case)?)?;
        assert_eq!(
            aggregate.plain_key().serialize(),
            fixed::<33>(&case.aggregate_key)?,
            "{}",
            case.name
        );
        assert_eq!(
            aggregate.xonly_key(),
            fixed::<32>(&case.aggregate_xonly)?,
            "{}",
            case.name
        );
        let message = bytes(&case.message)?;
        let extra_input = bytes(&case.extra_input)?;
        for leaf in &case.leaves {
            let secret = fixed::<32>(&leaf.secret_key)?;
            let public = public_key(&secret)?;
            assert_eq!(
                public.serialize(),
                fixed::<33>(&leaf.public_key)?,
                "{} {}",
                case.name,
                leaf.id
            );
            let (nonce, public_nonce) = nonce_gen_with_randomness(
                fixed(&leaf.randomness)?,
                Some(&secret),
                public,
                Some(aggregate.xonly_key()),
                Some(&message),
                Some(&extra_input),
            )?;
            assert_eq!(
                public_nonce.serialize(),
                fixed::<66>(&leaf.public_nonce)?,
                "{} {}",
                case.name,
                leaf.id
            );
            let context = session(case, &leaf.nonce_path, &leaf.key_path)?;
            let partial = sign(nonce, &secret, &context)?;
            assert_eq!(
                partial.serialize(),
                fixed::<32>(&leaf.partial_signature)?,
                "{} {}",
                case.name,
                leaf.id
            );
            assert!(
                partial_sig_verify(partial, public_nonce, public, &context)?,
                "{} {}",
                case.name,
                leaf.id
            );
            let imported = import_secret_nonce(&bytes(&leaf.secret_nonce)?)?;
            assert_eq!(
                sign(imported, &secret, &context)?.serialize(),
                fixed::<32>(&leaf.partial_signature)?,
                "{} {} imported",
                case.name,
                leaf.id
            );
        }
        let root = case
            .nodes
            .iter()
            .find(|node| node.id == "root")
            .ok_or(TestError::Missing("root node"))?;
        let partials = root
            .child_partials
            .iter()
            .map(|value| Ok(PartialSignature::from_slice(&bytes(value)?)?))
            .collect::<Result<Vec<_>, TestError>>()?;
        let root_context = RootSessionContext {
            aggregate_nonce: AggregateNonce::from_slice(&bytes(&case.root_nonce)?)?,
            pubkeys: keys(&case.root_public_keys)?,
            tweaks: tweaks(case)?,
            message: message.clone(),
        };
        let signature = aggregate_root(&partials, &root_context)?;
        assert_eq!(signature, fixed::<64>(&case.signature)?, "{}", case.name);
        assert!(
            schnorr_verify(&message, aggregate.xonly_key(), &signature),
            "{}",
            case.name
        );
        if message.len() == 32 {
            let digest = Message::from_digest(fixed(&case.message)?);
            let key = XOnlyPublicKey::from_slice(&aggregate.xonly_key())?;
            let sig = Signature::from_slice(&signature)?;
            Secp256k1::verification_only().verify_schnorr(&sig, &digest, &key)?;
        }
        if case.bip327_exact {
            flat_sessions += 1;
        } else {
            nested_sessions += 1;
        }
    }
    assert_eq!(flat_sessions, 9);
    assert_eq!(nested_sessions, 5);
    Ok(())
}

#[test]
fn reference_nodes_preserve_sorting_duplicates_and_nested_binding() -> Result<(), TestError> {
    for case in fixtures()?.sessions {
        for node in &case.nodes {
            let mut public_keys = keys(&node.public_keys)?;
            let aggregate = key_agg(&public_keys)?;
            assert_eq!(
                aggregate.plain_key().serialize(),
                fixed::<33>(&node.aggregate_key)?,
                "{} {}",
                case.name,
                node.id
            );
            public_keys.reverse();
            assert_eq!(
                key_agg(&public_keys)?.plain_key().serialize(),
                fixed::<33>(&node.aggregate_key)?,
                "{} {} reversed",
                case.name,
                node.id
            );
            let child_nonces = node
                .child_nonces
                .iter()
                .map(|value| Ok(PublicNonce::from_slice(&bytes(value)?)?))
                .collect::<Result<Vec<_>, TestError>>()?;
            let internal = nonce_agg(&child_nonces)?;
            assert_eq!(
                internal.serialize(),
                fixed::<66>(&node.internal_nonce)?,
                "{} {}",
                case.name,
                node.id
            );
            let child_partials = node
                .child_partials
                .iter()
                .map(|value| Ok(PartialSignature::from_slice(&bytes(value)?)?))
                .collect::<Result<Vec<_>, TestError>>()?;
            let partial_sum = aggregate_intermediate(&child_partials)?;
            assert_eq!(
                partial_sum.serialize(),
                fixed::<32>(&node.partial_sum)?,
                "{} {}",
                case.name,
                node.id
            );
            if node.id != "root" {
                let outward = nonce_agg_ext(internal, aggregate.plain_key())?;
                assert_eq!(
                    outward.serialize(),
                    fixed::<66>(&node.external_nonce)?,
                    "{} {}",
                    case.name,
                    node.id
                );
                let mut negated_key = aggregate.plain_key().serialize();
                negated_key[0] ^= 1;
                let negated = PlainPublicKey::from_slice(&negated_key)?;
                assert_eq!(
                    nonce_agg_ext(internal, negated)?.serialize(),
                    fixed::<66>(&node.external_nonce)?,
                    "{} {} x-only binding",
                    case.name,
                    node.id
                );
                assert!(
                    partial_sig_verify(
                        partial_sum,
                        outward,
                        aggregate.plain_key(),
                        &session(&case, &node.nonce_path, &node.key_path)?
                    )?,
                    "{} {} subgroup",
                    case.name,
                    node.id
                );
            }
        }
    }
    Ok(())
}

#[test]
fn root_tweak_uses_final_key_parity() -> Result<(), TestError> {
    let fixtures = fixtures()?;
    let case = case(&fixtures, "root_tweak_final_parity")?;
    let message = bytes(&case.message)?;
    let key = fixed::<32>(&case.aggregate_xonly)?;
    assert!(schnorr_verify(&message, key, &bytes(&case.signature)?));
    assert!(!schnorr_verify(
        &message,
        key,
        &bytes(&case.wrong_tweak_signature)?
    ));
    let invalid = Signature::from_slice(&bytes(&case.wrong_tweak_signature)?)?;
    assert!(
        Secp256k1::verification_only()
            .verify_schnorr(
                &invalid,
                &Message::from_digest(fixed(&case.message)?),
                &XOnlyPublicKey::from_slice(&key)?
            )
            .is_err()
    );
    Ok(())
}

#[test]
fn finite_generator_is_a_valid_intermediate_nonce() -> Result<(), TestError> {
    let fixture = fixtures()?.finite_generator;
    let aggregate = AggregateNonce::from_slice(&bytes(&fixture.internal_nonce)?)?;
    let key = PlainPublicKey::from_slice(&bytes(&fixture.aggregate_key)?)?;
    assert_eq!(
        nonce_agg_ext(aggregate, key)?.serialize(),
        fixed::<66>(&fixture.external_nonce)?
    );
    Ok(())
}
