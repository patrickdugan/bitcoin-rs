use bitcoin_rs_nested_musig2::{
    AggregateNonce, MAX_DEPTH, MAX_MESSAGE_BYTES, MAX_PARTICIPANTS, MAX_TWEAKS, PartialSignature,
    PlainPublicKey, PublicNonce, RootSessionContext, SessionContext, Tweak, aggregate_root,
    get_session_values, import_secret_nonce, key_agg, nonce_agg, nonce_agg_ext,
    nonce_gen_with_randomness, partial_sig_verify, public_key, schnorr_verify, sign,
};

use crate::support::{TestError, bytes, case, fixed, fixtures, keys, session};

const ORDER: &str = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";

#[test]
fn parsers_reject_noncanonical_lengths_ranges_and_points() -> Result<(), TestError> {
    let fixtures = fixtures()?;
    let case = case(&fixtures, "flat_32")?;
    let leaf = &case.leaves[0];
    let key = bytes(&leaf.public_key)?;
    let nonce = bytes(&leaf.public_nonce)?;
    let partial = bytes(&leaf.partial_signature)?;
    for width in [0, 1, 31, 32, 34, 65] {
        assert!(PlainPublicKey::from_slice(&vec![0; width]).is_err());
    }
    let mut oversized_key = key.clone();
    oversized_key.push(0);
    assert!(PlainPublicKey::from_slice(&oversized_key).is_err());
    let mut invalid_key = key.clone();
    invalid_key[0] = 4;
    assert!(PlainPublicKey::from_slice(&invalid_key).is_err());
    for width in [0, 1, 31, 33, 64] {
        assert!(public_key(&vec![1; width]).is_err());
    }
    assert!(public_key(&[0; 32]).is_err());
    assert!(public_key(&bytes(ORDER)?).is_err());
    for width in [0, 1, 32, 33, 65, 67, 70] {
        assert!(PublicNonce::from_slice(&vec![0; width]).is_err());
        assert!(AggregateNonce::from_slice(&vec![0; width]).is_err());
    }
    let mut oversized_nonce = nonce.clone();
    oversized_nonce.extend_from_slice(b"junk");
    assert!(PublicNonce::from_slice(&oversized_nonce).is_err());
    assert!(AggregateNonce::from_slice(&oversized_nonce).is_err());
    let mut invalid_nonce = nonce.clone();
    invalid_nonce[33] = 4;
    assert!(PublicNonce::from_slice(&invalid_nonce).is_err());
    assert!(AggregateNonce::from_slice(&invalid_nonce).is_err());
    assert!(PublicNonce::from_slice(&[0; 66]).is_err());
    assert!(AggregateNonce::from_slice(&[0; 66]).is_ok());
    for width in [0, 1, 31, 33, 64] {
        assert!(PartialSignature::from_slice(&vec![0; width]).is_err());
    }
    let mut oversized_partial = vec![0];
    oversized_partial.extend_from_slice(&partial);
    assert!(PartialSignature::from_slice(&oversized_partial).is_err());
    assert!(PartialSignature::from_slice(&bytes(ORDER)?).is_err());
    assert!(PartialSignature::from_slice(&[255; 32]).is_err());
    assert!(PartialSignature::from_slice(&[0; 32]).is_ok());
    assert!(Tweak::new(fixed(ORDER)?, false).is_err());
    assert!(Tweak::new([0; 32], false).is_ok());
    let secret_nonce = bytes(&leaf.secret_nonce)?;
    for width in [0, 1, 64, 96, 98, 101] {
        assert!(import_secret_nonce(&vec![0; width]).is_err());
    }
    for offset in [0, 32] {
        let mut invalid = secret_nonce.clone();
        invalid[offset..offset + 32].fill(0);
        assert!(import_secret_nonce(&invalid).is_err());
        invalid[offset..offset + 32].copy_from_slice(&bytes(ORDER)?);
        assert!(import_secret_nonce(&invalid).is_err());
    }
    Ok(())
}

#[test]
fn intermediate_infinity_fails_and_root_infinity_keeps_bip327_fallback() -> Result<(), TestError> {
    let fixtures = fixtures()?;
    let case = case(&fixtures, "flat_32")?;
    let leaf = &case.leaves[0];
    let public_nonce = PublicNonce::from_slice(&bytes(&leaf.public_nonce)?)?;
    let mut negated = public_nonce.serialize();
    negated[0] ^= 1;
    negated[33] ^= 1;
    let aggregate = nonce_agg(&[public_nonce, PublicNonce::from_slice(&negated)?])?;
    assert_eq!(aggregate.serialize(), [0; 66]);
    let public = PlainPublicKey::from_slice(&bytes(&leaf.public_key)?)?;
    assert!(nonce_agg_ext(aggregate, public).is_err());
    let mut first_infinity = public_nonce.serialize();
    first_infinity[..33].fill(0);
    assert!(nonce_agg_ext(AggregateNonce::from_slice(&first_infinity)?, public).is_err());
    let mut second_infinity = public_nonce.serialize();
    second_infinity[33..].fill(0);
    assert!(nonce_agg_ext(AggregateNonce::from_slice(&second_infinity)?, public).is_err());
    let context = RootSessionContext {
        aggregate_nonce: aggregate,
        pubkeys: keys(&case.root_public_keys)?,
        tweaks: Vec::new(),
        message: bytes(&case.message)?,
    };
    let mut leaf_context = session(case, &leaf.nonce_path, &leaf.key_path)?;
    leaf_context.nonce_path[0] = aggregate;
    let values = get_session_values(&leaf_context, public)?;
    assert_eq!(
        values.aggregate_nonce.xonly(),
        fixed::<32>("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")?
    );
    assert!(matches!(
        aggregate_root(&[PartialSignature::from_slice(&[0; 32])?], &context),
        Err(bitcoin_rs_nested_musig2::Error::InvalidSignature)
    ));
    Ok(())
}

#[test]
fn malformed_or_excessive_session_paths_fail_signing() -> Result<(), TestError> {
    let fixtures = fixtures()?;
    let case = case(&fixtures, "flat_32")?;
    let leaf = &case.leaves[0];
    let initial = session(case, &leaf.nonce_path, &leaf.key_path)?;
    let nonce = AggregateNonce::from_slice(&bytes(&case.root_nonce)?)?;
    let public = PlainPublicKey::from_slice(&bytes(&leaf.public_key)?)?;
    let invalid_contexts = [
        SessionContext {
            nonce_path: Vec::new(),
            key_path: Vec::new(),
            tweaks: Vec::new(),
            message: initial.message.clone(),
        },
        SessionContext {
            nonce_path: vec![nonce],
            key_path: Vec::new(),
            tweaks: Vec::new(),
            message: initial.message.clone(),
        },
        SessionContext {
            nonce_path: vec![nonce; MAX_DEPTH + 1],
            key_path: vec![Vec::new(); MAX_DEPTH + 1],
            tweaks: Vec::new(),
            message: initial.message.clone(),
        },
        SessionContext {
            nonce_path: vec![nonce],
            key_path: vec![vec![public; MAX_PARTICIPANTS]],
            tweaks: Vec::new(),
            message: initial.message.clone(),
        },
        SessionContext {
            nonce_path: initial.nonce_path.clone(),
            key_path: initial.key_path.clone(),
            tweaks: Vec::new(),
            message: vec![0; MAX_MESSAGE_BYTES + 1],
        },
        SessionContext {
            nonce_path: initial.nonce_path.clone(),
            key_path: initial.key_path.clone(),
            tweaks: vec![Tweak::new([0; 32], false)?; MAX_TWEAKS + 1],
            message: initial.message.clone(),
        },
        SessionContext {
            nonce_path: vec![nonce, AggregateNonce::from_slice(&[0; 66])?],
            key_path: vec![Vec::new(), Vec::new()],
            tweaks: Vec::new(),
            message: initial.message.clone(),
        },
    ];
    for context in invalid_contexts {
        let secret_nonce = import_secret_nonce(&bytes(&leaf.secret_nonce)?)?;
        assert!(sign(secret_nonce, &bytes(&leaf.secret_key)?, &context).is_err());
    }
    assert!(key_agg(&[]).is_err());
    assert!(key_agg(&vec![public; MAX_PARTICIPANTS + 1]).is_err());
    Ok(())
}

#[test]
fn signing_rejects_wrong_keys_and_nonce_generation_bindings() -> Result<(), TestError> {
    let fixtures = fixtures()?;
    let case = case(&fixtures, "flat_32")?;
    let leaf = &case.leaves[0];
    let context = session(case, &leaf.nonce_path, &leaf.key_path)?;
    let secret = fixed::<32>(&leaf.secret_key)?;
    for wrong_secret in [
        vec![0; 32],
        bytes(ORDER)?,
        vec![1; 31],
        vec![1; 33],
        bytes(&case.leaves[1].secret_key)?,
    ] {
        let nonce = import_secret_nonce(&bytes(&leaf.secret_nonce)?)?;
        assert!(sign(nonce, &wrong_secret, &context).is_err());
    }
    for change_key in [false, true] {
        let (nonce, _) = nonce_gen_with_randomness(
            fixed(&leaf.randomness)?,
            Some(&secret),
            public_key(&secret)?,
            Some(fixed(&case.aggregate_xonly)?),
            Some(&bytes(&case.message)?),
            Some(&bytes(&case.extra_input)?),
        )?;
        let mut altered = session(case, &leaf.nonce_path, &leaf.key_path)?;
        if change_key {
            let mut tweak = [0; 32];
            tweak[31] = 1;
            altered.tweaks.push(Tweak::new(tweak, false)?);
        } else {
            altered.message[0] ^= 1;
        }
        assert!(sign(nonce, &secret, &altered).is_err());
    }
    Ok(())
}

#[test]
fn altered_messages_keys_nonces_and_partials_fail_verification() -> Result<(), TestError> {
    let fixtures = fixtures()?;
    let case = case(&fixtures, "nested_balanced")?;
    let leaf = &case.leaves[0];
    let partial = PartialSignature::from_slice(&bytes(&leaf.partial_signature)?)?;
    let nonce = PublicNonce::from_slice(&bytes(&leaf.public_nonce)?)?;
    let public = PlainPublicKey::from_slice(&bytes(&leaf.public_key)?)?;
    let context = session(case, &leaf.nonce_path, &leaf.key_path)?;
    let mut altered = session(case, &leaf.nonce_path, &leaf.key_path)?;
    altered.message[0] ^= 1;
    assert!(!partial_sig_verify(partial, nonce, public, &altered)?);
    let other_nonce = PublicNonce::from_slice(&bytes(&case.leaves[1].public_nonce)?)?;
    assert!(!partial_sig_verify(partial, other_nonce, public, &context)?);
    let other_key = PlainPublicKey::from_slice(&bytes(&case.leaves[1].public_key)?)?;
    assert!(!partial_sig_verify(partial, nonce, other_key, &context)?);
    assert!(!partial_sig_verify(
        PartialSignature::from_slice(&[0; 32])?,
        nonce,
        public,
        &context
    )?);
    let mut signature = bytes(&case.signature)?;
    signature[63] ^= 1;
    assert!(!schnorr_verify(
        &bytes(&case.message)?,
        fixed(&case.aggregate_xonly)?,
        &signature
    ));
    let signature = bytes(&case.signature)?;
    assert!(!schnorr_verify(
        &altered.message,
        fixed(&case.aggregate_xonly)?,
        &signature
    ));
    assert!(!schnorr_verify(
        &context.message,
        fixed(&case.aggregate_xonly)?,
        &signature[..63]
    ));
    let mut oversized = signature;
    oversized.push(0);
    assert!(!schnorr_verify(
        &context.message,
        fixed(&case.aggregate_xonly)?,
        &oversized
    ));
    Ok(())
}
