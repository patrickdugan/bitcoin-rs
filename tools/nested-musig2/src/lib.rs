use bitcoin_hashes::{Hash, HashEngine, sha256};
use secp256k1::rand::{RngCore, rngs::OsRng};
use secp256k1::{Parity, PublicKey, SECP256K1, Scalar, XOnlyPublicKey};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

mod scalar;

use scalar::SecretScalar;

pub const MAX_DEPTH: usize = 8;
pub const MAX_PARTICIPANTS: usize = 1024;
pub const MAX_MESSAGE_BYTES: usize = 1024 * 1024;
pub const MAX_TWEAKS: usize = 128;
pub const MAX_EXTRA_INPUT_BYTES: usize = 1024 * 1024;

#[derive(Debug, Error)]
pub enum Error {
    #[error("{field} must contain {expected} bytes; received {actual}")]
    InvalidLength {
        field: &'static str,
        expected: usize,
        actual: usize,
    },
    #[error("scalar must be less than the secp256k1 group order")]
    InvalidScalar,
    #[error("invalid curve value: {0}")]
    Curve(#[from] secp256k1::Error),
    #[error("{field} exceeds the supported bound {limit}")]
    Limit { field: &'static str, limit: usize },
    #[error("{0} must contain at least one contribution")]
    Empty(&'static str),
    #[error("nonce and key paths must have the same nonzero length")]
    PathMismatch,
    #[error("aggregate key is the point at infinity")]
    InfiniteKey,
    #[error("intermediate aggregate nonce has an infinite component")]
    InfiniteIntermediateNonce,
    #[error("secret key does not match the nonce's public key")]
    NonceKeyMismatch,
    #[error("session differs from the aggregate key or message supplied to nonce generation")]
    NonceBindingMismatch,
    #[error("partial signature failed verification")]
    InvalidPartialSignature,
    #[error("final signature failed BIP340 verification")]
    InvalidSignature,
    #[error("operating-system randomness failed: {0}")]
    Randomness(#[source] secp256k1::rand::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PlainPublicKey(PublicKey);

impl PlainPublicKey {
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        exact_length(bytes, 33, "public key")?;
        Ok(Self(PublicKey::from_slice(bytes)?))
    }

    pub fn serialize(self) -> [u8; 33] {
        self.0.serialize()
    }

    pub fn xonly(self) -> [u8; 32] {
        self.0.x_only_public_key().0.serialize()
    }

    fn odd(self) -> bool {
        self.0.x_only_public_key().1 == Parity::Odd
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicNonce([PublicKey; 2]);

impl PublicNonce {
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        exact_length(bytes, 66, "public nonce")?;
        Ok(Self([
            PlainPublicKey::from_slice(&bytes[..33])?.0,
            PlainPublicKey::from_slice(&bytes[33..])?.0,
        ]))
    }

    pub fn serialize(self) -> [u8; 66] {
        serialize_nonce([Some(self.0[0]), Some(self.0[1])])
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AggregateNonce([Option<PublicKey>; 2]);

impl AggregateNonce {
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        exact_length(bytes, 66, "aggregate nonce")?;
        Ok(Self([
            parse_extended_point(&bytes[..33])?,
            parse_extended_point(&bytes[33..])?,
        ]))
    }

    pub fn serialize(self) -> [u8; 66] {
        serialize_nonce(self.0)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PartialSignature(Scalar);

impl PartialSignature {
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        Ok(Self(scalar::parse(exact_array(
            bytes,
            "partial signature",
        )?)?))
    }

    pub fn serialize(self) -> [u8; 32] {
        self.0.to_be_bytes()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Tweak {
    value: Scalar,
    is_xonly: bool,
}

impl Tweak {
    pub fn new(bytes: [u8; 32], is_xonly: bool) -> Result<Self> {
        Ok(Self {
            value: scalar::parse(bytes)?,
            is_xonly,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeyAggContext {
    key: PlainPublicKey,
    negated: bool,
    tweak: Scalar,
}

impl KeyAggContext {
    pub fn plain_key(self) -> PlainPublicKey {
        self.key
    }

    pub fn xonly_key(self) -> [u8; 32] {
        self.key.xonly()
    }

    pub fn key_negated(self) -> bool {
        self.negated
    }

    pub fn tweak_accumulator(self) -> [u8; 32] {
        self.tweak.to_be_bytes()
    }
}

/// A signing attempt consumes this value even when validation fails. Nonces
/// cannot be cloned or serialized, and retained scalar storage is erased on drop.
///
/// ```compile_fail
/// use bitcoin_rs_nested_musig2::{SecretNonce, SessionContext, sign};
/// fn reuse(nonce: SecretNonce, key: &[u8], session: &SessionContext) {
///     let _first = sign(nonce, key, session);
///     let _second = sign(nonce, key, session);
/// }
/// ```
pub struct SecretNonce {
    first: SecretScalar,
    second: SecretScalar,
    public_key: PlainPublicKey,
    public_nonce: PublicNonce,
    aggregate_key: Option<[u8; 32]>,
    message_hash: Option<[u8; 32]>,
}

#[derive(Clone, Debug)]
pub struct SessionContext {
    pub nonce_path: Vec<AggregateNonce>,
    pub key_path: Vec<Vec<PlainPublicKey>>,
    pub tweaks: Vec<Tweak>,
    pub message: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct RootSessionContext {
    pub aggregate_nonce: AggregateNonce,
    pub pubkeys: Vec<PlainPublicKey>,
    pub tweaks: Vec<Tweak>,
    pub message: Vec<u8>,
}

#[derive(Clone, Copy, Debug)]
pub struct SessionValues {
    pub aggregate_key: KeyAggContext,
    pub aggregate_nonce: PlainPublicKey,
    pub nonce_coefficient: [u8; 32],
    pub challenge: [u8; 32],
    pub challenge_coefficient: [u8; 32],
}

pub fn public_key(secret_key: &[u8]) -> Result<PlainPublicKey> {
    exact_length(secret_key, 32, "secret key")?;
    SecretScalar::nonzero(secret_key)?
        .public_key()
        .map(PlainPublicKey)
        .ok_or(Error::InfiniteKey)
}

pub fn key_agg(public_keys: &[PlainPublicKey]) -> Result<KeyAggContext> {
    let sorted = sorted_keys(public_keys)?;
    key_agg_sorted(&sorted)
}

pub fn apply_tweaks(context: &KeyAggContext, tweaks: &[Tweak]) -> Result<KeyAggContext> {
    limit(tweaks.len(), MAX_TWEAKS, "tweaks")?;
    let mut result = *context;
    for tweak in tweaks {
        let negate = tweak.is_xonly && result.key.odd();
        let key = if negate {
            result.key.0.negate(SECP256K1)
        } else {
            result.key.0
        };
        result.key = PlainPublicKey(
            point_add(Some(key), generator_mul(tweak.value)?)?.ok_or(Error::InfiniteKey)?,
        );
        result.tweak = scalar::add(
            tweak.value,
            if negate {
                scalar::negate(result.tweak)?
            } else {
                result.tweak
            },
        )?;
        result.negated ^= negate;
    }
    Ok(result)
}

pub fn nonce_gen(
    secret_key: Option<&[u8; 32]>,
    public_key: PlainPublicKey,
    aggregate_key: Option<[u8; 32]>,
    message: Option<&[u8]>,
    extra_input: Option<&[u8]>,
) -> Result<(SecretNonce, PublicNonce)> {
    let mut randomness = Zeroizing::new([0u8; 32]);
    OsRng
        .try_fill_bytes(randomness.as_mut())
        .map_err(Error::Randomness)?;
    nonce_gen_internal(
        &randomness,
        secret_key,
        public_key,
        aggregate_key,
        message,
        extra_input,
    )
}

#[cfg(feature = "conformance")]
pub fn nonce_gen_with_randomness(
    mut randomness: [u8; 32],
    secret_key: Option<&[u8; 32]>,
    public_key: PlainPublicKey,
    aggregate_key: Option<[u8; 32]>,
    message: Option<&[u8]>,
    extra_input: Option<&[u8]>,
) -> Result<(SecretNonce, PublicNonce)> {
    let result = nonce_gen_internal(
        &randomness,
        secret_key,
        public_key,
        aggregate_key,
        message,
        extra_input,
    );
    randomness.zeroize();
    result
}

#[cfg(feature = "conformance")]
pub fn import_secret_nonce(bytes: &[u8]) -> Result<SecretNonce> {
    exact_length(bytes, 97, "secret nonce")?;
    make_secret_nonce(
        SecretScalar::nonzero(&bytes[..32])?,
        SecretScalar::nonzero(&bytes[32..64])?,
        PlainPublicKey::from_slice(&bytes[64..])?,
        None,
        None,
    )
}

pub fn nonce_agg(nonces: &[PublicNonce]) -> Result<AggregateNonce> {
    contributions(nonces.len(), "public nonces")?;
    let mut result = [None, None];
    for nonce in nonces {
        result[0] = point_add(result[0], Some(nonce.0[0]))?;
        result[1] = point_add(result[1], Some(nonce.0[1]))?;
    }
    Ok(AggregateNonce(result))
}

pub fn nonce_agg_ext(nonce: AggregateNonce, key: PlainPublicKey) -> Result<PublicNonce> {
    let coefficient = intermediate_nonce_coefficient(nonce, key)?;
    let first = nonce.0[0].ok_or(Error::InfiniteIntermediateNonce)?;
    let second = point_mul(nonce.0[1], coefficient)?.ok_or(Error::InfiniteIntermediateNonce)?;
    Ok(PublicNonce([first, second]))
}

pub fn get_session_values(context: &SessionContext, key: PlainPublicKey) -> Result<SessionValues> {
    let depth = context.key_path.len();
    if depth == 0 || depth != context.nonce_path.len() {
        return Err(Error::PathMismatch);
    }
    limit(depth, MAX_DEPTH, "path depth")?;
    limit(context.message.len(), MAX_MESSAGE_BYTES, "message")?;
    limit(context.tweaks.len(), MAX_TWEAKS, "tweaks")?;
    let mut current_key = key;
    let mut key_coefficient = Scalar::ONE;
    let mut nonce_coefficient = Scalar::ONE;
    let mut root = None;
    for index in (0..depth).rev() {
        let siblings = &context.key_path[index];
        limit(siblings.len(), MAX_PARTICIPANTS - 1, "cosigners")?;
        let mut keys = Vec::with_capacity(siblings.len() + 1);
        keys.extend_from_slice(siblings);
        keys.push(current_key);
        keys.sort_by_key(|key| key.serialize());
        key_coefficient = scalar::mul(key_coefficient, key_coefficient_for(&keys, current_key)?)?;
        let parent = key_agg_sorted(&keys)?;
        if index > 0 {
            let internal = context.nonce_path[index];
            nonce_agg_ext(internal, parent.key)?;
            nonce_coefficient = scalar::mul(
                nonce_coefficient,
                intermediate_nonce_coefficient(internal, parent.key)?,
            )?;
        }
        current_key = parent.key;
        root = Some(parent);
    }
    let aggregate_key = apply_tweaks(&root.ok_or(Error::PathMismatch)?, &context.tweaks)?;
    let (aggregate_nonce, root_coefficient, challenge) =
        root_values(context.nonce_path[0], aggregate_key.key, &context.message)?;
    Ok(SessionValues {
        aggregate_key,
        aggregate_nonce,
        nonce_coefficient: scalar::mul(root_coefficient, nonce_coefficient)?.to_be_bytes(),
        challenge: challenge.to_be_bytes(),
        challenge_coefficient: scalar::mul(challenge, key_coefficient)?.to_be_bytes(),
    })
}

pub fn sign(
    nonce: SecretNonce,
    secret_key: &[u8],
    context: &SessionContext,
) -> Result<PartialSignature> {
    let key = public_key(secret_key)?;
    if key != nonce.public_key {
        return Err(Error::NonceKeyMismatch);
    }
    let values = get_session_values(context, key)?;
    if nonce
        .aggregate_key
        .is_some_and(|bound| bound != values.aggregate_key.xonly_key())
        || nonce
            .message_hash
            .is_some_and(|bound| bound != sha256::Hash::hash(&context.message).to_byte_array())
    {
        return Err(Error::NonceBindingMismatch);
    }
    let public_nonce = nonce.public_nonce;
    let coefficient = scalar::parse(values.nonce_coefficient)?;
    let challenge = scalar::parse(values.challenge_coefficient)?;
    let mut first = nonce.first;
    let mut second = nonce.second;
    if values.aggregate_nonce.odd() {
        first = first.negated();
        second = second.negated();
    }
    let mut private_key = SecretScalar::nonzero(secret_key)?;
    if values.aggregate_key.key.odd() ^ values.aggregate_key.negated {
        private_key = private_key.negated();
    }
    let signature = first
        .add(&second.multiply(coefficient)?)?
        .add(&private_key.multiply(challenge)?)?;
    let partial = PartialSignature::from_slice(&signature.bytes())?;
    if !partial_sig_verify(partial, public_nonce, key, context)? {
        return Err(Error::InvalidPartialSignature);
    }
    Ok(partial)
}

pub fn partial_sig_verify(
    signature: PartialSignature,
    nonce: PublicNonce,
    key: PlainPublicKey,
    context: &SessionContext,
) -> Result<bool> {
    let values = get_session_values(context, key)?;
    let coefficient = scalar::parse(values.nonce_coefficient)?;
    let mut challenge = scalar::parse(values.challenge_coefficient)?;
    let mut effective_nonce =
        point_add(Some(nonce.0[0]), point_mul(Some(nonce.0[1]), coefficient)?)?;
    if values.aggregate_nonce.odd() {
        effective_nonce = effective_nonce.map(|point| point.negate(SECP256K1));
    }
    if values.aggregate_key.key.odd() ^ values.aggregate_key.negated {
        challenge = scalar::negate(challenge)?;
    }
    Ok(generator_mul(signature.0)?
        == point_add(effective_nonce, point_mul(Some(key.0), challenge)?)?)
}

pub fn aggregate_intermediate(signatures: &[PartialSignature]) -> Result<PartialSignature> {
    contributions(signatures.len(), "partial signatures")?;
    let mut sum = Scalar::ZERO;
    for signature in signatures {
        sum = scalar::add(sum, signature.0)?;
    }
    Ok(PartialSignature(sum))
}

pub fn aggregate_root(
    signatures: &[PartialSignature],
    context: &RootSessionContext,
) -> Result<[u8; 64]> {
    limit(context.message.len(), MAX_MESSAGE_BYTES, "message")?;
    let aggregate_key = apply_tweaks(&key_agg(&context.pubkeys)?, &context.tweaks)?;
    let (nonce, _, challenge) =
        root_values(context.aggregate_nonce, aggregate_key.key, &context.message)?;
    let mut correction = scalar::mul(challenge, aggregate_key.tweak)?;
    if aggregate_key.key.odd() {
        correction = scalar::negate(correction)?;
    }
    let scalar = scalar::add(aggregate_intermediate(signatures)?.0, correction)?;
    let mut signature = [0u8; 64];
    signature[..32].copy_from_slice(&nonce.xonly());
    signature[32..].copy_from_slice(&scalar.to_be_bytes());
    if !schnorr_verify(&context.message, aggregate_key.xonly_key(), &signature) {
        return Err(Error::InvalidSignature);
    }
    Ok(signature)
}

pub fn schnorr_verify(message: &[u8], xonly_public_key: [u8; 32], signature: &[u8]) -> bool {
    schnorr_verify_inner(message, xonly_public_key, signature).unwrap_or(false)
}

fn schnorr_verify_inner(message: &[u8], key: [u8; 32], signature: &[u8]) -> Result<bool> {
    exact_length(signature, 64, "Schnorr signature")?;
    limit(message.len(), MAX_MESSAGE_BYTES, "message")?;
    let public_key =
        PublicKey::from_x_only_public_key(XOnlyPublicKey::from_slice(&key)?, Parity::Even);
    let mut compressed_nonce = [0u8; 33];
    compressed_nonce[0] = 2;
    compressed_nonce[1..].copy_from_slice(&signature[..32]);
    let nonce = PlainPublicKey::from_slice(&compressed_nonce)?;
    let scalar = PartialSignature::from_slice(&signature[32..])?.0;
    let challenge = challenge(nonce, PlainPublicKey(public_key), message)?;
    let result = point_add(
        generator_mul(scalar)?,
        point_mul(Some(public_key), scalar::negate(challenge)?)?,
    )?;
    Ok(result == Some(nonce.0))
}

fn nonce_gen_internal(
    randomness: &[u8; 32],
    secret_key: Option<&[u8; 32]>,
    public_key: PlainPublicKey,
    aggregate_key: Option<[u8; 32]>,
    message: Option<&[u8]>,
    extra_input: Option<&[u8]>,
) -> Result<(SecretNonce, PublicNonce)> {
    let extra_input = extra_input.unwrap_or_default();
    limit(
        extra_input.len(),
        MAX_EXTRA_INPUT_BYTES,
        "extra nonce input",
    )?;
    if let Some(message) = message {
        limit(message.len(), MAX_MESSAGE_BYTES, "message")?;
    }
    let mut masked = Zeroizing::new(*randomness);
    if let Some(secret_key) = secret_key {
        let mut auxiliary = tagged_hash("MuSig/aux", randomness);
        for index in 0..32 {
            masked[index] = secret_key[index] ^ auxiliary[index];
        }
        auxiliary.zeroize();
    }
    let aggregate_length = if aggregate_key.is_some() { 32 } else { 0 };
    let message_length = message.map_or(1, |message| 9 + message.len());
    let input_capacity =
        32 + 1 + 33 + 1 + aggregate_length + message_length + 4 + extra_input.len() + 1;
    let mut input = Zeroizing::new(Vec::with_capacity(input_capacity));
    input.extend_from_slice(masked.as_ref());
    input.push(33);
    input.extend_from_slice(&public_key.serialize());
    match aggregate_key {
        Some(key) => {
            input.push(32);
            input.extend_from_slice(&key);
        }
        None => input.push(0),
    }
    match message {
        Some(message) => {
            input.push(1);
            let length = u64::try_from(message.len()).map_err(|_| Error::Limit {
                field: "message",
                limit: MAX_MESSAGE_BYTES,
            })?;
            input.extend_from_slice(&length.to_be_bytes());
            input.extend_from_slice(message);
        }
        None => input.push(0),
    }
    let length = u32::try_from(extra_input.len()).map_err(|_| Error::Limit {
        field: "extra nonce input",
        limit: MAX_EXTRA_INPUT_BYTES,
    })?;
    input.extend_from_slice(&length.to_be_bytes());
    input.extend_from_slice(extra_input);
    input.push(0);
    let first = scalar::hash_nonce_scalar(tagged_hash("MuSig/nonce", &input))?;
    let last = input.len() - 1;
    input[last] = 1;
    let second = scalar::hash_nonce_scalar(tagged_hash("MuSig/nonce", &input))?;
    let nonce = make_secret_nonce(
        first,
        second,
        public_key,
        aggregate_key,
        message.map(|value| sha256::Hash::hash(value).to_byte_array()),
    )?;
    let public_nonce = nonce.public_nonce;
    Ok((nonce, public_nonce))
}

fn make_secret_nonce(
    first: SecretScalar,
    second: SecretScalar,
    public_key: PlainPublicKey,
    aggregate_key: Option<[u8; 32]>,
    message_hash: Option<[u8; 32]>,
) -> Result<SecretNonce> {
    let public_nonce = PublicNonce([
        first.public_key().ok_or(Error::InfiniteIntermediateNonce)?,
        second
            .public_key()
            .ok_or(Error::InfiniteIntermediateNonce)?,
    ]);
    Ok(SecretNonce {
        first,
        second,
        public_key,
        public_nonce,
        aggregate_key,
        message_hash,
    })
}

fn sorted_keys(keys: &[PlainPublicKey]) -> Result<Vec<PlainPublicKey>> {
    contributions(keys.len(), "public keys")?;
    let mut sorted = keys.to_vec();
    sorted.sort_by_key(|key| key.serialize());
    Ok(sorted)
}

fn key_agg_sorted(keys: &[PlainPublicKey]) -> Result<KeyAggContext> {
    let mut aggregate = None;
    for key in keys {
        aggregate = point_add(
            aggregate,
            point_mul(Some(key.0), key_coefficient_for(keys, *key)?)?,
        )?;
    }
    Ok(KeyAggContext {
        key: PlainPublicKey(aggregate.ok_or(Error::InfiniteKey)?),
        negated: false,
        tweak: Scalar::ZERO,
    })
}

fn key_coefficient_for(keys: &[PlainPublicKey], key: PlainPublicKey) -> Result<Scalar> {
    let first = keys.first().ok_or(Error::Empty("public keys"))?;
    if keys.iter().find(|candidate| *candidate != first) == Some(&key) {
        return Ok(Scalar::ONE);
    }
    let mut serialized = Vec::with_capacity(keys.len() * 33);
    for key in keys {
        serialized.extend_from_slice(&key.serialize());
    }
    let list_hash = tagged_hash("KeyAgg list", &serialized);
    let mut input = [0u8; 65];
    input[..32].copy_from_slice(&list_hash);
    input[32..].copy_from_slice(&key.serialize());
    hash_scalar("KeyAgg coefficient", &input)
}

fn intermediate_nonce_coefficient(nonce: AggregateNonce, key: PlainPublicKey) -> Result<Scalar> {
    let mut input = [0u8; 98];
    input[..66].copy_from_slice(&nonce.serialize());
    input[66..].copy_from_slice(&key.xonly());
    hash_scalar("NestedMuSig/aggnoncecoef", &input)
}

fn root_values(
    nonce: AggregateNonce,
    key: PlainPublicKey,
    message: &[u8],
) -> Result<(PlainPublicKey, Scalar, Scalar)> {
    let mut input = Vec::with_capacity(98 + message.len());
    input.extend_from_slice(&nonce.serialize());
    input.extend_from_slice(&key.xonly());
    input.extend_from_slice(message);
    let coefficient = hash_scalar("MuSig/noncecoef", &input)?;
    let combined = point_add(nonce.0[0], point_mul(nonce.0[1], coefficient)?)?;
    let effective = match combined {
        Some(point) => point,
        None => generator_mul(Scalar::ONE)?.ok_or(Error::InfiniteKey)?,
    };
    let effective = PlainPublicKey(effective);
    Ok((effective, coefficient, challenge(effective, key, message)?))
}

fn challenge(nonce: PlainPublicKey, key: PlainPublicKey, message: &[u8]) -> Result<Scalar> {
    let mut input = Vec::with_capacity(64 + message.len());
    input.extend_from_slice(&nonce.xonly());
    input.extend_from_slice(&key.xonly());
    input.extend_from_slice(message);
    hash_scalar("BIP0340/challenge", &input)
}

fn hash_scalar(tag: &str, input: &[u8]) -> Result<Scalar> {
    scalar::parse(scalar::reduce(tagged_hash(tag, input)))
}

fn tagged_hash(tag: &str, input: &[u8]) -> [u8; 32] {
    let tag_hash = sha256::Hash::hash(tag.as_bytes());
    let mut engine = sha256::Hash::engine();
    engine.input(tag_hash.as_byte_array());
    engine.input(tag_hash.as_byte_array());
    engine.input(input);
    sha256::Hash::from_engine(engine).to_byte_array()
}

fn generator_mul(coefficient: Scalar) -> Result<Option<PublicKey>> {
    Ok(SecretScalar::from_public(coefficient)?.public_key())
}

fn point_mul(point: Option<PublicKey>, coefficient: Scalar) -> Result<Option<PublicKey>> {
    if coefficient == Scalar::ZERO {
        return Ok(None);
    }
    point
        .map(|point| {
            point
                .mul_tweak(SECP256K1, &coefficient)
                .map_err(Error::from)
        })
        .transpose()
}

fn point_add(left: Option<PublicKey>, right: Option<PublicKey>) -> Result<Option<PublicKey>> {
    match (left, right) {
        (Some(left), Some(right)) => match left.combine(&right) {
            Ok(point) => Ok(Some(point)),
            Err(secp256k1::Error::InvalidPublicKeySum) => Ok(None),
            Err(error) => Err(error.into()),
        },
        (left, right) => Ok(left.or(right)),
    }
}

fn parse_extended_point(bytes: &[u8]) -> Result<Option<PublicKey>> {
    exact_length(bytes, 33, "extended point")?;
    if bytes == [0u8; 33] {
        Ok(None)
    } else {
        Ok(Some(PlainPublicKey::from_slice(bytes)?.0))
    }
}

fn serialize_nonce(points: [Option<PublicKey>; 2]) -> [u8; 66] {
    let mut result = [0u8; 66];
    for (index, point) in points.into_iter().enumerate() {
        if let Some(point) = point {
            result[index * 33..(index + 1) * 33].copy_from_slice(&point.serialize());
        }
    }
    result
}

fn exact_length(bytes: &[u8], expected: usize, field: &'static str) -> Result<()> {
    if bytes.len() != expected {
        return Err(Error::InvalidLength {
            field,
            expected,
            actual: bytes.len(),
        });
    }
    Ok(())
}

fn exact_array<const N: usize>(bytes: &[u8], field: &'static str) -> Result<[u8; N]> {
    bytes.try_into().map_err(|_| Error::InvalidLength {
        field,
        expected: N,
        actual: bytes.len(),
    })
}

fn contributions(length: usize, field: &'static str) -> Result<()> {
    if length == 0 {
        return Err(Error::Empty(field));
    }
    limit(length, MAX_PARTICIPANTS, field)
}

fn limit(length: usize, bound: usize, field: &'static str) -> Result<()> {
    if length > bound {
        Err(Error::Limit {
            field,
            limit: bound,
        })
    } else {
        Ok(())
    }
}
