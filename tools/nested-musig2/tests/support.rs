use bitcoin_rs_nested_musig2::{AggregateNonce, PlainPublicKey, SessionContext, Tweak};
use serde::Deserialize;

#[derive(Debug, thiserror::Error)]
pub(super) enum TestError {
    #[error(transparent)]
    Protocol(#[from] bitcoin_rs_nested_musig2::Error),
    #[error(transparent)]
    Json(#[from] sonic_rs::Error),
    #[error(transparent)]
    Hex(#[from] std::num::ParseIntError),
    #[error("fixture hex must have an even ASCII byte count")]
    HexLength,
    #[error("fixture has an unexpected fixed byte count")]
    ArrayLength,
    #[error(transparent)]
    Secp(#[from] bitcoin::secp256k1::Error),
    #[error("required fixture {0} is absent")]
    Missing(&'static str),
}

#[derive(Deserialize)]
pub(super) struct Fixtures {
    pub(super) sessions: Vec<Case>,
    pub(super) nonce_generation: Vec<NonceGeneration>,
    pub(super) finite_generator: GeneratorFixture,
}

#[derive(Deserialize)]
pub(super) struct NonceGeneration {
    pub(super) name: String,
    pub(super) randomness: String,
    pub(super) secret_key: Option<String>,
    pub(super) public_key: String,
    pub(super) aggregate_key: Option<String>,
    pub(super) message: Option<String>,
    pub(super) extra_input: Option<String>,
    pub(super) public_nonce: String,
}

#[derive(Deserialize)]
pub(super) struct Case {
    pub(super) name: String,
    pub(super) message: String,
    pub(super) extra_input: String,
    pub(super) tweaks: Vec<TweakFixture>,
    pub(super) root_public_keys: Vec<String>,
    pub(super) untweaked_key: String,
    pub(super) aggregate_key: String,
    pub(super) aggregate_xonly: String,
    pub(super) root_nonce: String,
    pub(super) signature: String,
    pub(super) wrong_tweak_signature: String,
    pub(super) bip327_exact: bool,
    pub(super) nodes: Vec<NodeFixture>,
    pub(super) leaves: Vec<LeafFixture>,
}

#[derive(Deserialize)]
pub(super) struct TweakFixture {
    pub(super) scalar: String,
    pub(super) is_xonly: bool,
}

#[derive(Deserialize)]
pub(super) struct NodeFixture {
    pub(super) id: String,
    pub(super) public_keys: Vec<String>,
    pub(super) aggregate_key: String,
    pub(super) child_nonces: Vec<String>,
    pub(super) internal_nonce: String,
    pub(super) external_nonce: String,
    pub(super) child_partials: Vec<String>,
    pub(super) partial_sum: String,
    pub(super) nonce_path: Vec<String>,
    pub(super) key_path: Vec<Vec<String>>,
}

#[derive(Deserialize)]
pub(super) struct LeafFixture {
    pub(super) id: String,
    pub(super) secret_key: String,
    pub(super) public_key: String,
    pub(super) randomness: String,
    pub(super) secret_nonce: String,
    pub(super) public_nonce: String,
    pub(super) nonce_path: Vec<String>,
    pub(super) key_path: Vec<Vec<String>>,
    pub(super) partial_signature: String,
}

#[derive(Deserialize)]
pub(super) struct GeneratorFixture {
    pub(super) aggregate_key: String,
    pub(super) internal_nonce: String,
    pub(super) external_nonce: String,
}

pub(super) fn fixtures() -> Result<Fixtures, TestError> {
    Ok(sonic_rs::from_str(include_str!(
        "fixtures/conformance.json"
    ))?)
}

pub(super) fn bytes(value: &str) -> Result<Vec<u8>, TestError> {
    if !value.is_ascii() || !value.len().is_multiple_of(2) {
        return Err(TestError::HexLength);
    }
    (0..value.len())
        .step_by(2)
        .map(|index| Ok(u8::from_str_radix(&value[index..index + 2], 16)?))
        .collect()
}

pub(super) fn fixed<const N: usize>(value: &str) -> Result<[u8; N], TestError> {
    bytes(value)?.try_into().map_err(|_| TestError::ArrayLength)
}

pub(super) fn keys(values: &[String]) -> Result<Vec<PlainPublicKey>, TestError> {
    values
        .iter()
        .map(|value| Ok(PlainPublicKey::from_slice(&bytes(value)?)?))
        .collect()
}

pub(super) fn tweaks(case: &Case) -> Result<Vec<Tweak>, TestError> {
    case.tweaks
        .iter()
        .map(|value| Ok(Tweak::new(fixed(&value.scalar)?, value.is_xonly)?))
        .collect()
}

pub(super) fn session(
    case: &Case,
    nonce_path: &[String],
    key_path: &[Vec<String>],
) -> Result<SessionContext, TestError> {
    Ok(SessionContext {
        nonce_path: nonce_path
            .iter()
            .map(|value| Ok(AggregateNonce::from_slice(&bytes(value)?)?))
            .collect::<Result<_, TestError>>()?,
        key_path: key_path
            .iter()
            .map(|values| keys(values))
            .collect::<Result<_, _>>()?,
        tweaks: tweaks(case)?,
        message: bytes(&case.message)?,
    })
}

pub(super) fn case<'a>(fixtures: &'a Fixtures, name: &'static str) -> Result<&'a Case, TestError> {
    fixtures
        .sessions
        .iter()
        .find(|value| value.name == name)
        .ok_or(TestError::Missing(name))
}
