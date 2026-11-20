use bitcoin_rs_ark_nested_musig2::policy::Shape;
use bitcoin_rs_ark_nested_musig2::scenario::{Synthetic, synthetic};

#[derive(Debug, thiserror::Error)]
pub(super) enum TestError {
    #[error(transparent)]
    Ark(#[from] bitcoin_rs_ark_nested_musig2::Error),
    #[error(transparent)]
    Codec(#[from] bitcoin_rs_ark_nested_musig2::codec::CodecError),
    #[error(transparent)]
    Json(#[from] sonic_rs::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Secp(#[from] bitcoin::secp256k1::Error),
    #[error(transparent)]
    Hex(#[from] bitcoin::hex::HexToBytesError),
    #[error(transparent)]
    Nested(#[from] bitcoin_rs_nested_musig2::Error),
    #[error("expected {expected}, observed {observed}")]
    Unexpected { expected: String, observed: String },
}

pub(super) const SEED: [u8; 32] = [42; 32];

pub(super) fn round(count: usize, shape: Shape) -> Result<Synthetic, TestError> {
    Ok(synthetic(count, shape, &SEED)?)
}

pub(super) fn rejection_stage<T>(result: Result<T, bitcoin_rs_ark_nested_musig2::Error>) -> String {
    match result {
        Ok(_) => "accepted".to_owned(),
        Err(bitcoin_rs_ark_nested_musig2::Error::Rejected(rejection)) => rejection.stage,
        Err(bitcoin_rs_ark_nested_musig2::Error::Signing { stage, .. }) => stage.to_owned(),
        Err(other) => format!("error: {other}"),
    }
}
