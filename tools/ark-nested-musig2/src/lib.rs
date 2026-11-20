pub mod client;
pub mod codec;
pub mod keys;
pub mod native;
pub mod policy;
pub mod remote;
pub mod round;
pub mod scenario;
pub mod scripts;
pub mod signing;
pub mod statement;
pub mod traffic;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("NestedMuSig2 operation failed: {0}")]
    Nested(#[from] bitcoin_rs_nested_musig2::Error),
    #[error("secp256k1 operation failed: {0}")]
    Secp(#[from] secp256k1::Error),
    #[error("Taproot construction failed: {0}")]
    Taproot(#[from] bitcoin::taproot::TaprootBuilderError),
    #[error("Taproot finalization failed")]
    TaprootIncomplete,
    #[error("Taproot sighash failed: {0}")]
    Sighash(#[from] bitcoin::sighash::TaprootError),
    #[error("filesystem operation failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON encoding failed: {0}")]
    Json(#[from] sonic_rs::Error),
    #[error("statement codec: {0}")]
    Codec(#[from] codec::CodecError),
    #[error("operating-system randomness failed: {0}")]
    Random(#[from] secp256k1::rand::Error),
    #[error("key file must be a regular file with mode 0600 or stricter")]
    KeyPermissions,
    #[error("key file format is invalid")]
    KeyFormat,
    #[error("key file belongs to a different network")]
    KeyNetwork,
    #[error("key files require Unix file permissions")]
    UnsupportedPlatform,
    #[error("value arithmetic overflowed or underflowed: {0}")]
    Value(&'static str),
    #[error("integer conversion out of range: {0}")]
    Range(&'static str),
    #[error("round construction is inconsistent: {0}")]
    Construction(String),
    #[error("signing failed at stage {stage}: {detail}")]
    Signing { stage: &'static str, detail: String },
    #[error("cosigner rejected the request at stage {0}")]
    Rejected(client::Rejection),
    #[error("remote signer protocol failure: {0}")]
    Remote(String),
}

pub type Result<T> = std::result::Result<T, Error>;

pub fn to_u32(value: usize, what: &'static str) -> Result<u32> {
    u32::try_from(value).map_err(|_| Error::Range(what))
}

pub fn to_u16(value: usize, what: &'static str) -> Result<u16> {
    u16::try_from(value).map_err(|_| Error::Range(what))
}

pub fn to_u64(value: usize, what: &'static str) -> Result<u64> {
    u64::try_from(value).map_err(|_| Error::Range(what))
}

pub fn add_sat(left: u64, right: u64, what: &'static str) -> Result<u64> {
    left.checked_add(right).ok_or(Error::Value(what))
}

pub fn sub_sat(left: u64, right: u64, what: &'static str) -> Result<u64> {
    left.checked_sub(right).ok_or(Error::Value(what))
}
