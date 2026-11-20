use bitcoin::consensus::{deserialize, serialize};
use bitcoin::hashes::Hash as _;
use bitcoin::{OutPoint, ScriptBuf, Transaction, Txid};
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CodecError {
    #[error("encoding ended before {0}")]
    Truncated(&'static str),
    #[error("{0} exceeds its bound")]
    Bound(&'static str),
    #[error("{remaining} trailing bytes after the statement")]
    Trailing { remaining: usize },
    #[error("unknown magic or version")]
    Version,
    #[error("unknown {0} code")]
    UnknownCode(&'static str),
    #[error("transaction template is not canonical or carries witness data")]
    Transaction,
    #[error("public key encoding is invalid")]
    Key,
}

pub const MAX_ITEMS: usize = 4096;
pub const MAX_BYTES: usize = 400_000;

#[derive(Default)]
pub struct Writer {
    pub bytes: Vec<u8>,
}

impl Writer {
    pub fn u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    pub fn u16(&mut self, value: u16) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    pub fn u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    pub fn u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    pub fn fixed(&mut self, value: &[u8]) {
        self.bytes.extend_from_slice(value);
    }

    pub fn count(&mut self, value: usize) -> Result<(), CodecError> {
        if value > MAX_ITEMS {
            return Err(CodecError::Bound("item count"));
        }
        self.u16(u16::try_from(value).map_err(|_| CodecError::Bound("item count"))?);
        Ok(())
    }

    pub fn var(&mut self, value: &[u8]) -> Result<(), CodecError> {
        if value.len() > MAX_BYTES {
            return Err(CodecError::Bound("byte string"));
        }
        self.u32(u32::try_from(value.len()).map_err(|_| CodecError::Bound("byte string"))?);
        self.fixed(value);
        Ok(())
    }

    pub fn outpoint(&mut self, value: &OutPoint) {
        self.fixed(&value.txid.to_byte_array());
        self.u32(value.vout);
    }

    pub fn script(&mut self, value: &ScriptBuf) -> Result<(), CodecError> {
        self.var(value.as_bytes())
    }

    pub fn transaction(&mut self, value: &Transaction) -> Result<(), CodecError> {
        if value.input.iter().any(|input| !input.witness.is_empty()) {
            return Err(CodecError::Transaction);
        }
        self.var(&serialize(value))
    }
}

pub struct Reader<'a> {
    bytes: &'a [u8],
}

impl<'a> Reader<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    pub fn take(&mut self, length: usize, what: &'static str) -> Result<&'a [u8], CodecError> {
        if self.bytes.len() < length {
            return Err(CodecError::Truncated(what));
        }
        let (head, tail) = self.bytes.split_at(length);
        self.bytes = tail;
        Ok(head)
    }

    pub fn array<const N: usize>(&mut self, what: &'static str) -> Result<[u8; N], CodecError> {
        self.take(N, what)?
            .try_into()
            .map_err(|_| CodecError::Truncated(what))
    }

    pub fn u8(&mut self, what: &'static str) -> Result<u8, CodecError> {
        Ok(self.array::<1>(what)?[0])
    }

    pub fn u16(&mut self, what: &'static str) -> Result<u16, CodecError> {
        Ok(u16::from_le_bytes(self.array(what)?))
    }

    pub fn u32(&mut self, what: &'static str) -> Result<u32, CodecError> {
        Ok(u32::from_le_bytes(self.array(what)?))
    }

    pub fn u64(&mut self, what: &'static str) -> Result<u64, CodecError> {
        Ok(u64::from_le_bytes(self.array(what)?))
    }

    pub fn count(&mut self, what: &'static str) -> Result<usize, CodecError> {
        let value = usize::from(self.u16(what)?);
        if value > MAX_ITEMS {
            return Err(CodecError::Bound(what));
        }
        Ok(value)
    }

    pub fn var(&mut self, what: &'static str) -> Result<&'a [u8], CodecError> {
        let length = usize::try_from(self.u32(what)?).map_err(|_| CodecError::Bound(what))?;
        if length > MAX_BYTES {
            return Err(CodecError::Bound(what));
        }
        self.take(length, what)
    }

    pub fn outpoint(&mut self, what: &'static str) -> Result<OutPoint, CodecError> {
        let txid = Txid::from_byte_array(self.array(what)?);
        Ok(OutPoint::new(txid, self.u32(what)?))
    }

    pub fn script(&mut self, what: &'static str) -> Result<ScriptBuf, CodecError> {
        Ok(ScriptBuf::from_bytes(self.var(what)?.to_vec()))
    }

    pub fn transaction(&mut self, what: &'static str) -> Result<Transaction, CodecError> {
        let bytes = self.var(what)?;
        let transaction: Transaction = deserialize(bytes).map_err(|_| CodecError::Transaction)?;
        if serialize(&transaction) != bytes
            || transaction
                .input
                .iter()
                .any(|input| !input.witness.is_empty())
        {
            return Err(CodecError::Transaction);
        }
        Ok(transaction)
    }

    pub fn finish(self) -> Result<(), CodecError> {
        if self.bytes.is_empty() {
            Ok(())
        } else {
            Err(CodecError::Trailing {
                remaining: self.bytes.len(),
            })
        }
    }
}
