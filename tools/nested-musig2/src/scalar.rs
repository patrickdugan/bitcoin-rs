use secp256k1::{PublicKey, SECP256K1, Scalar, SecretKey};
use zeroize::{Zeroize, Zeroizing};

use crate::{Error, Result};

const ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

pub(crate) fn reduce(mut value: [u8; 32]) -> [u8; 32] {
    let mut reduced = Zeroizing::new([0u8; 32]);
    let mut borrow = 0u8;
    for index in (0..32).rev() {
        let (first, first_borrow) = value[index].overflowing_sub(ORDER[index]);
        let (second, second_borrow) = first.overflowing_sub(borrow);
        reduced[index] = second;
        borrow = u8::from(first_borrow | second_borrow);
    }
    let mask = 0u8.wrapping_sub(1u8.wrapping_sub(borrow));
    for index in 0..32 {
        value[index] = (reduced[index] & mask) | (value[index] & !mask);
    }
    value
}

pub(crate) fn parse(value: [u8; 32]) -> Result<Scalar> {
    Scalar::from_be_bytes(value).map_err(|_| Error::InvalidScalar)
}

pub(crate) fn add(left: Scalar, right: Scalar) -> Result<Scalar> {
    let left = SecretScalar::from_public(left)?;
    let right = SecretScalar::from_public(right)?;
    parse(left.add(&right)?.bytes())
}

pub(crate) fn mul(left: Scalar, right: Scalar) -> Result<Scalar> {
    parse(SecretScalar::from_public(left)?.multiply(right)?.bytes())
}

pub(crate) fn negate(value: Scalar) -> Result<Scalar> {
    parse(SecretScalar::from_public(value)?.negated().bytes())
}

pub(crate) struct SecretScalar {
    value: Zeroizing<[u8; 32]>,
}

impl SecretScalar {
    pub(crate) fn nonzero(bytes: &[u8]) -> Result<Self> {
        let key = ErasedKey(SecretKey::from_slice(bytes)?);
        Ok(Self::from_key(&key))
    }

    pub(crate) fn from_public(value: Scalar) -> Result<Self> {
        Ok(Self {
            value: Zeroizing::new(value.to_be_bytes()),
        })
    }

    pub(crate) fn bytes(&self) -> [u8; 32] {
        *self.value
    }

    pub(crate) fn public_key(&self) -> Option<PublicKey> {
        self.key()
            .as_ref()
            .map(|key| PublicKey::from_secret_key(SECP256K1, &key.0))
    }

    pub(crate) fn negated(mut self) -> Self {
        if let Some(key) = self.key() {
            let negated = ErasedKey(key.0.negate());
            self.value.zeroize();
            *self.value = negated.0.secret_bytes();
        }
        self
    }

    pub(crate) fn multiply(self, coefficient: Scalar) -> Result<Self> {
        match self.key() {
            Some(key) if coefficient != Scalar::ZERO => {
                let product = ErasedKey(key.0.mul_tweak(&coefficient)?);
                Ok(Self::from_key(&product))
            }
            _ => Self::from_public(Scalar::ZERO),
        }
    }

    pub(crate) fn add(self, other: &Self) -> Result<Self> {
        match (self.key(), other.key()) {
            (Some(left), Some(right)) => {
                let mut tweak = Scalar::from(right.0);
                let sum = left.0.add_tweak(&tweak);
                tweak.non_secure_erase();
                match sum {
                    Ok(key) => Ok(Self::from_key(&ErasedKey(key))),
                    Err(secp256k1::Error::InvalidTweak) => Self::from_public(Scalar::ZERO),
                    Err(error) => Err(error.into()),
                }
            }
            (Some(key), None) | (None, Some(key)) => Ok(Self::from_key(&key)),
            (None, None) => Self::from_public(Scalar::ZERO),
        }
    }

    fn from_key(key: &ErasedKey) -> Self {
        Self {
            value: Zeroizing::new(key.0.secret_bytes()),
        }
    }

    fn key(&self) -> Option<ErasedKey> {
        SecretKey::from_slice(self.value.as_ref())
            .ok()
            .map(ErasedKey)
    }
}

struct ErasedKey(SecretKey);

impl Drop for ErasedKey {
    fn drop(&mut self) {
        self.0.non_secure_erase();
    }
}

pub(crate) fn hash_nonce_scalar(mut bytes: [u8; 32]) -> Result<SecretScalar> {
    let mut reduced = reduce(bytes);
    bytes.zeroize();
    let scalar = SecretScalar::nonzero(&reduced);
    reduced.zeroize();
    scalar
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reduction_boundaries_follow_the_group_order() {
        assert_eq!(reduce([0; 32]), [0; 32]);
        assert_eq!(reduce(Scalar::MAX.to_be_bytes()), Scalar::MAX.to_be_bytes());
        assert_eq!(reduce(ORDER), [0; 32]);
        let mut next = ORDER;
        next[31] = 0x42;
        assert_eq!(reduce(next), Scalar::ONE.to_be_bytes());
        let maximum_remainder = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x45, 0x51, 0x23, 0x19, 0x50, 0xb7,
            0x5f, 0xc4, 0x40, 0x2d, 0xa1, 0x73, 0x2f, 0xc9, 0xbe, 0xbe,
        ];
        assert_eq!(reduce([0xff; 32]), maximum_remainder);
    }

    #[test]
    fn scalar_zero_and_cancellation_remain_valid() -> Result<()> {
        assert_eq!(add(Scalar::MAX, Scalar::ONE)?, Scalar::ZERO);
        assert_eq!(add(Scalar::ZERO, Scalar::ONE)?, Scalar::ONE);
        assert_eq!(mul(Scalar::ZERO, Scalar::MAX)?, Scalar::ZERO);
        assert_eq!(mul(Scalar::MAX, Scalar::MAX)?, Scalar::ONE);
        assert_eq!(negate(Scalar::ZERO)?, Scalar::ZERO);
        assert_eq!(negate(Scalar::MAX)?, Scalar::ONE);
        Ok(())
    }
}
