//! BIP 448 (BIP 446 `OP_TEMPLATEHASH`, BIP 348 `OP_CHECKSIGFROMSTACK`, BIP 349
//! `OP_INTERNALKEY`): opcode bytes, the regtest activation switch, and the
//! BIP 340 verifier for arbitrary-length messages.

use std::sync::atomic::{AtomicBool, Ordering};

use secp256k1::{Parity, PublicKey, SECP256K1, Scalar, SecretKey, XOnlyPublicKey};
use sha2::{Digest, Sha256};

/// `OP_INTERNALKEY` replaces `OP_SUCCESS203`.
pub const OP_INTERNALKEY: u8 = 0xcb;
/// `OP_CHECKSIGFROMSTACK` replaces `OP_SUCCESS204`.
pub const OP_CHECKSIGFROMSTACK: u8 = 0xcc;
/// `OP_TEMPLATEHASH` replaces `OP_SUCCESS206`.
pub const OP_TEMPLATEHASH: u8 = 0xce;

static REGTEST_ACTIVATION: AtomicBool = AtomicBool::new(false);

/// Turns the BIP 448 opcodes on for every tapscript this process evaluates.
///
/// Callers gate this on the regtest network; the script crate does not know
/// which network it runs under. The switch is process-wide and meant to be set
/// once at start-up, before any script is evaluated, so cached script results
/// never mix both rule sets.
pub fn set_regtest_activation(enabled: bool) {
    REGTEST_ACTIVATION.store(enabled, Ordering::SeqCst);
}

/// Whether the process-wide regtest activation switch is on.
#[must_use]
pub fn regtest_activation() -> bool {
    REGTEST_ACTIVATION.load(Ordering::SeqCst)
}

/// True for the three bytes BIP 448 redefines.
#[must_use]
pub const fn is_bip448_opcode(op: u8) -> bool {
    matches!(op, OP_INTERNALKEY | OP_CHECKSIGFROMSTACK | OP_TEMPLATEHASH)
}

const CURVE_ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

fn tagged_hash(tag: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let tag_hash = Sha256::digest(tag);
    let mut engine = Sha256::new();
    engine.update(tag_hash);
    engine.update(tag_hash);
    for part in parts {
        engine.update(part);
    }
    engine.finalize().into()
}

/// Reduces a 256-bit big-endian integer modulo the curve order. Since
/// `2^256 < 2n`, a single subtraction is enough.
fn reduce_mod_n(value: [u8; 32]) -> [u8; 32] {
    if value < CURVE_ORDER {
        return value;
    }
    let mut out = [0_u8; 32];
    let mut borrow = 0_i16;
    for i in (0..32).rev() {
        let mut diff = i16::from(value[i]) - i16::from(CURVE_ORDER[i]) - borrow;
        if diff < 0 {
            diff += 256;
            borrow = 1;
        } else {
            borrow = 0;
        }
        out[i] = u8::try_from(diff).unwrap_or(0);
    }
    out
}

/// BIP 340 verification of `sig` over a message of any length.
#[must_use]
pub(crate) fn verify_bip340(sig: &[u8; 64], msg: &[u8], pubkey: &[u8; 32]) -> bool {
    let Ok(xonly) = XOnlyPublicKey::from_slice(pubkey) else {
        return false;
    };
    let p = PublicKey::from_x_only_public_key(xonly, Parity::Even);
    let r_bytes = &sig[..32];
    let mut s_bytes = [0_u8; 32];
    s_bytes.copy_from_slice(&sig[32..]);
    // r must be a field element; equality with the recovered x below enforces
    // it, since a recovered x is always below the field size.
    if Scalar::from_be_bytes(s_bytes).is_err() {
        return false;
    }
    let e_bytes = reduce_mod_n(tagged_hash(b"BIP0340/challenge", &[r_bytes, pubkey, msg]));
    let Ok(e) = Scalar::from_be_bytes(e_bytes) else {
        return false;
    };
    // R = s*G - e*P
    let s_g = SecretKey::from_slice(&s_bytes)
        .ok()
        .map(|sk| PublicKey::from_secret_key(SECP256K1, &sk));
    let e_p = if e == Scalar::ZERO {
        None
    } else {
        p.mul_tweak(SECP256K1, &e)
            .ok()
            .map(|point| point.negate(SECP256K1))
    };
    let r_point = match (s_g, e_p) {
        (Some(a), Some(b)) => match a.combine(&b) {
            Ok(point) => point,
            Err(_) => return false,
        },
        (Some(a), None) => a,
        (None, Some(b)) => b,
        (None, None) => return false,
    };
    let (r_x, parity) = r_point.x_only_public_key();
    parity == Parity::Even && r_x.serialize() == r_bytes
}

#[cfg(test)]
mod tests {
    #![expect(clippy::expect_used, reason = "test assertions")]

    use super::{CURVE_ORDER, reduce_mod_n, verify_bip340};

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
            .collect()
    }

    #[test]
    fn reduction_wraps_at_the_curve_order() {
        assert_eq!(reduce_mod_n(CURVE_ORDER), [0; 32]);
        let mut above = CURVE_ORDER;
        above[31] += 5;
        let mut expected = [0_u8; 32];
        expected[31] = 5;
        assert_eq!(reduce_mod_n(above), expected);
        assert_eq!(reduce_mod_n([0xff; 32])[..15], [0; 15]);
    }

    /// Rows of the BIP 340 `test-vectors.csv` at the pinned bips commit:
    /// `pubkey, message, signature, result`.
    #[test]
    fn bip340_vectors() {
        let csv = include_str!("../tests/data/bip340-test-vectors.csv");
        let mut checked = 0;
        for line in csv.lines().skip(1).filter(|l| !l.trim().is_empty()) {
            let cols: Vec<&str> = line.split(',').collect();
            let pubkey = hex(cols[2]);
            let msg = hex(cols[4]);
            let sig = hex(cols[5]);
            let expected = cols[6] == "TRUE";
            let result = match (
                <[u8; 32]>::try_from(pubkey.as_slice()),
                <[u8; 64]>::try_from(sig.as_slice()),
            ) {
                (Ok(pk), Ok(sig)) => verify_bip340(&sig, &msg, &pk),
                _ => false,
            };
            assert_eq!(result, expected, "BIP340 vector {}", cols[0]);
            checked += 1;
        }
        assert!(checked >= 19, "checked {checked} vectors");
    }
}
