use core::cmp::Ordering;

use smallvec::SmallVec;

use crate::{ScriptErrCode, ScriptError};

pub(crate) const COST: i64 = 50;
const MAX_WIDTH: usize = 32;
const ACC_WIDTH: usize = MAX_WIDTH + 1;
type Accumulator = [u8; ACC_WIDTH];

fn compare(a: &[u8], b: &[u8]) -> Ordering {
    a.iter().rev().cmp(b.iter().rev())
}

fn add_reduce(a: &Accumulator, b: &Accumulator, modulus: &Accumulator) -> Accumulator {
    let mut result = [0_u8; ACC_WIDTH];
    let mut carry = 0_u16;
    for i in 0..ACC_WIDTH {
        let sum = u16::from(a[i]) + u16::from(b[i]) + carry;
        result[i] = sum.to_le_bytes()[0];
        carry = sum >> 8;
    }
    if compare(&result, modulus) != Ordering::Less {
        let mut borrow = 0_i16;
        for i in 0..ACC_WIDTH {
            let difference = i16::from(result[i]) - i16::from(modulus[i]) - borrow;
            result[i] = difference.to_le_bytes()[0];
            borrow = i16::from(difference < 0);
        }
    }
    result
}

/// All residues are width-matched canonical unsigned values below a minimally encoded modulus.
pub(crate) fn evaluate(
    a: &[u8],
    b: &[u8],
    c: &[u8],
    m: &[u8],
) -> Result<SmallVec<[u8; 32]>, ScriptError> {
    let width = m.len();
    let invalid = || ScriptError::Invalid {
        code: ScriptErrCode::MulAddModEncoding,
    };
    if !(1..=MAX_WIDTH).contains(&width)
        || m.last() == Some(&0)
        || (width == 1 && m[0] < 2)
        || [a, b, c]
            .iter()
            .any(|x| x.len() != width || compare(x, m) != Ordering::Less)
    {
        return Err(invalid());
    }
    let mut modulus = [0_u8; ACC_WIDTH];
    let mut multiplicand = [0_u8; ACC_WIDTH];
    let mut addend = [0_u8; ACC_WIDTH];
    modulus[..width].copy_from_slice(m);
    multiplicand[..width].copy_from_slice(a);
    addend[..width].copy_from_slice(c);
    let mut result = [0_u8; ACC_WIDTH];
    for byte in b.iter().rev() {
        for bit in (0..8).rev() {
            result = add_reduce(&result, &result, &modulus);
            if byte & (1 << bit) != 0 {
                result = add_reduce(&result, &multiplicand, &modulus);
            }
        }
    }
    result = add_reduce(&result, &addend, &modulus);
    Ok(SmallVec::from_slice(&result[..width]))
}

#[cfg(test)]
mod tests;
