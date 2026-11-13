#![expect(clippy::expect_used, reason = "independent arithmetic vectors")]

use std::process::Command;

use super::*;

fn decode(hex: &str) -> Vec<u8> {
    if hex == "-" {
        return Vec::new();
    }
    assert!(hex.len().is_multiple_of(2));
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("oracle hex"))
        .collect()
}

#[test]
fn independent_spiral_vectors_cover_every_width_and_canonical_rejection() {
    let run = Command::new("python3")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/muladdmod/vectors.py"
        ))
        .output()
        .expect("python3 is required for the experimental differential suite");
    assert!(
        run.status.success(),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    let text = String::from_utf8(run.stdout).expect("ASCII oracle output");
    let mut good = 0;
    let mut bad = 0;
    for (line, row) in text.lines().enumerate() {
        let columns: Vec<_> = row.split_whitespace().collect();
        assert_eq!(columns.len(), 5);
        let operands: Vec<_> = columns[..4].iter().map(|x| decode(x)).collect();
        let actual = evaluate(&operands[0], &operands[1], &operands[2], &operands[3]);
        if columns[4] == "ERR" {
            assert_eq!(
                actual,
                Err(ScriptError::Invalid {
                    code: ScriptErrCode::MulAddModEncoding
                }),
                "vector {line}"
            );
            bad += 1;
        } else {
            assert_eq!(
                actual.expect("valid oracle vector").as_slice(),
                decode(columns[4]),
                "vector {line}"
            );
            good += 1;
        }
    }
    assert_eq!((good, bad), (12037, 293));
}

#[test]
fn maximum_width_carry_is_reduced_without_truncation() {
    let m = [255; 32];
    let mut x = m;
    x[0] = 254;
    assert_eq!(
        evaluate(&x, &x, &x, &m).expect("canonical").as_slice(),
        [0; 32].as_slice()
    );
    assert_eq!(evaluate(&x, &x, &[0; 32], &m).expect("canonical")[0], 1);
}

#[test]
fn unsigned_high_bit_and_composite_modulus_have_integer_semantics() {
    assert_eq!(
        evaluate(&[128], &[1], &[0], &[251])
            .expect("unsigned residue")
            .as_slice(),
        [128].as_slice()
    );
    assert_eq!(
        evaluate(&[3], &[5], &[0], &[15])
            .expect("composite modulus")
            .as_slice(),
        [0].as_slice()
    );
}

mod properties {
    //! Property tests across every permitted width `1..=32` against an
    //! independent 64-bit limb (`u128` product) reference and ring identities.
    use proptest::prelude::*;

    use super::{ScriptErrCode, ScriptError, evaluate};

    fn unpack256(bytes: &[u8]) -> [u64; 4] {
        let mut limbs = [0_u64; 4];
        for (idx, chunk) in bytes.chunks(8).enumerate() {
            if let Some(slot) = limbs.get_mut(idx) {
                let mut buf = [0_u8; 8];
                if let Some(dst) = buf.get_mut(..chunk.len()) {
                    dst.copy_from_slice(chunk);
                }
                *slot = u64::from_le_bytes(buf);
            }
        }
        limbs
    }

    fn pack_le(limbs: &[u64; 4], width: usize) -> Vec<u8> {
        let mut raw = [0_u8; 32];
        for (idx, limb) in limbs.iter().enumerate() {
            if let Some(dst) = raw.get_mut(idx * 8..(idx + 1) * 8) {
                dst.copy_from_slice(&limb.to_le_bytes());
            }
        }
        raw.get(..width).unwrap_or_default().to_vec()
    }

    fn cmp_limbs<const N: usize>(a: &[u64; N], b: &[u64; N]) -> std::cmp::Ordering {
        for idx in (0..N).rev() {
            let lhs = a.get(idx).copied().unwrap_or(0);
            let rhs = b.get(idx).copied().unwrap_or(0);
            match lhs.cmp(&rhs) {
                std::cmp::Ordering::Equal => {}
                non_eq => return non_eq,
            }
        }
        std::cmp::Ordering::Equal
    }

    fn sub_assign_limbs<const N: usize>(acc: &mut [u64; N], rhs: &[u64; N]) {
        let mut borrow = 0_u64;
        for idx in 0..N {
            let lhs = acc.get(idx).copied().unwrap_or(0);
            let sub = rhs.get(idx).copied().unwrap_or(0);
            let (d1, b1) = lhs.overflowing_sub(sub);
            let (d2, b2) = d1.overflowing_sub(borrow);
            if let Some(slot) = acc.get_mut(idx) {
                *slot = d2;
            }
            borrow = u64::from(b1) + u64::from(b2);
        }
    }

    fn shl1_limbs<const N: usize>(acc: &mut [u64; N]) {
        let mut carry = 0_u64;
        for slot in acc.iter_mut() {
            let next = *slot >> 63;
            *slot = (*slot << 1) | carry;
            carry = next;
        }
    }

    fn rem_wide_by_256(numer: &[u64; 8], modulus: &[u64; 4]) -> [u64; 4] {
        let mut rem = [0_u64; 5];
        let mut mod5 = [0_u64; 5];
        mod5[..4].copy_from_slice(modulus);
        for limb in numer.iter().rev() {
            for bit in (0..64_u32).rev() {
                shl1_limbs(&mut rem);
                rem[0] |= (*limb >> bit) & 1;
                if cmp_limbs(&rem, &mod5) != std::cmp::Ordering::Less {
                    sub_assign_limbs(&mut rem, &mod5);
                }
            }
        }
        let mut out = [0_u64; 4];
        out.copy_from_slice(&rem[..4]);
        out
    }

    /// Independent schoolbook limb oracle for `(a * b + c) mod m` over 1..=32 bytes.
    fn ref_muladdmod(a: &[u8], b: &[u8], c: &[u8], m: &[u8]) -> Vec<u8> {
        let la = unpack256(a);
        let lb = unpack256(b);
        let lc = unpack256(c);
        let lm = unpack256(m);
        let mut prod = [0_u64; 8];
        for (i, &la_i) in la.iter().enumerate() {
            let mut carry = 0_u128;
            for (j, &lb_j) in lb.iter().enumerate() {
                let cur = u128::from(prod[i + j]) + u128::from(la_i) * u128::from(lb_j) + carry;
                prod[i + j] = u64::try_from(cur & u128::from(u64::MAX)).unwrap_or(0);
                carry = cur >> 64;
            }
            prod[i + 4] = u64::try_from(carry).unwrap_or(0);
        }
        let mut add_carry = 0_u128;
        for (i, slot) in prod.iter_mut().enumerate() {
            let addend = lc.get(i).copied().map_or(0, u128::from);
            let sum = u128::from(*slot) + addend + add_carry;
            *slot = u64::try_from(sum & u128::from(u64::MAX)).unwrap_or(0);
            add_carry = sum >> 64;
        }
        let rem = rem_wide_by_256(&prod, &lm);
        pack_le(&rem, m.len())
    }

    fn canonical_modulus(width: usize, seed: &[u8; 32]) -> Vec<u8> {
        let mut m = seed.get(..width).unwrap_or_default().to_vec();
        if let Some(last) = m.last_mut() {
            if *last == 0 {
                *last = 1;
            }
        }
        if width == 1 && m.first().copied().unwrap_or(0) < 2 {
            if let Some(first) = m.first_mut() {
                *first = 2;
            }
        }
        m
    }

    fn canonical_residue(raw: &[u8; 32], modulus: &[u8]) -> Vec<u8> {
        let mut numer = [0_u64; 8];
        numer[..4].copy_from_slice(&unpack256(&raw[..modulus.len()]));
        let lm = unpack256(modulus);
        let rem = rem_wide_by_256(&numer, &lm);
        pack_le(&rem, modulus.len())
    }

    fn cases() -> ProptestConfig {
        ProptestConfig {
            cases: std::env::var("PROPTEST_CASES")
                .ok()
                .and_then(|value| value.parse().ok())
                .unwrap_or(4096),
            ..ProptestConfig::default()
        }
    }

    proptest! {
        #![proptest_config(cases())]

        #[test]
        fn canonical_operands_match_limb_reference_across_all_widths(
            width in 1_usize..=32,
            m_seed in any::<[u8; 32]>(),
            a_seed in any::<[u8; 32]>(),
            b_seed in any::<[u8; 32]>(),
            c_seed in any::<[u8; 32]>(),
        ) {
            let m = canonical_modulus(width, &m_seed);
            let a = canonical_residue(&a_seed, &m);
            let b = canonical_residue(&b_seed, &m);
            let c = canonical_residue(&c_seed, &m);
            let got = evaluate(&a, &b, &c, &m);
            let expected = ref_muladdmod(&a, &b, &c, &m);
            prop_assert_eq!(got.as_ref().map(|r| r.to_vec()), Ok(expected));
            let result = got.unwrap_or_default();
            prop_assert_eq!(result.len(), width);
            prop_assert_eq!(
                cmp_limbs(&unpack256(&result), &unpack256(&m)),
                std::cmp::Ordering::Less
            );
        }

        #[test]
        fn ring_identities_commutativity_and_distributivity_hold(
            width in 1_usize..=32,
            m_seed in any::<[u8; 32]>(),
            a1_seed in any::<[u8; 32]>(),
            a2_seed in any::<[u8; 32]>(),
            b_seed in any::<[u8; 32]>(),
            c_seed in any::<[u8; 32]>(),
        ) {
            let m = canonical_modulus(width, &m_seed);
            let a1 = canonical_residue(&a1_seed, &m);
            let a2 = canonical_residue(&a2_seed, &m);
            let b = canonical_residue(&b_seed, &m);
            let c = canonical_residue(&c_seed, &m);
            let zero = vec![0_u8; width];
            let mut one = vec![0_u8; width];
            if let Some(first) = one.first_mut() {
                *first = 1;
            }
            prop_assert_eq!(evaluate(&a1, &b, &c, &m), evaluate(&b, &a1, &c, &m));
            let mul_id = evaluate(&a1, &one, &zero, &m).map(|r| r.to_vec());
            let add_id = evaluate(&a1, &zero, &c, &m).map(|r| r.to_vec());
            prop_assert_eq!(mul_id, Ok(a1.clone()));
            prop_assert_eq!(add_id, Ok(c.clone()));
            let sum_a = evaluate(&a1, &one, &a2, &m).expect("sum canonical");
            let lhs = evaluate(&sum_a, &b, &c, &m).expect("lhs canonical");
            let part1 = evaluate(&a1, &b, &zero, &m).expect("part1 canonical");
            let part2 = evaluate(&a2, &b, &c, &m).expect("part2 canonical");
            let rhs = evaluate(&part1, &one, &part2, &m).expect("rhs canonical");
            prop_assert_eq!(lhs, rhs);
        }

        #[test]
        fn any_operand_at_or_above_the_modulus_is_rejected(
            width in 1_usize..=32,
            m_seed in any::<[u8; 32]>(),
            good_seed in any::<[u8; 32]>(),
            delta in any::<u8>(),
            slot in 0_usize..3,
        ) {
            let m = canonical_modulus(width, &m_seed);
            let good = canonical_residue(&good_seed, &m);
            // Build bad >= m of the exact same width (saturating to all-0xff if m + delta overflows width)
            let mut bad = m.clone();
            let mut carry = u16::from(delta);
            for byte in &mut bad {
                let s = u16::from(*byte) + carry;
                *byte = u8::try_from(s & 0xff).unwrap_or(0xff);
                carry = s >> 8;
            }
            if carry > 0 {
                bad.fill(0xff);
            }
            let mut operands = [good.clone(), good.clone(), good];
            if let Some(operand) = operands.get_mut(slot) {
                *operand = bad;
            }
            let [a, b, c] = &operands;
            prop_assert_eq!(
                evaluate(a, b, c, &m),
                Err(ScriptError::Invalid { code: ScriptErrCode::MulAddModEncoding })
            );
        }

        #[test]
        fn width_mismatch_and_nonminimal_modulus_are_rejected(
            width in 1_usize..=32,
            m_seed in any::<[u8; 32]>(),
            x_seed in any::<[u8; 32]>(),
            slot in 0_usize..4,
            grow in any::<bool>(),
        ) {
            let m = canonical_modulus(width, &m_seed);
            let x = canonical_residue(&x_seed, &m);
            let mut operands = [x.clone(), x.clone(), x, m];
            if let Some(operand) = operands.get_mut(slot) {
                if grow {
                    operand.push(0);
                } else {
                    operand.pop();
                }
            }
            let [a, b, c, modulus] = &operands;
            prop_assert_eq!(
                evaluate(a, b, c, modulus),
                Err(ScriptError::Invalid { code: ScriptErrCode::MulAddModEncoding })
            );
        }
    }
}
