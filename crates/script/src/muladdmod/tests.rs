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
