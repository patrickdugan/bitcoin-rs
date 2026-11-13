//! Validation-cost benchmark for the experimental `OP_MULADDMOD` charge.
//!
//! Measures single-threaded tapscript execution time per operation for
//! arithmetic (every operand width 1..=32 and several modulus classes), for
//! BIP342-priced Schnorr checks, for mixed scripts, and for the unpriced
//! `DUP SHA256 DROP` pattern that tapscript already permits. Also executes one
//! maximum-density spend sized for a 4,000,000 weight-unit block.
//!
//! Output is one JSON document on stdout. Research tooling only.
//!
//! cargo run --release -p bitcoin-rs-script --features experimental-muladdmod \
//!   --example muladdmod_cost -- [repetitions]
#![expect(
    clippy::expect_used,
    reason = "benchmark fixtures abort on setup errors"
)]

use std::fmt::Write as _;
use std::time::{Duration, Instant};

use bitcoin::hashes::Hash as _;
use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey};
use bitcoin::sighash::{Annex, Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::{LeafVersion, TapLeafHash, TaprootBuilder};
use bitcoin::{ScriptBuf, Transaction};
use bitcoin_rs_primitives::{Amount, OutPoint, Script, Tx, TxOut, deserialize};
use bitcoin_rs_script::{PreparedTransaction, VerifyFlags};

const OP_MULADDMOD: u8 = 0xf0;
const OP_2OVER: u8 = 0x70;
const OP_DROP: u8 = 0x75;
const OP_2DROP: u8 = 0x6d;
const OP_2DUP: u8 = 0x6e;
const OP_DUP: u8 = 0x76;
const OP_SHA256: u8 = 0xa8;
const OP_CHECKSIGVERIFY: u8 = 0xad;
const OP_PICK: u8 = 0x79;
const OP_5: u8 = 0x55;
const OP_TRUE: u8 = 0x51;
const BLOCK_WEIGHT: usize = 4_000_000;

struct Fixture {
    tx: Tx,
    prevouts: Vec<(OutPoint, TxOut)>,
    witness_bytes: usize,
}

/// Build a one-input script-path spend. `sig_slots` lists witness indexes to
/// replace with a valid BIP340 signature (default sighash) for `keypair`.
fn fixture(script: &[u8], stack: &[Vec<u8>], annex_len: usize, sig_slots: &[usize]) -> Fixture {
    let secp = Secp256k1::new();
    let keypair = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[37; 32]).expect("key"));
    let leaf = ScriptBuf::from_bytes(script.to_vec());
    let tree = TaprootBuilder::new()
        .add_leaf(0, leaf.clone())
        .expect("leaf")
        .finalize(&secp, keypair.x_only_public_key().0)
        .expect("tree");
    let control = tree
        .control_block(&(leaf.clone(), LeafVersion::TapScript))
        .expect("control");
    let spk = ScriptBuf::new_p2tr_tweaked(tree.output_key());
    let prev = bitcoin::TxOut {
        value: bitcoin::Amount::from_sat(1_000_000),
        script_pubkey: spk.clone(),
    };
    let mut annex = Vec::new();
    if annex_len > 0 {
        annex = vec![0_u8; annex_len];
        if let Some(first) = annex.first_mut() {
            *first = 0x50;
        }
    }
    let mut tx = Transaction {
        version: bitcoin::transaction::Version(2),
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![bitcoin::TxIn {
            previous_output: bitcoin::OutPoint::new(bitcoin::Txid::from_byte_array([17; 32]), 0),
            script_sig: ScriptBuf::new(),
            sequence: bitcoin::Sequence::MAX,
            witness: bitcoin::Witness::new(),
        }],
        output: vec![bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(900_000),
            script_pubkey: ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array([42; 20])),
        }],
    };
    let mut items = stack.to_vec();
    if !sig_slots.is_empty() {
        let leaf_hash = TapLeafHash::from_script(&leaf, LeafVersion::TapScript);
        let annex_opt = if annex.is_empty() {
            None
        } else {
            Some(Annex::new(&annex).expect("annex"))
        };
        let sighash = SighashCache::new(&tx)
            .taproot_signature_hash(
                0,
                &Prevouts::All(std::slice::from_ref(&prev)),
                annex_opt,
                Some((leaf_hash, 0xffff_ffff)),
                TapSighashType::Default,
            )
            .expect("sighash");
        let message = Message::from_digest(sighash.to_byte_array());
        let signature = secp.sign_schnorr_no_aux_rand(&message, &keypair);
        for slot in sig_slots {
            if let Some(item) = items.get_mut(*slot) {
                *item = signature.as_ref().to_vec();
            }
        }
        for item in &mut items {
            if item.len() == 32 && item.iter().all(|b| *b == 0xee) {
                *item = keypair.x_only_public_key().0.serialize().to_vec();
            }
        }
    }
    items.push(leaf.to_bytes());
    items.push(control.serialize());
    if !annex.is_empty() {
        items.push(annex);
    }
    let witness = bitcoin::Witness::from_slice(&items);
    let witness_bytes = witness.size();
    if let Some(input) = tx.input.first_mut() {
        input.witness = witness;
    }
    let native: Tx = deserialize(&bitcoin::consensus::serialize(&tx)).expect("native tx");
    let outpoint = native.inputs.first().expect("input").previous_output;
    Fixture {
        tx: native,
        prevouts: vec![(
            outpoint,
            TxOut {
                value: Amount::from_sat(1_000_000),
                script_pubkey: Script::from_bytes(spk.to_bytes()),
            },
        )],
        witness_bytes,
    }
}

fn flags() -> VerifyFlags {
    VerifyFlags::MANDATORY.union(VerifyFlags::EXPERIMENTAL_MULADDMOD)
}

fn verify_time(fixture: &Fixture, reps: u32) -> Duration {
    let prepared = PreparedTransaction::new(&fixture.tx, &fixture.prevouts).expect("prevouts");
    let mut samples = Vec::with_capacity(usize::try_from(reps).unwrap_or(1));
    for _ in 0..reps {
        let start = Instant::now();
        let result = prepared.verify_input(0, flags(), None);
        let elapsed = start.elapsed();
        assert_eq!(result, Ok(true), "benchmark fixture must be valid");
        samples.push(elapsed);
    }
    samples.sort();
    samples
        .get(samples.len() / 2)
        .copied()
        .unwrap_or(Duration::ZERO)
}

fn repeat(unit: &[u8], count: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(unit.len() * count);
    for _ in 0..count {
        out.extend_from_slice(unit);
    }
    out
}

/// Arithmetic script: K x (2OVER 2OVER MULADDMOD DROP), then 2DROP 2DROP TRUE.
fn arithmetic_fixture(operands: &[Vec<u8>; 4], k: usize) -> Fixture {
    let mut script = repeat(&[OP_2OVER, OP_2OVER, OP_MULADDMOD, OP_DROP], k);
    script.extend_from_slice(&[OP_2DROP, OP_2DROP, OP_TRUE]);
    fixture(&script, operands, k * 50 + 64, &[])
}

/// Schnorr script: K x (2DUP CHECKSIGVERIFY), then 2DROP TRUE.
fn schnorr_fixture(k: usize) -> Fixture {
    let mut script = repeat(&[OP_2DUP, OP_CHECKSIGVERIFY], k);
    script.extend_from_slice(&[OP_2DROP, OP_TRUE]);
    fixture(&script, &[vec![0; 64], vec![0xee; 32]], k * 50 + 64, &[0])
}

/// Mixed: K x (2OVER 2OVER MULADDMOD DROP 5 PICK 5 PICK CHECKSIGVERIFY).
fn mixed_fixture(operands: &[Vec<u8>; 4], k: usize) -> Fixture {
    let mut script = repeat(
        &[
            OP_2OVER,
            OP_2OVER,
            OP_MULADDMOD,
            OP_DROP,
            OP_5,
            OP_PICK,
            OP_5,
            OP_PICK,
            OP_CHECKSIGVERIFY,
        ],
        k,
    );
    script.extend_from_slice(&[OP_2DROP, OP_2DROP, OP_2DROP, OP_TRUE]);
    let mut stack = vec![vec![0; 64], vec![0xee; 32]];
    stack.extend(operands.iter().cloned());
    fixture(&script, &stack, k * 100 + 64, &[0])
}

/// Unpriced hashing that tapscript already allows: K x (DUP SHA256 DROP) on 520 bytes.
fn sha_fixture(k: usize) -> Fixture {
    let mut script = repeat(&[OP_DUP, OP_SHA256, OP_DROP], k);
    script.extend_from_slice(&[OP_DROP, OP_TRUE]);
    fixture(&script, &[vec![0xab; 520]], 0, &[])
}

fn per_op(make: &dyn Fn(usize) -> Fixture, k: usize, reps: u32) -> (f64, usize) {
    let base = verify_time(&make(0), reps);
    let fixture = make(k);
    let full = verify_time(&fixture, reps);
    let delta = full.saturating_sub(base).as_secs_f64();
    let k_f = f64::from(u32::try_from(k).unwrap_or(u32::MAX));
    (delta / k_f * 1e9, fixture.witness_bytes)
}

fn le_bytes(value_hex_be: &[u8]) -> Vec<u8> {
    let mut out = value_hex_be.to_vec();
    out.reverse();
    out
}

fn operands_for(modulus_le: Vec<u8>, b_le: Vec<u8>) -> [Vec<u8>; 4] {
    let mut m_minus_1 = modulus_le.clone();
    for byte in &mut m_minus_1 {
        if *byte == 0 {
            *byte = 0xff;
        } else {
            *byte -= 1;
            break;
        }
    }
    [m_minus_1.clone(), b_le, m_minus_1, modulus_le]
}

fn main() {
    let reps: u32 = std::env::args()
        .nth(1)
        .and_then(|value| value.parse().ok())
        .unwrap_or(15);
    let k = 2000_usize;
    let mut json = String::from("{\n  \"k_ops_per_measurement\": 2000,\n");
    let _ = writeln!(json, "  \"repetitions\": {reps},");
    json.push_str("  \"muladdmod_by_width\": [\n");
    for width in 1..=32_usize {
        let max_m = vec![0xff_u8; width];
        let mut b_max = max_m.clone();
        if let Some(low) = b_max.first_mut() {
            *low = 0xfe;
        }
        let mut low_m = vec![0_u8; width];
        if let Some(top) = low_m.last_mut() {
            *top = 1;
        }
        if let Some(first) = low_m.first_mut() {
            *first |= 1;
        }
        if width == 1 {
            low_m = vec![3];
        }
        let mut b_low = low_m.clone();
        if let Some(first) = b_low.first_mut() {
            *first -= 1;
        }
        let classes: [(&str, [Vec<u8>; 4]); 2] = [
            ("max_modulus_b_all_ones", operands_for(max_m, b_max)),
            ("min_top_byte_modulus", operands_for(low_m, b_low)),
        ];
        for (name, operands) in &classes {
            let (ns, witness) = per_op(&|n| arithmetic_fixture(operands, n), k, reps);
            let _ = writeln!(
                json,
                "    {{\"width\": {width}, \"class\": \"{name}\", \"ns_per_op\": {ns:.1}, \"ns_per_budget_unit\": {:.2}, \"witness_bytes_at_k\": {witness}}},",
                ns / 50.0
            );
        }
    }
    let p25519 = le_bytes(&{
        let mut v = vec![0x7f_u8];
        v.extend(vec![0xff_u8; 30]);
        v.push(0xed);
        v
    });
    let composite_small = operands_for(vec![15], vec![14]);
    let prime_small = operands_for(vec![17], vec![16]);
    let p25519_ops = operands_for(p25519.clone(), {
        let mut b = p25519;
        if let Some(first) = b.first_mut() {
            *first -= 1;
        }
        b
    });
    let specials: [(&str, &[Vec<u8>; 4]); 3] = [
        ("m15_composite_1byte", &composite_small),
        ("m17_prime_1byte", &prime_small),
        ("m_2p255_minus_19", &p25519_ops),
    ];
    json.push_str("    null\n  ],\n  \"muladdmod_special\": [\n");
    for (name, operands) in specials {
        let (ns, _) = per_op(&|n| arithmetic_fixture(operands, n), k, reps);
        let _ = writeln!(
            json,
            "    {{\"class\": \"{name}\", \"ns_per_op\": {ns:.1}, \"ns_per_budget_unit\": {:.2}}},",
            ns / 50.0
        );
    }
    json.push_str("    null\n  ],\n");
    let (schnorr_ns, _) = per_op(&schnorr_fixture, k, reps);
    let _ = writeln!(
        json,
        "  \"schnorr_checksigverify\": {{\"ns_per_op\": {schnorr_ns:.1}, \"ns_per_budget_unit\": {:.2}}},",
        schnorr_ns / 50.0
    );
    let worst = operands_for(vec![0xff; 32], {
        let mut b = vec![0xff; 32];
        if let Some(first) = b.first_mut() {
            *first = 0xfe;
        }
        b
    });
    let (mixed_ns, _) = per_op(&|n| mixed_fixture(&worst, n), k / 2, reps);
    let _ = writeln!(
        json,
        "  \"mixed_arith_plus_schnorr\": {{\"ns_per_pair\": {mixed_ns:.1}, \"ns_per_budget_unit\": {:.2}}},",
        mixed_ns / 100.0
    );
    let (sha_ns, _) = per_op(&sha_fixture, k, reps);
    let _ = writeln!(
        json,
        "  \"unpriced_sha256_520\": {{\"ns_per_op\": {sha_ns:.1}, \"script_bytes_per_op\": 3, \"ns_per_witness_byte\": {:.2}}},",
        sha_ns / 3.0
    );
    let block_ops = (BLOCK_WEIGHT - 2_000) / 54;
    let max_fixture = arithmetic_fixture(&worst, block_ops);
    let max_time = verify_time(&max_fixture, 3);
    let sig_fixture = schnorr_fixture(block_ops);
    let sig_time = verify_time(&sig_fixture, 3);
    let _ = writeln!(
        json,
        "  \"block_sized_single_input\": {{\"ops\": {block_ops}, \"muladdmod_witness_bytes\": {}, \"muladdmod_seconds\": {:.4}, \"schnorr_witness_bytes\": {}, \"schnorr_seconds\": {:.4}}}",
        max_fixture.witness_bytes,
        max_time.as_secs_f64(),
        sig_fixture.witness_bytes,
        sig_time.as_secs_f64()
    );
    json.push_str("}\n");
    print!("{json}");
}
