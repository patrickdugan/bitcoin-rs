#![expect(clippy::expect_used)]

use bitcoin::hashes::{Hash as _, sha256};
use bitcoin::hex::FromHex as _;
use bitcoin::opcodes::{Opcode, all::OP_EQUAL};
use bitcoin::script::Builder;
use bitcoin::secp256k1::{Keypair, Message, Secp256k1, XOnlyPublicKey};
use bitcoin::taproot::{LeafVersion, TaprootBuilder};
use bitcoin::{Amount, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
use bitcoin_rs_primitives::{Script, Tx};
use bitcoin_rs_script::{
    Interpreter, OP_CHECKSIGFROMSTACK, OP_INTERNALKEY, OP_TEMPLATEHASH, ScriptErrCode, ScriptError,
    VerifyFlags,
};
use sonic_rs::{JsonContainerTrait as _, JsonValueTrait as _};

const ON: VerifyFlags = VerifyFlags::MANDATORY.union(VerifyFlags::BIP448);
const ON_STANDARD: VerifyFlags = VerifyFlags::STANDARD.union(VerifyFlags::BIP448);

fn op(byte: u8) -> Opcode {
    Opcode::from(byte)
}

fn keypair(seed: u8) -> Keypair {
    Keypair::from_seckey_slice(&Secp256k1::new(), &[seed; 32]).expect("key")
}

fn tapleaf_output(script: &ScriptBuf, internal: XOnlyPublicKey) -> (ScriptBuf, Vec<u8>) {
    let secp = Secp256k1::new();
    let info = TaprootBuilder::new()
        .add_leaf(0, script.clone())
        .expect("leaf")
        .finalize(&secp, internal)
        .expect("finalize");
    let control = info
        .control_block(&(script.clone(), LeafVersion::TapScript))
        .expect("control")
        .serialize();
    (ScriptBuf::new_p2tr_tweaked(info.output_key()), control)
}

fn spend_tx(inputs: usize) -> Transaction {
    Transaction {
        version: bitcoin::transaction::Version(2),
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: (0..inputs)
            .map(|i| TxIn {
                previous_output: bitcoin::OutPoint::new(
                    bitcoin::Txid::from_byte_array([17; 32]),
                    u32::try_from(i).expect("index"),
                ),
                script_sig: ScriptBuf::new(),
                sequence: Sequence(0xffff_fffd),
                witness: Witness::new(),
            })
            .collect(),
        output: vec![TxOut {
            value: Amount::from_sat(99_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    }
}

/// Independent BIP 446 template hash straight from the BIP text.
fn template_hash(tx: &Transaction, index: u32, annex: Option<&[u8]>) -> [u8; 32] {
    use bitcoin::consensus::Encodable as _;
    let mut sequences = Vec::new();
    for input in &tx.input {
        sequences.extend_from_slice(&input.sequence.0.to_le_bytes());
    }
    let mut outputs = Vec::new();
    for output in &tx.output {
        output.consensus_encode(&mut outputs).expect("encode");
    }
    let mut msg = Vec::new();
    msg.extend_from_slice(&tx.version.0.to_le_bytes());
    msg.extend_from_slice(&tx.lock_time.to_consensus_u32().to_le_bytes());
    msg.extend_from_slice(sha256::Hash::hash(&sequences).as_byte_array());
    msg.extend_from_slice(sha256::Hash::hash(&outputs).as_byte_array());
    msg.push(u8::from(annex.is_some()));
    msg.extend_from_slice(&index.to_le_bytes());
    if let Some(annex) = annex {
        let mut prefixed = vec![u8::try_from(annex.len()).expect("short annex")];
        prefixed.extend_from_slice(annex);
        msg.extend_from_slice(sha256::Hash::hash(&prefixed).as_byte_array());
    }
    let tag = sha256::Hash::hash(b"TemplateHash");
    let mut full = Vec::new();
    full.extend_from_slice(tag.as_byte_array());
    full.extend_from_slice(tag.as_byte_array());
    full.extend_from_slice(&msg);
    sha256::Hash::hash(&full).to_byte_array()
}

fn run_input(
    tx: &Transaction,
    prevout_spk: &ScriptBuf,
    index: usize,
    flags: VerifyFlags,
) -> Result<bool, ScriptError> {
    let native: Tx = bitcoin_rs_primitives::deserialize(&bitcoin::consensus::serialize(tx))
        .expect("native decode");
    let prevouts: Vec<_> = tx
        .input
        .iter()
        .map(|_| bitcoin_rs_primitives::TxOut {
            value: bitcoin_rs_primitives::Amount::from_sat(100_000),
            script_pubkey: Script::from_bytes(prevout_spk.to_bytes()),
        })
        .collect();
    let input = &native.inputs[index];
    let result = Interpreter.execute_with_prevouts(
        &prevouts[index].script_pubkey,
        &input.script_sig,
        &input.witness,
        flags,
        &prevouts,
        &native,
        index,
    );
    let prepared_rows: Vec<_> = native
        .inputs
        .iter()
        .map(|i| i.previous_output)
        .zip(prevouts.iter().cloned())
        .collect();
    let prepared = bitcoin_rs_script::PreparedTransaction::new(&native, &prepared_rows)
        .expect("prevouts")
        .verify_input(index, flags, None);
    assert_eq!(result, prepared, "interpreter and prepared paths agree");
    result
}

/// Spends a one-leaf taproot output with `script`, witness items below it.
fn spend_leaf(
    script: &ScriptBuf,
    items: &[Vec<u8>],
    internal: XOnlyPublicKey,
    flags: VerifyFlags,
) -> Result<bool, ScriptError> {
    let (spk, control) = tapleaf_output(script, internal);
    let mut tx = spend_tx(1);
    let mut witness = Witness::new();
    for item in items {
        witness.push(item);
    }
    witness.push(script.as_bytes());
    witness.push(&control);
    tx.input[0].witness = witness;
    run_input(&tx, &spk, 0, flags)
}

fn is_eval_false(result: &Result<bool, ScriptError>) -> bool {
    matches!(
        result,
        Err(ScriptError::Invalid {
            code: ScriptErrCode::EvalFalse
        })
    )
}

fn err_code(result: &Result<bool, ScriptError>) -> Option<ScriptErrCode> {
    match result {
        Err(ScriptError::Invalid { code }) => Some(*code),
        _ => None,
    }
}

fn internal() -> (Keypair, XOnlyPublicKey) {
    let kp = keypair(0x21);
    let (xonly, _) = kp.x_only_public_key();
    (kp, xonly)
}

#[test]
fn opcode_bytes_match_the_bips() {
    assert_eq!(OP_INTERNALKEY, 0xcb);
    assert_eq!(OP_CHECKSIGFROMSTACK, 0xcc);
    assert_eq!(OP_TEMPLATEHASH, 0xce);
}

#[test]
fn flag_off_the_bytes_stay_op_success() {
    let (_, xonly) = internal();
    for byte in [0xcb_u8, 0xcc, 0xce] {
        let script = Builder::new().push_opcode(op(byte)).into_script();
        assert_eq!(
            spend_leaf(&script, &[], xonly, VerifyFlags::MANDATORY),
            Ok(true),
            "byte {byte:#x} is OP_SUCCESS without the flag"
        );
        assert_eq!(
            err_code(&spend_leaf(&script, &[], xonly, VerifyFlags::STANDARD)),
            Some(ScriptErrCode::DiscourageOpSuccess),
            "standardness still discourages byte {byte:#x} without the flag"
        );
    }
}

#[test]
fn flag_on_the_bytes_are_no_longer_op_success() {
    let (_, xonly) = internal();
    let csfs = Builder::new().push_opcode(op(0xcc)).into_script();
    assert_eq!(
        err_code(&spend_leaf(&csfs, &[], xonly, ON)),
        Some(ScriptErrCode::InvalidStackOperation)
    );
    let bad = Builder::new()
        .push_opcode(op(0xce))
        .push_slice([0_u8; 32])
        .push_opcode(OP_EQUAL)
        .into_script();
    assert!(is_eval_false(&spend_leaf(&bad, &[], xonly, ON)));
    let ik = Builder::new()
        .push_opcode(op(0xcb))
        .push_slice(xonly.serialize())
        .push_opcode(OP_EQUAL)
        .into_script();
    assert_eq!(spend_leaf(&ik, &[], xonly, ON_STANDARD), Ok(true));
}

#[test]
fn internalkey_pushes_the_taproot_internal_key() {
    let (_, xonly) = internal();
    let ik = Builder::new()
        .push_opcode(op(0xcb))
        .push_slice(xonly.serialize())
        .push_opcode(OP_EQUAL)
        .into_script();
    assert_eq!(spend_leaf(&ik, &[], xonly, ON), Ok(true));
    let other = keypair(0x22).x_only_public_key().0;
    assert!(is_eval_false(&spend_leaf(&ik, &[], other, ON)));
    let ik_other = Builder::new()
        .push_opcode(op(0xcb))
        .push_slice(other.serialize())
        .push_opcode(OP_EQUAL)
        .into_script();
    assert_eq!(spend_leaf(&ik_other, &[], other, ON), Ok(true));
}

fn template_leaf(hash: [u8; 32]) -> ScriptBuf {
    Builder::new()
        .push_opcode(op(0xce))
        .push_slice(hash)
        .push_opcode(OP_EQUAL)
        .into_script()
}

#[test]
fn templatehash_matches_the_bip_preimage() {
    let (_, xonly) = internal();
    let mut tx = spend_tx(1);
    let script = template_leaf(template_hash(&tx, 0, None));
    let (spk, control) = tapleaf_output(&script, xonly);
    let mut witness = Witness::new();
    witness.push(script.as_bytes());
    witness.push(&control);
    tx.input[0].witness = witness;
    assert_eq!(run_input(&tx, &spk, 0, ON), Ok(true));

    let mutate = |f: &dyn Fn(&mut Transaction)| {
        let mut other = tx.clone();
        f(&mut other);
        run_input(&other, &spk, 0, ON)
    };
    assert!(is_eval_false(&mutate(
        &|t| t.version = bitcoin::transaction::Version(3)
    )));
    assert!(is_eval_false(&mutate(&|t| {
        t.lock_time = bitcoin::absolute::LockTime::from_height(7).expect("height");
    })));
    assert!(is_eval_false(&mutate(
        &|t| t.input[0].sequence = Sequence(0xffff_fffe)
    )));
    assert!(is_eval_false(&mutate(
        &|t| t.output[0].value = Amount::from_sat(98_999)
    )));
    assert!(is_eval_false(&mutate(&|t| {
        t.output[0].script_pubkey = ScriptBuf::from_bytes(vec![0x00]);
    })));
    assert!(is_eval_false(&mutate(&|t| t
        .output
        .push(t.output[0].clone()))));
    assert_eq!(
        mutate(&|t| {
            t.input[0].previous_output =
                bitcoin::OutPoint::new(bitcoin::Txid::from_byte_array([99; 32]), 5);
        }),
        Ok(true),
        "the spent outpoint is not committed"
    );
}

#[test]
fn templatehash_commits_to_the_input_index() {
    let (_, xonly) = internal();
    let mut tx = spend_tx(2);
    let script = template_leaf(template_hash(&tx, 1, None));
    let (spk, control) = tapleaf_output(&script, xonly);
    for i in 0..2 {
        let mut witness = Witness::new();
        witness.push(script.as_bytes());
        witness.push(&control);
        tx.input[i].witness = witness;
    }
    assert_eq!(run_input(&tx, &spk, 1, ON), Ok(true));
    assert!(is_eval_false(&run_input(&tx, &spk, 0, ON)));
}

#[test]
fn templatehash_commits_to_the_annex() {
    let (_, xonly) = internal();
    let annex = vec![0x50_u8, 1, 2, 3];
    let mut tx = spend_tx(1);
    let with_annex = template_leaf(template_hash(&tx, 0, Some(&annex)));
    let (spk, control) = tapleaf_output(&with_annex, xonly);
    let mut witness = Witness::new();
    witness.push(with_annex.as_bytes());
    witness.push(&control);
    witness.push(&annex);
    tx.input[0].witness = witness;
    assert_eq!(run_input(&tx, &spk, 0, ON), Ok(true));
    let mut other_annex = tx.clone();
    let mut witness = Witness::new();
    witness.push(with_annex.as_bytes());
    witness.push(&control);
    witness.push([0x50_u8, 9]);
    other_annex.input[0].witness = witness;
    assert!(is_eval_false(&run_input(&other_annex, &spk, 0, ON)));
    assert_ne!(
        template_hash(&tx, 0, None),
        template_hash(&tx, 0, Some(&annex))
    );
}

fn csfs_script() -> ScriptBuf {
    Builder::new().push_opcode(op(0xcc)).into_script()
}

fn sign(kp: &Keypair, message: [u8; 32]) -> Vec<u8> {
    Secp256k1::new()
        .sign_schnorr_no_aux_rand(&Message::from_digest(message), kp)
        .serialize()
        .to_vec()
}

#[test]
fn csfs_accepts_a_valid_signature_and_pushes_one() {
    let (kp, xonly) = internal();
    let msg = [7_u8; 32];
    let sig = sign(&kp, msg);
    let items = [sig, msg.to_vec(), xonly.serialize().to_vec()];
    assert_eq!(spend_leaf(&csfs_script(), &items, xonly, ON), Ok(true));
    assert_eq!(
        spend_leaf(&csfs_script(), &items, xonly, ON_STANDARD),
        Ok(true)
    );
    let eq_one = Builder::new()
        .push_opcode(op(0xcc))
        .push_slice([1_u8])
        .push_opcode(OP_EQUAL)
        .into_script();
    assert_eq!(spend_leaf(&eq_one, &items, xonly, ON), Ok(true));
}

#[test]
fn csfs_rejects_wrong_signature_message_or_key() {
    let (kp, xonly) = internal();
    let msg = [7_u8; 32];
    let sig = sign(&kp, msg);
    let pk = xonly.serialize().to_vec();

    let wrong_msg = [sig.clone(), [8_u8; 32].to_vec(), pk.clone()];
    assert_eq!(
        err_code(&spend_leaf(&csfs_script(), &wrong_msg, xonly, ON)),
        Some(ScriptErrCode::SchnorrSig)
    );
    let mut flipped = sig.clone();
    flipped[10] ^= 1;
    let bad_sig = [flipped, msg.to_vec(), pk.clone()];
    assert_eq!(
        err_code(&spend_leaf(&csfs_script(), &bad_sig, xonly, ON)),
        Some(ScriptErrCode::SchnorrSig)
    );
    let other = keypair(0x23).x_only_public_key().0.serialize().to_vec();
    let wrong_key = [sig.clone(), msg.to_vec(), other];
    assert_eq!(
        err_code(&spend_leaf(&csfs_script(), &wrong_key, xonly, ON)),
        Some(ScriptErrCode::SchnorrSig)
    );
    let mut long = sig.clone();
    long.push(0x01);
    let sized = [long, msg.to_vec(), pk.clone()];
    assert_eq!(
        err_code(&spend_leaf(&csfs_script(), &sized, xonly, ON)),
        Some(ScriptErrCode::SchnorrSigSize)
    );
    let short = [sig[..63].to_vec(), msg.to_vec(), pk];
    assert_eq!(
        err_code(&spend_leaf(&csfs_script(), &short, xonly, ON)),
        Some(ScriptErrCode::SchnorrSigSize)
    );
}

#[test]
fn csfs_empty_signature_pushes_an_empty_vector() {
    let (_, xonly) = internal();
    let items = [vec![], vec![9_u8; 5], xonly.serialize().to_vec()];
    let script = Builder::new()
        .push_opcode(op(0xcc))
        .push_opcode(bitcoin::opcodes::all::OP_PUSHBYTES_0)
        .push_opcode(OP_EQUAL)
        .into_script();
    assert_eq!(spend_leaf(&script, &items, xonly, ON), Ok(true));
    assert!(is_eval_false(&spend_leaf(
        &csfs_script(),
        &items,
        xonly,
        ON
    )));
}

#[test]
fn csfs_pubkey_size_rules() {
    let (kp, xonly) = internal();
    let msg = [1_u8; 32];
    let sig = sign(&kp, msg);
    for sig_item in [sig.clone(), vec![]] {
        let items = [sig_item, msg.to_vec(), vec![]];
        assert_eq!(
            err_code(&spend_leaf(&csfs_script(), &items, xonly, ON)),
            Some(ScriptErrCode::TapscriptEmptyPubkey)
        );
    }
    for len in [1_usize, 31, 33, 64] {
        let items = [vec![0xaa_u8; 64], msg.to_vec(), vec![0x02; len]];
        assert_eq!(
            spend_leaf(&csfs_script(), &items, xonly, ON),
            Ok(true),
            "unknown key type of {len} bytes"
        );
        assert_eq!(
            err_code(&spend_leaf(&csfs_script(), &items, xonly, ON_STANDARD)),
            Some(ScriptErrCode::DiscourageUpgradablePubkeyType)
        );
    }
    let mut bad_x = [0xff_u8; 32];
    bad_x[31] = 0x2f;
    let items = [sig, msg.to_vec(), bad_x.to_vec()];
    assert_eq!(
        err_code(&spend_leaf(&csfs_script(), &items, xonly, ON)),
        Some(ScriptErrCode::SchnorrSig)
    );
}

#[test]
fn csfs_stack_underflow_fails() {
    let (_, xonly) = internal();
    for count in 0..3 {
        let items: Vec<Vec<u8>> = (0..count).map(|_| vec![1_u8; 32]).collect();
        assert_eq!(
            err_code(&spend_leaf(&csfs_script(), &items, xonly, ON)),
            Some(ScriptErrCode::InvalidStackOperation),
            "{count} items"
        );
    }
}

#[test]
fn csfs_spends_sigops_budget_only_for_non_empty_signatures() {
    let (_, xonly) = internal();
    let repeated = |n: usize, sig: &[u8]| {
        let mut builder = Builder::new();
        for _ in 0..n {
            builder = builder
                .push_opcode(op(0xcc))
                .push_opcode(bitcoin::opcodes::all::OP_DROP);
        }
        let script = builder.push_opcode(bitcoin::opcodes::OP_TRUE).into_script();
        let mut items = Vec::new();
        for _ in 0..n {
            items.push(sig.to_vec());
            items.push(vec![0_u8; 1]);
            items.push(vec![0x02; 33]);
        }
        spend_leaf(&script, &items, xonly, ON)
    };
    assert_eq!(repeated(1, &[1]), Ok(true));
    assert_eq!(
        err_code(&repeated(12, &[1])),
        Some(ScriptErrCode::TapscriptValidationWeight)
    );
    assert_eq!(repeated(12, &[]), Ok(true), "empty signatures are free");
}

#[test]
fn csfs_through_the_interpreter_matches_bip340_vectors() {
    let (_, xonly) = internal();
    let csv = include_str!("data/bip340-test-vectors.csv");
    let mut lengths = std::collections::BTreeSet::new();
    let mut count = 0;
    for line in csv.lines().skip(1).filter(|l| !l.trim().is_empty()) {
        let cols: Vec<&str> = line.split(',').collect();
        let pk = Vec::from_hex(cols[2]).expect("pk");
        let msg = Vec::from_hex(cols[4]).expect("msg");
        let sig = Vec::from_hex(cols[5]).expect("sig");
        let expected = cols[6] == "TRUE";
        let result = spend_leaf(&csfs_script(), &[sig, msg.clone(), pk], xonly, ON);
        assert_eq!(
            result == Ok(true),
            expected,
            "vector {}: {result:?}",
            cols[0]
        );
        lengths.insert(msg.len());
        count += 1;
    }
    assert_eq!(count, 19);
    assert!(lengths.is_superset(&[0, 1, 17, 32, 100].into_iter().collect()));
}

#[test]
fn rebindable_signature_template_internalkey_csfs() {
    let (kp, xonly) = internal();
    let script = Builder::new()
        .push_opcode(op(0xce))
        .push_opcode(op(0xcb))
        .push_opcode(op(0xcc))
        .into_script();
    let (spk, control) = tapleaf_output(&script, xonly);
    let mut tx = spend_tx(1);
    let sig = sign(&kp, template_hash(&tx, 0, None));
    let mut witness = Witness::new();
    witness.push(&sig);
    witness.push(script.as_bytes());
    witness.push(&control);
    tx.input[0].witness = witness;
    assert_eq!(run_input(&tx, &spk, 0, ON), Ok(true));
    assert_eq!(run_input(&tx, &spk, 0, ON_STANDARD), Ok(true));

    let mut rebound = tx.clone();
    rebound.input[0].previous_output =
        bitcoin::OutPoint::new(bitcoin::Txid::from_byte_array([55; 32]), 3);
    assert_eq!(
        run_input(&rebound, &spk, 0, ON),
        Ok(true),
        "rebinds to a new outpoint"
    );

    let mut tampered = tx.clone();
    tampered.output[0].value = Amount::from_sat(1);
    assert_eq!(
        err_code(&run_input(&tampered, &spk, 0, ON)),
        Some(ScriptErrCode::SchnorrSig)
    );
    let mut flipped = tx;
    let mut witness = Witness::new();
    let mut bad = sig;
    bad[0] ^= 0x80;
    witness.push(&bad);
    witness.push(script.as_bytes());
    witness.push(&control);
    flipped.input[0].witness = witness;
    assert_eq!(
        err_code(&run_input(&flipped, &spk, 0, ON)),
        Some(ScriptErrCode::SchnorrSig)
    );
}

fn tx_from_hex(hex: &str) -> Tx {
    bitcoin_rs_primitives::deserialize(&Vec::from_hex(hex).expect("hex")).expect("tx")
}

fn txout_from_hex(hex: &str) -> bitcoin_rs_primitives::TxOut {
    bitcoin_rs_primitives::deserialize(&Vec::from_hex(hex).expect("hex")).expect("txout")
}

#[test]
fn bip446_basics_vectors() {
    let rows = sonic_rs::from_str::<sonic_rs::Value>(include_str!("data/bip446-basics.json"))
        .expect("json");
    let mut count = 0;
    for row in rows.as_array().expect("array") {
        let tx = tx_from_hex(row["spending_tx"].as_str().expect("tx"));
        let prevouts: Vec<_> = row["spent_outputs"]
            .as_array()
            .expect("outputs")
            .iter()
            .map(|o| txout_from_hex(o.as_str().expect("hex")))
            .collect();
        let index = usize::try_from(row["input_index"].as_u64().expect("index")).expect("index");
        let valid = row["valid"].as_bool().expect("valid");
        let input = &tx.inputs[index];
        let result = Interpreter.execute_with_prevouts(
            &prevouts[index].script_pubkey,
            &input.script_sig,
            &input.witness,
            ON,
            &prevouts,
            &tx,
            index,
        );
        assert_eq!(
            result.is_ok(),
            valid,
            "{}: {result:?}",
            row["comment"].as_str().unwrap_or_default()
        );
        count += 1;
    }
    assert!(count >= 10, "ran {count} basics vectors");
}

#[test]
fn bip446_script_assets_vectors() {
    // The published file ends with a trailing comma (Core's asset format).
    let text = include_str!("data/bip446-script_assets_test.json")
        .trim_end()
        .trim_end_matches(']')
        .trim_end()
        .trim_end_matches(',')
        .to_owned()
        + "]";
    let rows = sonic_rs::from_str::<sonic_rs::Value>(&text).expect("json");
    let (mut successes, mut failures) = (0_u32, 0_u32);
    for row in rows.as_array().expect("array") {
        let tx = tx_from_hex(row["tx"].as_str().expect("tx"));
        let prevouts: Vec<_> = row["prevouts"]
            .as_array()
            .expect("prevouts")
            .iter()
            .map(|o| txout_from_hex(o.as_str().expect("hex")))
            .collect();
        let index = usize::try_from(row["index"].as_u64().expect("index")).expect("index");
        let flags = VerifyFlags::from_core_names(row["flags"].as_str().expect("flags"))
            .expect("flags parse");
        let comment = row["comment"].as_str().unwrap_or_default();
        for (key, should_pass) in [("success", true), ("failure", false)] {
            let Some(case) = row.get(key) else { continue };
            let witness: Vec<Vec<u8>> = case["witness"]
                .as_array()
                .expect("witness")
                .iter()
                .map(|w| Vec::from_hex(w.as_str().expect("hex")).expect("hex"))
                .collect();
            let script_sig = Vec::from_hex(case["scriptSig"].as_str().expect("scriptSig"))
                .expect("scriptSig hex");
            let result = Interpreter.execute_with_prevouts(
                &prevouts[index].script_pubkey,
                &script_sig,
                &witness.into(),
                flags,
                &prevouts,
                &tx,
                index,
            );
            assert_eq!(
                result == Ok(true),
                should_pass,
                "{comment} ({key}) flags={} -> {result:?}",
                row["flags"].as_str().unwrap_or_default()
            );
            if should_pass {
                successes += 1;
            } else {
                failures += 1;
            }
        }
    }
    assert!(successes > 100 && failures > 100, "{successes}/{failures}");
}
