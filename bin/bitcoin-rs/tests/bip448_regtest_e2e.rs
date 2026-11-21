//! End-to-end BIP 448 demo on regtest: a 3-party LN-Symmetry-style channel.
//!
//! The channel key is a 3-party MuSig2 aggregate used as the taproot internal
//! key. Every state's output carries two tapleaves:
//!
//! * update(n): `<BASE+n+1> CLTV DROP TEMPLATEHASH INTERNALKEY CHECKSIGFROMSTACK`
//!   A later update transaction, signed once by the aggregate key over its own
//!   template hash, spends any earlier state's output. State numbers ride in
//!   nLockTime as `BASE + n`, so a lower state can never replace a higher one.
//! * settle(n): `<DELAY> CSV DROP TEMPLATEHASH <settlement template hash> EQUAL`
//!   After the delay anyone broadcasts the pre-committed settlement; no
//!   signature and no per-state penalty data exist.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::print_stderr)]

use bitcoin::hashes::{Hash as _, sha256};
use bitcoin::opcodes::all::{OP_CLTV, OP_CSV, OP_DROP, OP_EQUAL};
use bitcoin::script::Builder;
use bitcoin::secp256k1::XOnlyPublicKey;
use bitcoin::taproot::{LeafVersion, TaprootBuilder, TaprootSpendInfo};
use bitcoin::{
    Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness, WPubkeyHash,
    absolute::LockTime, transaction::Version,
};
use bitcoin_rs_e2e::helpers::{
    COINBASE_MATURITY, coinbase_at, funding_address, funding_output, mine_blocks_to, raw_spend_to,
    sign_p2pkh_inputs, submit_genesis, tx_hex,
};
use bitcoin_rs_e2e::{Kind, ProcessNode, SpawnOptions};
use bitcoin_rs_nested_musig2 as musig;
use sonic_rs::{JsonContainerTrait as _, JsonValueTrait as _, json};

use crate::support::TestError;

const CSV_HEIGHT: u32 = 432;
const BASE: u32 = 500_000_000;
const DELAY: i64 = 10;
const UPDATE_FEE: u64 = 2_000;
const SETTLE_FEE: u64 = 2_000;
const SECRETS: [[u8; 32]; 3] = [[0x11; 32], [0x22; 32], [0x33; 32]];

fn op(byte: u8) -> bitcoin::opcodes::Opcode {
    bitcoin::opcodes::Opcode::from(byte)
}

fn spawn(extra: &'static [&'static str]) -> ProcessNode {
    ProcessNode::spawn_with(
        Kind::BitcoinRs,
        &SpawnOptions {
            binary: Some(std::path::Path::new(env!("CARGO_BIN_EXE_bitcoin-rs"))),
            extra_args: extra,
            ..SpawnOptions::default()
        },
    )
    .expect("bitcoin-rs regtest node")
}

fn p2wpkh(tag: u8) -> ScriptBuf {
    ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array([tag; 20]))
}

/// BIP 446 template hash, written from the BIP text.
fn template_hash(tx: &Transaction, index: u32) -> [u8; 32] {
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
    msg.push(0);
    msg.extend_from_slice(&index.to_le_bytes());
    let tag = sha256::Hash::hash(b"TemplateHash");
    let mut full = Vec::new();
    full.extend_from_slice(tag.as_byte_array());
    full.extend_from_slice(tag.as_byte_array());
    full.extend_from_slice(&msg);
    sha256::Hash::hash(&full).to_byte_array()
}

struct Parties {
    pubs: Vec<musig::PlainPublicKey>,
    internal: XOnlyPublicKey,
}

impl Parties {
    fn new() -> Self {
        let pubs: Vec<_> = SECRETS
            .iter()
            .map(|s| musig::public_key(s).expect("public key"))
            .collect();
        let agg = musig::key_agg(&pubs).expect("key aggregation").xonly_key();
        Self {
            pubs,
            internal: XOnlyPublicKey::from_slice(&agg).expect("aggregate x-only key"),
        }
    }

    /// One full 3-party MuSig2 round over `message`, verified before return.
    fn sign(&self, message: &[u8]) -> Vec<u8> {
        let agg = self.internal.serialize();
        let mut secret_nonces = Vec::new();
        let mut public_nonces = Vec::new();
        for (secret, public) in SECRETS.iter().zip(&self.pubs) {
            let (sn, pn) = musig::nonce_gen(Some(secret), *public, Some(agg), Some(message), None)
                .expect("nonce");
            secret_nonces.push(sn);
            public_nonces.push(pn);
        }
        let agg_nonce = musig::nonce_agg(&public_nonces).expect("nonce aggregation");
        let mut partials = Vec::new();
        for (i, secret_nonce) in secret_nonces.into_iter().enumerate() {
            let others: Vec<_> = self
                .pubs
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .map(|(_, key)| *key)
                .collect();
            let context = musig::SessionContext {
                nonce_path: vec![agg_nonce],
                key_path: vec![others],
                tweaks: vec![],
                message: message.to_vec(),
            };
            partials.push(musig::sign(secret_nonce, &SECRETS[i], &context).expect("partial"));
        }
        let signature = musig::aggregate_root(
            &partials,
            &musig::RootSessionContext {
                aggregate_nonce: agg_nonce,
                pubkeys: self.pubs.clone(),
                tweaks: vec![],
                message: message.to_vec(),
            },
        )
        .expect("aggregate signature");
        assert!(musig::schnorr_verify(message, agg, &signature));
        signature.to_vec()
    }
}

/// Outputs of one channel state's settlement transaction.
fn settlement_outputs(n: u32, value: u64) -> Vec<TxOut> {
    let pct: [u64; 3] = match n {
        0 => [40, 30, 30],
        1 => [35, 35, 30],
        2 => [30, 40, 30],
        _ => [20, 50, 30],
    };
    let total = value - SETTLE_FEE;
    let a = total * pct[0] / 100;
    let b = total * pct[1] / 100;
    vec![
        TxOut {
            value: Amount::from_sat(a),
            script_pubkey: p2wpkh(0xa1),
        },
        TxOut {
            value: Amount::from_sat(b),
            script_pubkey: p2wpkh(0xb2),
        },
        TxOut {
            value: Amount::from_sat(total - a - b),
            script_pubkey: p2wpkh(0xc3),
        },
    ]
}

fn spending_tx(
    prevout: OutPoint,
    lock_time: u32,
    sequence: u32,
    outputs: Vec<TxOut>,
) -> Transaction {
    Transaction {
        version: Version::TWO,
        lock_time: LockTime::from_consensus(lock_time),
        input: vec![TxIn {
            previous_output: prevout,
            script_sig: ScriptBuf::new(),
            sequence: Sequence(sequence),
            witness: Witness::new(),
        }],
        output: outputs,
    }
}

struct State {
    n: u32,
    value: u64,
    update_leaf: ScriptBuf,
    settle_leaf: ScriptBuf,
    info: TaprootSpendInfo,
}

impl State {
    fn new(parties: &Parties, n: u32, v0: u64) -> Self {
        let value = v0 - UPDATE_FEE * u64::from(n);
        let update_leaf = Builder::new()
            .push_int(i64::from(BASE + n + 1))
            .push_opcode(OP_CLTV)
            .push_opcode(OP_DROP)
            .push_opcode(op(0xce))
            .push_opcode(op(0xcb))
            .push_opcode(op(0xcc))
            .into_script();
        let settlement = spending_tx(
            OutPoint::null(),
            0,
            u32::try_from(DELAY).expect("delay"),
            settlement_outputs(n, value),
        );
        let settle_leaf = Builder::new()
            .push_int(DELAY)
            .push_opcode(OP_CSV)
            .push_opcode(OP_DROP)
            .push_opcode(op(0xce))
            .push_slice(template_hash(&settlement, 0))
            .push_opcode(OP_EQUAL)
            .into_script();
        let info = TaprootBuilder::new()
            .add_leaf(1, update_leaf.clone())
            .expect("update leaf")
            .add_leaf(1, settle_leaf.clone())
            .expect("settle leaf")
            .finalize(&bitcoin::secp256k1::Secp256k1::new(), parties.internal)
            .expect("taproot tree");
        Self {
            n,
            value,
            update_leaf,
            settle_leaf,
            info,
        }
    }

    fn txout(&self) -> TxOut {
        TxOut {
            value: Amount::from_sat(self.value),
            script_pubkey: ScriptBuf::new_p2tr_tweaked(self.info.output_key()),
        }
    }

    fn witness(&self, leaf: &ScriptBuf, items: &[&[u8]]) -> Witness {
        let control = self
            .info
            .control_block(&(leaf.clone(), LeafVersion::TapScript))
            .expect("control block")
            .serialize();
        let mut witness = Witness::new();
        for item in items {
            witness.push(item);
        }
        witness.push(leaf.as_bytes());
        witness.push(&control);
        witness
    }

    /// The update transaction for this state, with its pre-signed template.
    fn update_tx(&self, parties: &Parties, spends: OutPoint) -> (Transaction, Vec<u8>) {
        let tx = spending_tx(
            spends,
            BASE + self.n,
            0xffff_fffd,
            vec![self.txout()],
        );
        let sig = parties.sign(&template_hash(&tx, 0));
        (tx, sig)
    }

    fn settle_tx(&self, outpoint: OutPoint) -> Transaction {
        let mut tx = spending_tx(
            outpoint,
            0,
            u32::try_from(DELAY).expect("delay"),
            settlement_outputs(self.n, self.value),
        );
        tx.input[0].witness = self.witness(&self.settle_leaf, &[]);
        tx
    }
}

fn with_update_witness(prev: &State, mut tx: Transaction, sig: &[u8]) -> Transaction {
    tx.input[0].witness = prev.witness(&prev.update_leaf, &[sig]);
    tx
}

fn preview(node: &mut ProcessNode, tx: &Transaction) -> (bool, String) {
    let result = node
        .rpc("testmempoolaccept", &json!([[tx_hex(tx)]]))
        .expect("testmempoolaccept");
    let row = &result[0];
    (
        row["allowed"].as_bool().expect("allowed"),
        row["reject-reason"].as_str().unwrap_or_default().to_owned(),
    )
}

fn broadcast_and_mine(node: &mut ProcessNode, tx: &Transaction) -> String {
    let txid = node
        .rpc("sendrawtransaction", &json!([tx_hex(tx)]))
        .expect("sendrawtransaction")
        .as_str()
        .expect("txid")
        .to_owned();
    let mempool = node
        .rpc("getmempoolentry", &json!([txid]))
        .expect("mempool entry");
    assert_eq!(
        mempool["vsize"].as_u64(),
        Some(u64::try_from(tx.vsize()).unwrap()),
        "node vsize matches the library's"
    );
    let block = node
        .rpc("generateblock", &json!(["raw(51)", [txid]]))
        .expect("mine from mempool");
    assert!(block["hash"].as_str().is_some());
    txid
}

#[test]
fn three_party_ln_symmetry_update_replaces_and_settles() -> Result<(), TestError> {
    let parties = Parties::new();
    let mut node = spawn(&["--bip448"]);
    submit_genesis(&mut node)?;
    // Regtest enforces BIP68/BIP112 (CSV) from height 432; mine past it.
    let _ = mine_blocks_to(
        &mut node,
        CSV_HEIGHT + COINBASE_MATURITY,
        &format!("addr({})", funding_address()?),
    )?;
    let (coinbase_outpoint, coinbase_out) = funding_output(&coinbase_at(&mut node, 1)?)?;

    // Funding: the coinbase pays the state-0 output (the channel).
    let v0 = coinbase_out.value.to_sat() - 5_000;
    let s0 = State::new(&parties, 0, v0);
    let mut funding = raw_spend_to(
        coinbase_outpoint,
        &coinbase_out,
        5_000,
        Sequence::MAX,
        &s0.txout().script_pubkey,
    );
    sign_p2pkh_inputs(&mut funding, std::slice::from_ref(&coinbase_out))?;
    let funding_txid = broadcast_and_mine(&mut node, &funding);
    let funding_out = OutPoint::new(funding.compute_txid(), 0);
    assert_eq!(funding_out.txid.to_string(), funding_txid);

    // Channel states 1, 2 and 3; update transactions are signed once each.
    let s1 = State::new(&parties, 1, v0);
    let s2 = State::new(&parties, 2, v0);
    let s3 = State::new(&parties, 3, v0);
    let (u1, sig1) = s1.update_tx(&parties, funding_out);
    let u1 = with_update_witness(&s0, u1, &sig1);
    let (u2_template, sig2) = s2.update_tx(&parties, OutPoint::null());
    let (u3_template, sig3) = s3.update_tx(&parties, OutPoint::null());

    // State-1 update spends the funding output.
    let u1_txid = broadcast_and_mine(&mut node, &u1);
    let u1_out = OutPoint::new(u1.compute_txid(), 0);
    assert_eq!(u1_txid, u1.compute_txid().to_string());

    // The state-2 update could equally replace state 1; the channel skips it.
    let mut u2 = u2_template.clone();
    u2.input[0].previous_output = u1_out;
    let u2 = with_update_witness(&s1, u2, &sig2);
    assert_eq!(preview(&mut node, &u2), (true, String::new()), "state 2 may replace state 1");

    // State-3 update, signed once over its template hash, spends state 1.
    let mut u3 = u3_template.clone();
    u3.input[0].previous_output = u1_out;
    let u3 = with_update_witness(&s1, u3, &sig3);

    // Tampering with the template or the signature is rejected.
    let mut tampered_template = u3.clone();
    tampered_template.output[0].value = Amount::from_sat(s3.value - 1);
    let (allowed, why) = preview(&mut node, &tampered_template);
    assert!(!allowed, "tampered template accepted");
    eprintln!("tampered template rejected: {why}");
    let mined = node.rpc("generateblock", &json!(["raw(51)", [tx_hex(&tampered_template)]]));
    assert!(mined.is_err(), "consensus must refuse the tampered template: {mined:?}");
    let mut bad_sig = sig3.clone();
    bad_sig[5] ^= 0x01;
    let tampered_sig = with_update_witness(&s1, u3_template.clone(), &bad_sig);
    let mut tampered_sig = tampered_sig;
    tampered_sig.input[0].previous_output = u1_out;
    let (allowed, why) = preview(&mut node, &tampered_sig);
    assert!(!allowed, "tampered signature accepted");
    eprintln!("tampered signature rejected: {why}");
    // A state-2 signature does not authorise the state-3 transaction.
    let wrong_sig = with_update_witness(&s1, u3_template.clone(), &sig2);
    let mut wrong_sig = wrong_sig;
    wrong_sig.input[0].previous_output = u1_out;
    assert!(!preview(&mut node, &wrong_sig).0, "signature for another template accepted");

    let u3_txid = broadcast_and_mine(&mut node, &u3);
    let u3_out = OutPoint::new(u3.compute_txid(), 0);
    assert_eq!(u3_txid, u3.compute_txid().to_string());

    // After state 3, neither state 2 nor state 1 can rebind over it.
    let mut stale_u2 = u2_template.clone();
    stale_u2.input[0].previous_output = u3_out;
    let stale_u2 = with_update_witness(&s3, stale_u2, &sig2);
    let (allowed, why) = preview(&mut node, &stale_u2);
    assert!(!allowed, "stale state replaced a newer state");
    eprintln!("stale state-2 update over state 3 rejected: {why}");

    // A settlement committed for an older state does not fit state 3's output.
    let stale_settle = s1.settle_tx(u3_out);
    let mut stale_settle = stale_settle;
    stale_settle.input[0].witness = s3.witness(&s3.settle_leaf, &[]);
    stale_settle.output = settlement_outputs(1, s1.value);
    assert!(!preview(&mut node, &stale_settle).0, "stale settlement accepted");

    // Settlement of state 3 waits for the relative delay, then pays 3 parties.
    let settle = s3.settle_tx(u3_out);
    let mut mined_after = 0;
    loop {
        let (allowed, why) = preview(&mut node, &settle);
        if allowed {
            break;
        }
        assert!(
            mined_after < 12,
            "settlement never became final, last reason: {why}"
        );
        if mined_after == 0 {
            eprintln!("settlement before the delay rejected: {why}");
        }
        let _ = mine_blocks_to(&mut node, 1, "raw(51)")?;
        mined_after += 1;
    }
    assert_eq!(
        mined_after,
        u32::try_from(DELAY - 1).unwrap(),
        "accepted once the next block is DELAY deep"
    );
    let settle_txid = broadcast_and_mine(&mut node, &settle);
    assert_eq!(settle.output.len(), 3);
    let paid: u64 = settle.output.iter().map(|o| o.value.to_sat()).sum();
    assert_eq!(paid, s3.value - SETTLE_FEE);

    // Everything broadcast was mined: the mempool is empty again.
    assert_eq!(node.rpc("getrawmempool", &json!([]))?, json!([]));

    eprintln!("BIP448-VSIZE funding(p2pkh->p2tr)  vsize={} weight={}", funding.vsize(), funding.weight().to_wu());
    for (name, tx) in [("update state 1 (spends funding)", &u1), ("update state 3 (spends state 1)", &u3), ("settlement state 3 (3 outputs, CSV)", &settle)] {
        eprintln!(
            "BIP448-VSIZE {name:<36} vsize={} weight={} witness_bytes={}",
            tx.vsize(),
            tx.weight().to_wu(),
            tx.input[0].witness.size()
        );
    }
    node.stop()?;
    Ok(())
}

#[test]
fn without_the_switch_the_opcodes_stay_op_success() -> Result<(), TestError> {
    let parties = Parties::new();
    let mut node = spawn(&[]);
    submit_genesis(&mut node)?;
    let _ = mine_blocks_to(
        &mut node,
        COINBASE_MATURITY + 1,
        &format!("addr({})", funding_address()?),
    )?;
    let (coinbase_outpoint, coinbase_out) = funding_output(&coinbase_at(&mut node, 1)?)?;
    let v0 = coinbase_out.value.to_sat() - 5_000;
    let s0 = State::new(&parties, 0, v0);
    let mut funding = raw_spend_to(
        coinbase_outpoint,
        &coinbase_out,
        5_000,
        Sequence::MAX,
        &s0.txout().script_pubkey,
    );
    sign_p2pkh_inputs(&mut funding, std::slice::from_ref(&coinbase_out))?;
    let _ = broadcast_and_mine(&mut node, &funding);
    let funding_out = OutPoint::new(funding.compute_txid(), 0);

    // A garbage signature: with the opcodes undefined the leaf is OP_SUCCESS,
    // which consensus accepts and relay policy refuses.
    let s1 = State::new(&parties, 1, v0);
    let (tx, _) = s1.update_tx(&parties, funding_out);
    let forged = with_update_witness(&s0, tx, &[0_u8; 64]);
    let (allowed, why) = preview(&mut node, &forged);
    assert!(!allowed, "policy must discourage OP_SUCCESS");
    eprintln!("flag off, mempool: {why}");
    let mined = node.rpc("generateblock", &json!(["raw(51)", [tx_hex(&forged)]]));
    assert!(mined.is_ok(), "consensus accepts the OP_SUCCESS spend: {mined:?}");

    node.stop()?;
    Ok(())
}
