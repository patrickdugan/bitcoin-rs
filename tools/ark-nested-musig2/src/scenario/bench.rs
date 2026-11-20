use std::collections::BTreeMap;
use std::path::Path;
use std::time::Instant;

use bitcoin::hex::DisplayHex as _;
use bitcoin::{Transaction, TxOut};
use serde::Serialize;

use crate::client::{Intent, Observed, RoleSigner};
use crate::keys::Participant;
use crate::native;
use crate::policy::{Shape, SignerId};
use crate::round::{
    Params, RoundSpec, build_round, exit_tx, sign_round, synthetic_outpoint, unanchored,
};
use crate::scripts::key_path_script;
use crate::signing::Cosigners;
use crate::statement::{
    ArkTransitionV1, Funding, FundingKind, Participant as Leaf, check_statement, nova_witness,
};
use crate::traffic::Traffic;
use crate::{Error, Result, to_u16, to_u32, to_u64};

#[derive(Clone, Debug, Serialize)]
pub struct BenchRow {
    pub vtxos: usize,
    pub shape: &'static str,
    pub commitment_vsize: usize,
    pub commitment_fee_sat: u64,
    pub tree_txs: usize,
    pub tree_vsize_total: usize,
    pub tree_fee_total_sat: u64,
    pub cooperative_l1_txs: usize,
    pub cooperative_vbytes_per_vtxo: f64,
    pub cooperative_fee_per_vtxo_sat: f64,
    pub unilateral_exit_txs_one_user: usize,
    pub unilateral_exit_vbytes_one_user: usize,
    pub unilateral_exit_fee_one_user_sat: u64,
    pub mass_exit_txs: usize,
    pub mass_exit_vbytes: usize,
    pub mass_exit_fee_sat: u64,
    pub mass_exit_vbytes_per_vtxo: f64,
    pub build_seconds: f64,
    pub signing_seconds: f64,
    pub traffic: Traffic,
    pub native_verify_seconds: f64,
    pub native_inputs_verified: usize,
    pub statement_bytes: usize,
    pub statement_digest: String,
    pub statement_check_accepted: bool,
    pub nova_items: usize,
    pub nova_steps: u64,
}

fn fee(tx: &Transaction, prevouts: &[TxOut]) -> Result<u64> {
    let inputs = prevouts
        .iter()
        .try_fold(0_u64, |t, o| crate::add_sat(t, o.value.to_sat(), "fee in"))?;
    let outputs = tx
        .output
        .iter()
        .try_fold(0_u64, |t, o| crate::add_sat(t, o.value.to_sat(), "fee out"))?;
    crate::sub_sat(inputs, outputs, "fee")
}

fn ratio(numerator: u64, denominator: usize) -> f64 {
    let numerator = u32::try_from(numerator).map(f64::from).unwrap_or(f64::MAX);
    let denominator = u32::try_from(denominator)
        .map(f64::from)
        .unwrap_or(f64::MAX);
    numerator / denominator
}

/// A round of `count` VTXOs with seeded test keys, synthetic confirmed
/// prevouts, and one in-process signer per role.
pub struct Synthetic {
    pub params: Params,
    pub statement: ArkTransitionV1,
    pub cosigners: Cosigners,
    pub intents: BTreeMap<SignerId, Intent>,
    pub owners: BTreeMap<[u8; 33], SignerId>,
    pub users: Vec<Participant>,
    pub asp: Participant,
    pub observed: Vec<Observed>,
}

pub fn synthetic(count: usize, shape: Shape, seed: &[u8; 32]) -> Result<Synthetic> {
    let params = Params::regtest(shape);
    let asp_key = Participant::from_seed(seed, "asp", 0)?;
    let asp = asp_key.plain()?;
    let mut users = Vec::new();
    for index in 0..count {
        users.push(Participant::from_seed(
            seed,
            "user",
            to_u32(index, "user")?,
        )?);
    }
    let mut leaves = Vec::new();
    let mut boarding = Vec::new();
    let mut observed = Vec::new();
    for (index, user) in users.iter().enumerate() {
        let owner = user.plain()?.serialize();
        let amount = 200_000 + 10 * to_u64(index, "amount")?;
        leaves.push(Leaf {
            owner,
            amount_sat: amount,
        });
        let script = crate::scripts::VtxoScript {
            owner: user.xonly()?,
            asp: asp_key.xonly()?,
            exit_delay: params.boarding_delay,
        }
        .script_pubkey()?;
        let outpoint = synthetic_outpoint("bench-boarding", to_u32(index, "index")?);
        boarding.push(Funding {
            outpoint,
            amount_sat: amount,
            script_pubkey: script.clone(),
            kind: FundingKind::Boarding { owner },
        });
        observed.push(Observed {
            outpoint,
            amount_sat: amount,
            script_pubkey: script,
            confirmations: 6,
        });
    }
    let liquidity_amount = 10_000_000 + 2_000 * to_u64(count, "count")?;
    let liquidity = Funding {
        outpoint: synthetic_outpoint("bench-liquidity", 0),
        amount_sat: liquidity_amount,
        script_pubkey: key_path_script(asp_key.xonly()?),
        kind: FundingKind::Liquidity,
    };
    observed.push(Observed {
        outpoint: liquidity.outpoint,
        amount_sat: liquidity_amount,
        script_pubkey: liquidity.script_pubkey.clone(),
        confirmations: 6,
    });
    let statement = build_round(
        &params,
        asp,
        &RoundSpec {
            round: 1,
            sequence: 1,
            previous: [0; 32],
            participants: leaves,
            boarding,
            liquidity,
            old_vtxos: Vec::new(),
            coop_exits: Vec::new(),
            anchor: unanchored(),
        },
    )?;
    let mut cosigners: Cosigners = BTreeMap::new();
    let mut intents = BTreeMap::new();
    let mut owners = BTreeMap::new();
    cosigners.insert(
        SignerId::Asp,
        Box::new(RoleSigner::new(
            SignerId::Asp,
            Participant::from_seed(seed, "asp", 0)?,
        )?),
    );
    intents.insert(
        SignerId::Asp,
        Intent {
            observed: observed.clone(),
            ..Intent::default()
        },
    );
    for index in 0..count {
        let id = SignerId::User(to_u16(index, "user")?);
        let key = Participant::from_seed(seed, "user", to_u32(index, "user")?)?;
        owners.insert(key.plain()?.serialize(), id);
        cosigners.insert(id, Box::new(RoleSigner::new(id, key)?));
        intents.insert(
            id,
            Intent {
                receive: vec![statement.participants[index].amount_sat],
                boarding: vec![(
                    statement.funding[index].outpoint,
                    statement.funding[index].amount_sat,
                )],
                observed: observed.clone(),
                ..Intent::default()
            },
        );
    }
    Ok(Synthetic {
        params,
        statement,
        cosigners,
        intents,
        owners,
        users,
        asp: asp_key,
        observed,
    })
}

/// One synthetic round signed by in-process signers. Every input of every
/// transaction, including one unilateral exit per VTXO, runs through the
/// bitcoin-rs interpreter.
pub fn bench(count: usize, shape: Shape, seed: &[u8; 32], out: Option<&Path>) -> Result<BenchRow> {
    let started = Instant::now();
    let Synthetic {
        params,
        statement,
        mut cosigners,
        intents,
        owners,
        users,
        ..
    } = synthetic(count, shape, seed)?;
    let build_seconds = started.elapsed().as_secs_f64();
    let signing_started = Instant::now();
    let signed = sign_round(&statement, &mut cosigners, &intents, &owners, 0)?;
    let signing_seconds = signing_started.elapsed().as_secs_f64();
    let vtxos = statement.vtxo_outpoints()?;
    let mut exits = Vec::new();
    for index in 0..count {
        let script = statement.vtxo_script(index)?;
        let user = &users[index];
        exits.push((
            exit_tx(
                &script,
                vtxos[index],
                statement.participants[index].amount_sat,
                key_path_script(user.xonly()?),
                params.fee_rate_sat_per_kvb,
                user,
            )?,
            vec![crate::round::output(
                statement.participants[index].amount_sat,
                script.script_pubkey()?,
            )],
        ));
    }
    let verify_started = Instant::now();
    let mut verified =
        native::verify_all_inputs(&signed.commitment, &statement.commitment_prevouts())
            .map_err(|error| Error::Construction(format!("commitment: {error}")))?;
    let mut tree_vsize = 0;
    let mut tree_fee = 0;
    for (index, tx) in signed.tree.iter().enumerate() {
        let prevout = statement.tree_prevout(index)?;
        verified += native::verify_all_inputs(tx, std::slice::from_ref(&prevout))
            .map_err(|error| Error::Construction(format!("tree {index}: {error}")))?;
        tree_vsize += tx.vsize();
        tree_fee += fee(tx, &[prevout])?;
    }
    let mut exit_vsize = 0;
    let mut exit_fee = 0;
    for (index, (tx, prevouts)) in exits.iter().enumerate() {
        verified += native::verify_all_inputs(tx, prevouts)
            .map_err(|error| Error::Construction(format!("exit {index}: {error}")))?;
        exit_vsize += tx.vsize();
        exit_fee += fee(tx, prevouts)?;
    }
    let native_verify_seconds = verify_started.elapsed().as_secs_f64();
    let branch = statement.branch(0);
    let one_vsize: usize = branch
        .iter()
        .map(|index| signed.tree[*index].vsize())
        .sum::<usize>()
        + exits[0].0.vsize();
    let mut one_fee = fee(&exits[0].0, &exits[0].1)?;
    for index in &branch {
        one_fee += fee(&signed.tree[*index], &[statement.tree_prevout(*index)?])?;
    }
    let commitment_fee = fee(&signed.commitment, &statement.commitment_prevouts())?;
    let report = check_statement(&statement, &signed.all())?;
    let witness = nova_witness(&statement)?;
    let bytes = statement.encode()?;
    if let Some(out) = out {
        let name = format!("{}-{count}", shape.name());
        std::fs::write(out.join(format!("statement-{name}.bin")), &bytes)?;
        std::fs::write(
            out.join(format!("nova-witness-{name}.json")),
            sonic_rs::to_string(&witness)?,
        )?;
    }
    let commitment_vsize = signed.commitment.vsize();
    Ok(BenchRow {
        vtxos: count,
        shape: shape.name(),
        commitment_vsize,
        commitment_fee_sat: commitment_fee,
        tree_txs: signed.tree.len(),
        tree_vsize_total: tree_vsize,
        tree_fee_total_sat: tree_fee,
        cooperative_l1_txs: 1,
        cooperative_vbytes_per_vtxo: ratio(to_u64(commitment_vsize, "vsize")?, count),
        cooperative_fee_per_vtxo_sat: ratio(commitment_fee, count),
        unilateral_exit_txs_one_user: branch.len() + 1,
        unilateral_exit_vbytes_one_user: one_vsize,
        unilateral_exit_fee_one_user_sat: one_fee,
        mass_exit_txs: signed.tree.len() + count,
        mass_exit_vbytes: tree_vsize + exit_vsize,
        mass_exit_fee_sat: tree_fee + exit_fee,
        mass_exit_vbytes_per_vtxo: ratio(to_u64(tree_vsize + exit_vsize, "vsize")?, count),
        build_seconds,
        signing_seconds,
        traffic: signed.traffic,
        native_verify_seconds,
        native_inputs_verified: verified,
        statement_bytes: bytes.len(),
        statement_digest: statement.digest()?.to_lower_hex_string(),
        statement_check_accepted: report.accepted,
        nova_items: witness.items.len(),
        nova_steps: to_u64(witness.items.len(), "items")? + witness.expect.input_count,
    })
}
