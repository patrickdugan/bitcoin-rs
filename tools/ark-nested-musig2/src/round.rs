use std::collections::{BTreeMap, VecDeque};

use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash as _;
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};
use bitcoin_rs_nested_musig2::PlainPublicKey;

use crate::client::Intent;
use crate::keys::{KeyNetwork, Participant, xonly_of};
use crate::policy::{Shape, SignerId};
use crate::scripts::{NodeScript, VtxoScript, csv_sequence, key_path_script};
use crate::signing::{Cosigners, Fault, SchnorrRequest, SignTarget, sighash, sign_tree_tx};
use crate::statement::{
    AnchorAssumption, ArkTransitionV1, ChainAnchor, CoopExit, Forfeit, Funding, FundingKind,
    OldVtxo, Participant as Leaf, Policy, TreeTx, split_point,
};
use crate::traffic::Traffic;
use crate::{Error, Result, add_sat, sub_sat, to_u16, to_u32, to_u64};

pub const DUST_SAT: u64 = 330;

#[derive(Clone, Copy, Debug)]
pub struct Params {
    pub network: KeyNetwork,
    pub shape: Shape,
    pub exit_delay: u16,
    pub boarding_delay: u16,
    pub batch_expiry: u16,
    pub fee_rate_sat_per_kvb: u64,
    pub fee_bound_sat: u64,
    pub connector_sat: u64,
}

impl Params {
    pub fn regtest(shape: Shape) -> Self {
        Self {
            network: KeyNetwork::Regtest,
            shape,
            exit_delay: 12,
            boarding_delay: 30,
            batch_expiry: 40,
            fee_rate_sat_per_kvb: 2_000,
            fee_bound_sat: 200_000,
            connector_sat: 400,
        }
    }
}

#[derive(Clone, Debug)]
pub struct RoundSpec {
    pub round: u32,
    pub sequence: u32,
    pub previous: [u8; 32],
    pub participants: Vec<Leaf>,
    pub boarding: Vec<Funding>,
    pub liquidity: Funding,
    pub old_vtxos: Vec<OldVtxo>,
    pub coop_exits: Vec<([u8; 33], ScriptBuf, u64)>,
    pub anchor: ChainAnchor,
}

pub fn fee_for(vsize: usize, rate_sat_per_kvb: u64) -> Result<u64> {
    Ok(to_u64(vsize, "vsize")?
        .checked_mul(rate_sat_per_kvb)
        .ok_or(Error::Value("fee"))?
        .div_ceil(1000))
}

pub fn input(outpoint: OutPoint, sequence: Sequence) -> TxIn {
    TxIn {
        previous_output: outpoint,
        script_sig: ScriptBuf::new(),
        sequence,
        witness: Witness::new(),
    }
}

pub fn output(value: u64, script: ScriptBuf) -> TxOut {
    TxOut {
        value: Amount::from_sat(value),
        script_pubkey: script,
    }
}

pub fn template(inputs: Vec<TxIn>, outputs: Vec<TxOut>) -> Transaction {
    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: inputs,
        output: outputs,
    }
}

/// Virtual size with placeholder signatures of the exact final length.
pub fn vsize_with(tx: &Transaction, witnesses: &[Vec<Vec<u8>>]) -> usize {
    let mut sized = tx.clone();
    for (input, witness) in sized.input.iter_mut().zip(witnesses) {
        input.witness = Witness::from_slice(witness);
    }
    sized.vsize()
}

pub fn key_path_witness() -> Vec<Vec<u8>> {
    vec![vec![0_u8; 64]]
}

pub fn cooperative_witness(script: &VtxoScript) -> Result<Vec<Vec<u8>>> {
    let leaf = script.cooperative_leaf();
    Ok(vec![
        vec![0_u8; 64],
        vec![0_u8; 64],
        leaf.to_bytes(),
        script.control_block(&leaf)?.serialize(),
    ])
}

fn tree_tx_fee(rate: u64) -> Result<u64> {
    let dummy_script = key_path_script(xonly_of(PlainPublicKey::from_slice(
        &crate::scripts::nums_compressed(),
    )?)?);
    let tx = template(
        vec![input(OutPoint::null(), Sequence::MAX)],
        vec![output(1, dummy_script.clone()), output(1, dummy_script)],
    );
    fee_for(vsize_with(&tx, &[key_path_witness()]), rate)
}

fn range_value(
    spec: &RoundSpec,
    lo: u16,
    hi: u16,
    tree_fee: u64,
    cache: &mut BTreeMap<(u16, u16), u64>,
) -> Result<u64> {
    if hi - lo == 1 {
        return spec
            .participants
            .get(usize::from(lo))
            .map(|leaf| leaf.amount_sat)
            .ok_or_else(|| Error::Construction("participant out of range".to_owned()));
    }
    let mid = split_point(lo, hi);
    let left = range_value(spec, lo, mid, tree_fee, cache)?;
    let right = range_value(spec, mid, hi, tree_fee, cache)?;
    let value = add_sat(
        add_sat(left, right, "range value")?,
        tree_fee,
        "range value",
    )?;
    cache.insert((lo, hi), value);
    Ok(value)
}

/// The operator's construction: values bottom-up so each tree transaction pays
/// its own fee, then templates top-down so every txid is fixed before signing.
pub fn build_round(
    params: &Params,
    asp: PlainPublicKey,
    spec: &RoundSpec,
) -> Result<ArkTransitionV1> {
    let count = spec.participants.len();
    if count < 2 {
        return Err(Error::Construction(
            "a round needs at least two VTXOs".to_owned(),
        ));
    }
    let count_u16 = to_u16(count, "participants")?;
    let asp_xonly = xonly_of(asp)?;
    let asp_script = key_path_script(asp_xonly);
    let mut funding = spec.boarding.clone();
    funding.push(spec.liquidity.clone());
    let mut statement = ArkTransitionV1 {
        network: params.network,
        genesis: bitcoin::blockdata::constants::genesis_block(params.network.bitcoin())
            .block_hash()
            .to_byte_array(),
        round: spec.round,
        sequence: spec.sequence,
        previous: spec.previous,
        policy: Policy {
            shape: params.shape,
            asp: asp.serialize(),
            exit_delay: params.exit_delay,
            boarding_delay: params.boarding_delay,
            batch_expiry: params.batch_expiry,
            fee_rate_sat_per_kvb: params.fee_rate_sat_per_kvb,
            fee_bound_sat: params.fee_bound_sat,
            connector_sat: params.connector_sat,
        },
        participants: spec.participants.clone(),
        funding,
        old_vtxos: spec.old_vtxos.clone(),
        commitment: template(Vec::new(), Vec::new()),
        batch_vout: 0,
        connectors: Vec::new(),
        coop_exits: Vec::new(),
        tree: Vec::new(),
        forfeits: Vec::new(),
        anchor: spec.anchor.clone(),
    };
    let tree_fee = tree_tx_fee(params.fee_rate_sat_per_kvb)?;
    let mut values = BTreeMap::new();
    let batch_value = range_value(spec, 0, count_u16, tree_fee, &mut values)?;
    let mut outputs = vec![output(batch_value, statement.range_script(0, count_u16)?)];
    for _ in &spec.old_vtxos {
        statement
            .connectors
            .push(to_u32(outputs.len(), "connector vout")?);
        outputs.push(output(params.connector_sat, asp_script.clone()));
    }
    for (owner, script, amount) in &spec.coop_exits {
        statement.coop_exits.push(CoopExit {
            vout: to_u32(outputs.len(), "exit vout")?,
            owner: *owner,
            amount_sat: *amount,
            script_pubkey: script.clone(),
        });
        outputs.push(output(*amount, script.clone()));
    }
    let change_vout = outputs.len();
    outputs.push(output(0, asp_script.clone()));
    let inputs: Vec<TxIn> = statement
        .funding
        .iter()
        .map(|funding| input(funding.outpoint, Sequence::ENABLE_RBF_NO_LOCKTIME))
        .collect();
    let mut commitment = template(inputs, outputs);
    let mut witnesses = Vec::new();
    for funding in &statement.funding {
        witnesses.push(match &funding.kind {
            FundingKind::Boarding { owner } => {
                cooperative_witness(&statement.boarding_script(owner)?)?
            }
            FundingKind::Liquidity => key_path_witness(),
        });
    }
    let fee = fee_for(
        vsize_with(&commitment, &witnesses),
        params.fee_rate_sat_per_kvb,
    )?;
    let total_in = statement.funding.iter().try_fold(0_u64, |total, funding| {
        add_sat(total, funding.amount_sat, "commitment inputs")
    })?;
    let spent = commitment.output.iter().try_fold(0_u64, |total, out| {
        add_sat(total, out.value.to_sat(), "commitment outputs")
    })?;
    let change = sub_sat(
        sub_sat(total_in, spent, "liquidity")?,
        fee,
        "liquidity after fee",
    )?;
    if change < DUST_SAT || fee > params.fee_bound_sat {
        return Err(Error::Construction(format!(
            "commitment change {change} sat or fee {fee} sat is outside policy"
        )));
    }
    commitment.output[change_vout].value = Amount::from_sat(change);
    statement.commitment = commitment;
    let mut queue = VecDeque::from([(
        0_u16,
        count_u16,
        None::<u16>,
        0_u32,
        statement.commitment.compute_txid(),
    )]);
    while let Some((lo, hi, parent, parent_vout, parent_txid)) = queue.pop_front() {
        let mid = split_point(lo, hi);
        let left = if mid - lo == 1 {
            spec.participants[usize::from(lo)].amount_sat
        } else {
            values[&(lo, mid)]
        };
        let right = if hi - mid == 1 {
            spec.participants[usize::from(mid)].amount_sat
        } else {
            values[&(mid, hi)]
        };
        let tx = template(
            vec![input(
                OutPoint::new(parent_txid, parent_vout),
                Sequence::MAX,
            )],
            vec![
                output(left, statement.range_script(lo, mid)?),
                output(right, statement.range_script(mid, hi)?),
            ],
        );
        let index = to_u16(statement.tree.len(), "tree index")?;
        let txid = tx.compute_txid();
        statement.tree.push(TreeTx {
            lo,
            hi,
            parent,
            parent_vout,
            tx,
        });
        if mid - lo >= 2 {
            queue.push_back((lo, mid, Some(index), 0, txid));
        }
        if hi - mid >= 2 {
            queue.push_back((mid, hi, Some(index), 1, txid));
        }
    }
    let commitment_txid = statement.commitment.compute_txid();
    for (position, old) in spec.old_vtxos.iter().enumerate() {
        let connector = statement.connectors[position];
        let tx = template(
            vec![
                input(OutPoint::new(commitment_txid, connector), Sequence::MAX),
                input(old.outpoint, Sequence::MAX),
            ],
            vec![output(0, asp_script.clone())],
        );
        let vsize = vsize_with(
            &tx,
            &[
                key_path_witness(),
                cooperative_witness(&statement.owner_vtxo_script(&old.owner)?)?,
            ],
        );
        let fee = fee_for(vsize, params.fee_rate_sat_per_kvb)?;
        let mut tx = tx;
        tx.output[0].value = Amount::from_sat(sub_sat(
            add_sat(old.amount_sat, params.connector_sat, "forfeit value")?,
            fee,
            "forfeit fee",
        )?);
        statement.forfeits.push(Forfeit {
            old: to_u16(position, "old index")?,
            connector: to_u16(position, "connector index")?,
            tx,
        });
    }
    Ok(statement)
}

/// Re-points tree and forfeit inputs at the current parent txids after a
/// template edit, in tree index order (parents precede children).
pub fn relink(statement: &mut ArkTransitionV1) {
    let commitment = statement.commitment.compute_txid();
    for index in 0..statement.tree.len() {
        let parent = match statement.tree[index].parent {
            None => commitment,
            Some(parent) => statement.tree[usize::from(parent)].tx.compute_txid(),
        };
        statement.tree[index].tx.input[0].previous_output.txid = parent;
    }
    for forfeit in &mut statement.forfeits {
        forfeit.tx.input[0].previous_output.txid = commitment;
    }
}

pub struct SignedRound {
    pub digest: [u8; 32],
    pub commitment: Transaction,
    pub tree: Vec<Transaction>,
    pub forfeits: Vec<Transaction>,
    pub traffic: Traffic,
}

impl SignedRound {
    pub fn all(&self) -> Vec<Transaction> {
        let mut all = vec![self.commitment.clone()];
        all.extend(self.tree.iter().cloned());
        all.extend(self.forfeits.iter().cloned());
        all
    }
}

fn cosigner(
    cosigners: &mut Cosigners,
    id: SignerId,
) -> Result<&mut Box<dyn crate::signing::Cosigner>> {
    cosigners.get_mut(&id).ok_or_else(|| Error::Signing {
        stage: "coordinator-topology",
        detail: format!("{} is not connected", id.label()),
    })
}

/// Every cosigner validates the statement against its own intent, the tree is
/// signed and handed back for verification, and only then are boarding,
/// liquidity and forfeit inputs signed.
pub fn sign_round(
    statement: &ArkTransitionV1,
    cosigners: &mut Cosigners,
    intents: &BTreeMap<SignerId, Intent>,
    owners: &BTreeMap<[u8; 33], SignerId>,
    attempt: u32,
) -> Result<SignedRound> {
    let digest = statement.digest()?;
    for (id, intent) in intents {
        let loaded = cosigner(cosigners, *id)?.load(statement, intent)?;
        if loaded != digest {
            return Err(Error::Signing {
                stage: "statement-digest",
                detail: format!("{} derived a different digest", id.label()),
            });
        }
    }
    let mut traffic = Traffic::default();
    let mut tree = Vec::new();
    for index in 0..statement.tree.len() {
        let signed = sign_tree_tx(
            statement,
            digest,
            to_u16(index, "tree")?,
            cosigners,
            owners,
            attempt,
            Fault::None,
        )?;
        traffic.merge(&signed.traffic);
        let mut tx = statement.tree[index].tx.clone();
        tx.input[0].witness = Witness::from_slice(&[signed.signature.to_vec()]);
        tree.push(tx);
    }
    for id in intents.keys() {
        cosigner(cosigners, *id)?.accept_tree(digest, &tree)?;
    }
    let mut commitment = statement.commitment.clone();
    for (index, funding) in statement.funding.iter().enumerate() {
        let position = to_u16(index, "funding")?;
        match &funding.kind {
            FundingKind::Boarding { owner } => {
                let owner_id = *owners.get(owner).ok_or_else(|| {
                    Error::Construction("boarding owner has no signer".to_owned())
                })?;
                let target = SignTarget::Boarding(position);
                let request = SchnorrRequest {
                    statement: digest,
                    target,
                };
                let owner_sig = cosigner(cosigners, owner_id)?.schnorr(&request)?;
                let asp_sig = cosigner(cosigners, SignerId::Asp)?.schnorr(&request)?;
                let script = statement.boarding_script(owner)?;
                let leaf = script.cooperative_leaf();
                commitment.input[index].witness = Witness::from_slice(&[
                    owner_sig.to_vec(),
                    asp_sig.to_vec(),
                    leaf.to_bytes(),
                    script.control_block(&leaf)?.serialize(),
                ]);
            }
            FundingKind::Liquidity => {
                let request = SchnorrRequest {
                    statement: digest,
                    target: SignTarget::Liquidity(position),
                };
                let signature = cosigner(cosigners, SignerId::Asp)?.schnorr(&request)?;
                commitment.input[index].witness = Witness::from_slice(&[signature.to_vec()]);
            }
        }
    }
    let mut forfeits = Vec::new();
    for (index, forfeit) in statement.forfeits.iter().enumerate() {
        let position = to_u16(index, "forfeit")?;
        let old = &statement.old_vtxos[usize::from(forfeit.old)];
        let owner_id = *owners
            .get(&old.owner)
            .ok_or_else(|| Error::Construction("forfeit owner has no signer".to_owned()))?;
        let request = SchnorrRequest {
            statement: digest,
            target: SignTarget::Forfeit(position),
        };
        let owner_sig = cosigner(cosigners, owner_id)?.schnorr(&request)?;
        let asp_sig = cosigner(cosigners, SignerId::Asp)?.schnorr(&request)?;
        let connector_sig = cosigner(cosigners, SignerId::Asp)?.schnorr(&SchnorrRequest {
            statement: digest,
            target: SignTarget::Connector(position),
        })?;
        let script = statement.owner_vtxo_script(&old.owner)?;
        let leaf = script.cooperative_leaf();
        let mut tx = forfeit.tx.clone();
        tx.input[0].witness = Witness::from_slice(&[connector_sig.to_vec()]);
        tx.input[1].witness = Witness::from_slice(&[
            owner_sig.to_vec(),
            asp_sig.to_vec(),
            leaf.to_bytes(),
            script.control_block(&leaf)?.serialize(),
        ]);
        forfeits.push(tx);
    }
    Ok(SignedRound {
        digest,
        commitment,
        tree,
        forfeits,
        traffic,
    })
}

/// A single-key spend of `outpoint` through the owner's CSV exit leaf.
pub fn exit_tx(
    script: &VtxoScript,
    outpoint: OutPoint,
    amount: u64,
    destination: ScriptBuf,
    rate: u64,
    owner: &Participant,
) -> Result<Transaction> {
    let leaf = script.exit_leaf();
    let control = script.control_block(&leaf)?.serialize();
    let mut tx = template(
        vec![input(outpoint, csv_sequence(script.exit_delay))],
        vec![output(0, destination)],
    );
    let vsize = vsize_with(&tx, &[vec![vec![0; 64], leaf.to_bytes(), control.clone()]]);
    tx.output[0].value = Amount::from_sat(sub_sat(amount, fee_for(vsize, rate)?, "exit fee")?);
    let prevouts = [output(amount, script.script_pubkey()?)];
    let digest = sighash(&crate::signing::SpendTarget {
        tx: tx.clone(),
        prevouts: prevouts.to_vec(),
        input: 0,
        leaf: Some(leaf.clone()),
    })?;
    let signature = owner.sign_script_path(digest)?;
    tx.input[0].witness = Witness::from_slice(&[signature.to_vec(), leaf.to_bytes(), control]);
    Ok(tx)
}

/// The operator's reclaim of a tree node output after the batch expiry.
pub fn sweep_tx(
    node: &NodeScript,
    outpoint: OutPoint,
    amount: u64,
    rate: u64,
    asp: &Participant,
) -> Result<Transaction> {
    let leaf = node.sweep_leaf();
    let control = node.control_block()?.serialize();
    let mut tx = template(
        vec![input(outpoint, csv_sequence(node.expiry))],
        vec![output(0, key_path_script(asp.xonly()?))],
    );
    let vsize = vsize_with(&tx, &[vec![vec![0; 64], leaf.to_bytes(), control.clone()]]);
    tx.output[0].value = Amount::from_sat(sub_sat(amount, fee_for(vsize, rate)?, "sweep fee")?);
    let digest = sighash(&crate::signing::SpendTarget {
        tx: tx.clone(),
        prevouts: vec![output(amount, node.script_pubkey()?)],
        input: 0,
        leaf: Some(leaf.clone()),
    })?;
    let signature = asp.sign_script_path(digest)?;
    tx.input[0].witness = Witness::from_slice(&[signature.to_vec(), leaf.to_bytes(), control]);
    Ok(tx)
}

/// A key-path spend from single-key Taproot outputs controlled by `key`.
pub fn key_spend(
    key: &Participant,
    inputs: &[(OutPoint, u64)],
    outputs: Vec<TxOut>,
    sequence: Sequence,
    version: Version,
) -> Result<Transaction> {
    let script = key_path_script(key.xonly()?);
    let mut tx = template(
        inputs
            .iter()
            .map(|(outpoint, _)| input(*outpoint, sequence))
            .collect(),
        outputs,
    );
    tx.version = version;
    let prevouts: Vec<TxOut> = inputs
        .iter()
        .map(|(_, amount)| output(*amount, script.clone()))
        .collect();
    for index in 0..tx.input.len() {
        let digest = sighash(&crate::signing::SpendTarget {
            tx: tx.clone(),
            prevouts: prevouts.clone(),
            input: index,
            leaf: None,
        })?;
        tx.input[index].witness = Witness::from_slice(&[key.sign_key_path(digest)?.to_vec()]);
    }
    Ok(tx)
}

pub fn key_spend_vsize(inputs: usize, outputs: &[TxOut]) -> usize {
    let tx = template(
        (0..inputs)
            .map(|_| input(OutPoint::null(), Sequence::MAX))
            .collect(),
        outputs.to_vec(),
    );
    let witnesses: Vec<Vec<Vec<u8>>> = (0..inputs).map(|_| key_path_witness()).collect();
    vsize_with(&tx, &witnesses)
}

pub fn unanchored() -> ChainAnchor {
    ChainAnchor {
        block_hash: [0; 32],
        height: 0,
        assumption: AnchorAssumption::Unanchored,
    }
}

pub fn synthetic_outpoint(label: &str, index: u32) -> OutPoint {
    OutPoint::new(
        Txid::from_byte_array(crate::statement::tagged_hash(
            b"ark-nested-musig2/synthetic",
            label.as_bytes(),
        )),
        index,
    )
}
