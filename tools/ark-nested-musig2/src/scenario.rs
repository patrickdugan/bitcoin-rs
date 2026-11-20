mod adversarial;
mod bench;

pub use adversarial::AdversarialCase;
pub use bench::{BenchRow, Synthetic, bench, synthetic};

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::str::FromStr as _;

use bitcoin::consensus::encode::serialize_hex;
use bitcoin::hex::{DisplayHex as _, FromHex as _};
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxOut, Witness};
use serde::{Deserialize, Serialize};

use crate::client::{Intent, Observed, RoleSigner};
use crate::keys::{KeyNetwork, Participant};
use crate::policy::{Shape, SignerId};
use crate::remote::ProcessCosigner;
use crate::round::{
    Params, RoundSpec, build_round, exit_tx, fee_for, key_spend, key_spend_vsize, output,
    sign_round, sweep_tx,
};
use crate::scripts::{VtxoScript, key_path_script};
use crate::signing::Cosigners;
use crate::statement::{
    AnchorAssumption, ArkTransitionV1, ChainAnchor, CheckReport, Funding, FundingKind, OldVtxo,
    Participant as Leaf, check_statement, nova_witness,
};
use crate::traffic::Traffic;
use crate::{Error, Result, sub_sat, to_u16, to_u32};

pub const FUNDING_SCHEMA: &str = "ark-nm2-funding-v1";
pub const P2A_SCRIPT: [u8; 4] = [0x51, 0x02, 0x4e, 0x73];
pub const BOARDING_BASE_SAT: u64 = 200_000;
pub const LIQUIDITY_SAT: u64 = 5_000_000;

pub fn key_file(dir: &Path, role: SignerId) -> PathBuf {
    match role {
        SignerId::Asp => dir.join("asp.key"),
        SignerId::User(index) => dir.join(format!("user-{index}.key")),
    }
}

pub fn faucet_file(dir: &Path) -> PathBuf {
    dir.join("faucet.key")
}

pub fn boarding_amount(base: u64, user: u16) -> u64 {
    base + 1_000 * u64::from(user)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FundingOutput {
    pub role: String,
    pub index: u16,
    pub vout: u32,
    pub amount_sat: u64,
    pub script_pubkey: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FundingRecord {
    pub schema: String,
    pub network: String,
    pub txid: String,
    pub hex: String,
    pub vsize: usize,
    pub fee_sat: u64,
    pub outputs: Vec<FundingOutput>,
}

impl FundingRecord {
    pub fn find(&self, role: &str, index: u16) -> Result<(OutPoint, &FundingOutput)> {
        let output = self
            .outputs
            .iter()
            .find(|output| output.role == role && output.index == index)
            .ok_or_else(|| Error::Construction(format!("funding has no {role} {index}")))?;
        let txid = bitcoin::Txid::from_str(&self.txid)
            .map_err(|_| Error::Construction("funding txid".to_owned()))?;
        Ok((OutPoint::new(txid, output.vout), output))
    }
}

pub fn script_hex(text: &str) -> Result<ScriptBuf> {
    Ok(ScriptBuf::from_bytes(Vec::<u8>::from_hex(text).map_err(
        |_| Error::Construction("script hex".to_owned()),
    )?))
}

/// The regtest faucet transaction: boarding outputs for every user, one
/// liquidity output per round attempt, two outputs for the anchor package
/// probe, and change back to the faucet.
pub fn fund(
    dir: &Path,
    network: KeyNetwork,
    users: u16,
    rounds: u16,
    coinbase: OutPoint,
    coinbase_sat: u64,
    params: &Params,
    boarding_base: u64,
    liquidity_sat: u64,
) -> Result<FundingRecord> {
    let faucet = Participant::load(&faucet_file(dir), network)?;
    let asp = Participant::load(&key_file(dir, SignerId::Asp), network)?;
    let asp_xonly = asp.xonly()?;
    let mut outputs = Vec::new();
    let mut records = Vec::new();
    for user in 0..users {
        let owner = Participant::load(&key_file(dir, SignerId::User(user)), network)?;
        let script = VtxoScript {
            owner: owner.xonly()?,
            asp: asp_xonly,
            exit_delay: params.boarding_delay,
        }
        .script_pubkey()?;
        records.push((
            "boarding",
            user,
            boarding_amount(boarding_base, user),
            script.clone(),
        ));
        outputs.push(output(boarding_amount(boarding_base, user), script));
    }
    for round in 0..rounds {
        let script = key_path_script(asp_xonly);
        records.push(("liquidity", round, liquidity_sat, script.clone()));
        outputs.push(output(liquidity_sat, script));
    }
    let faucet_script = key_path_script(faucet.xonly()?);
    for (index, role) in ["anchor-parent", "anchor-child"].into_iter().enumerate() {
        records.push((
            role,
            to_u16(index, "anchor")?,
            boarding_base,
            faucet_script.clone(),
        ));
        outputs.push(output(boarding_base, faucet_script.clone()));
    }
    outputs.push(output(0, faucet_script.clone()));
    let fee = fee_for(key_spend_vsize(1, &outputs), params.fee_rate_sat_per_kvb)?;
    let spent = outputs.iter().try_fold(0_u64, |total, o| {
        crate::add_sat(total, o.value.to_sat(), "funding")
    })?;
    let change = sub_sat(
        sub_sat(coinbase_sat, spent, "funding change")?,
        fee,
        "funding fee",
    )?;
    let last = outputs.len() - 1;
    outputs[last].value = Amount::from_sat(change);
    records.push(("change", 0, change, faucet_script));
    let tx = key_spend(
        &faucet,
        &[(coinbase, coinbase_sat)],
        outputs,
        Sequence::ENABLE_RBF_NO_LOCKTIME,
        Version::TWO,
    )?;
    Ok(FundingRecord {
        schema: FUNDING_SCHEMA.to_owned(),
        network: network.name().to_owned(),
        txid: tx.compute_txid().to_string(),
        hex: serialize_hex(&tx),
        vsize: tx.vsize(),
        fee_sat: fee,
        outputs: records
            .into_iter()
            .enumerate()
            .map(|(vout, (role, index, amount, script))| {
                Ok(FundingOutput {
                    role: role.to_owned(),
                    index,
                    vout: to_u32(vout, "vout")?,
                    amount_sat: amount,
                    script_pubkey: script.to_hex_string(),
                })
            })
            .collect::<Result<_>>()?,
    })
}

#[derive(Clone, Debug, Deserialize)]
pub struct ObservedUtxo {
    pub outpoint: String,
    pub amount_sat: u64,
    pub script_pubkey: String,
    pub confirmations: u32,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ObservedRecord {
    pub node: String,
    pub best_hash: String,
    pub height: u32,
    pub utxos: Vec<ObservedUtxo>,
}

impl ObservedRecord {
    pub fn utxos(&self) -> Result<Vec<Observed>> {
        self.utxos
            .iter()
            .map(|utxo| {
                Ok(Observed {
                    outpoint: OutPoint::from_str(&utxo.outpoint)
                        .map_err(|_| Error::Construction("observed outpoint".to_owned()))?,
                    amount_sat: utxo.amount_sat,
                    script_pubkey: script_hex(&utxo.script_pubkey)?,
                    confirmations: utxo.confirmations,
                })
            })
            .collect()
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct GraphTx {
    pub id: String,
    pub kind: &'static str,
    pub txid: String,
    pub wtxid: String,
    pub hex: String,
    pub version: i32,
    pub vsize: usize,
    pub weight: u64,
    pub fee_sat: Option<u64>,
    pub signers: Vec<String>,
    pub statement: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "step", rename_all = "kebab-case")]
pub enum Play {
    Submit {
        id: String,
        expect: &'static str,
        stage: &'static str,
        note: &'static str,
    },
    Package {
        parent: String,
        child: String,
        note: &'static str,
    },
    Mine {
        include: Vec<String>,
        note: &'static str,
    },
    MineUntilAge {
        id: String,
        vout: u32,
        age: u32,
        note: &'static str,
    },
    AssertUtxo {
        id: String,
        vout: u32,
        unspent: bool,
        note: &'static str,
    },
    AssertMempool {
        id: String,
        present: bool,
        note: &'static str,
    },
    Reorg {
        depth: u32,
        note: &'static str,
    },
}

#[derive(Serialize)]
pub struct StatementRecord {
    pub name: String,
    pub digest: String,
    pub bytes: usize,
    pub hex: String,
    pub check: CheckReport,
}

#[derive(Serialize)]
pub struct SigningRecord {
    pub round: String,
    pub shape: &'static str,
    pub traffic: Traffic,
    pub remote_users: Vec<u16>,
    pub remote_pids: Vec<u32>,
}

#[derive(Serialize)]
pub struct ScenarioOutput {
    pub schema: &'static str,
    pub network: &'static str,
    pub params: ParamsRecord,
    pub txs: Vec<GraphTx>,
    pub plays: Vec<Play>,
    pub statements: Vec<StatementRecord>,
    pub signing: Vec<SigningRecord>,
    pub adversarial: Vec<AdversarialCase>,
}

#[derive(Serialize)]
pub struct ParamsRecord {
    pub exit_delay: u16,
    pub boarding_delay: u16,
    pub batch_expiry: u16,
    pub fee_rate_sat_per_kvb: u64,
    pub fee_bound_sat: u64,
    pub connector_sat: u64,
}

pub struct Graph {
    pub txs: Vec<GraphTx>,
    prevouts: BTreeMap<OutPoint, TxOut>,
}

impl Graph {
    fn new() -> Self {
        Self {
            txs: Vec::new(),
            prevouts: BTreeMap::new(),
        }
    }

    fn learn(&mut self, tx: &Transaction) {
        let txid = tx.compute_txid();
        for (vout, out) in tx.output.iter().enumerate() {
            if let Ok(vout) = u32::try_from(vout) {
                self.prevouts.insert(OutPoint::new(txid, vout), out.clone());
            }
        }
    }

    pub fn add(
        &mut self,
        id: &str,
        kind: &'static str,
        tx: &Transaction,
        signers: &[&str],
        statement: Option<String>,
    ) -> Result<()> {
        let fee = tx
            .input
            .iter()
            .map(|input| {
                self.prevouts
                    .get(&input.previous_output)
                    .map(|out| out.value.to_sat())
            })
            .collect::<Option<Vec<u64>>>()
            .and_then(|values| values.into_iter().try_fold(0_u64, u64::checked_add))
            .zip(
                tx.output
                    .iter()
                    .try_fold(0_u64, |total, out| total.checked_add(out.value.to_sat())),
            )
            .and_then(|(inputs, outputs)| inputs.checked_sub(outputs));
        self.txs.push(GraphTx {
            id: id.to_owned(),
            kind,
            txid: tx.compute_txid().to_string(),
            wtxid: tx.compute_wtxid().to_string(),
            hex: serialize_hex(tx),
            version: tx.version.0,
            vsize: tx.vsize(),
            weight: tx.weight().to_wu(),
            fee_sat: fee,
            signers: signers.iter().map(|signer| (*signer).to_owned()).collect(),
            statement,
        });
        self.learn(tx);
        Ok(())
    }
}

pub struct ScenarioInput<'a> {
    pub dir: &'a Path,
    pub network: KeyNetwork,
    pub funding: &'a FundingRecord,
    pub observed: &'a [ObservedRecord],
    pub remote_users: &'a [u16],
    pub binary: &'a Path,
}

pub const ROUND_USERS: u16 = 4;
pub const REFUSED_USER: u16 = 4;

fn submit(id: &str, expect: &'static str, stage: &'static str, note: &'static str) -> Play {
    Play::Submit {
        id: id.to_owned(),
        expect,
        stage,
        note,
    }
}

fn mine(include: &[&str], note: &'static str) -> Play {
    Play::Mine {
        include: include.iter().map(|id| (*id).to_owned()).collect(),
        note,
    }
}

struct Session {
    cosigners: Cosigners,
    remote: Vec<u32>,
}

fn connect(input: &ScenarioInput<'_>, users: &[u16]) -> Result<Session> {
    let mut cosigners: Cosigners = BTreeMap::new();
    let mut remote = Vec::new();
    cosigners.insert(
        SignerId::Asp,
        Box::new(RoleSigner::new(
            SignerId::Asp,
            Participant::load(&key_file(input.dir, SignerId::Asp), input.network)?,
        )?),
    );
    for user in users {
        let id = SignerId::User(*user);
        let path = key_file(input.dir, id);
        if input.remote_users.contains(user) {
            let process = ProcessCosigner::spawn(input.binary, id, &path, input.network)?;
            remote.push(process.pid);
            cosigners.insert(id, Box::new(process));
        } else {
            cosigners.insert(
                id,
                Box::new(RoleSigner::new(
                    id,
                    Participant::load(&path, input.network)?,
                )?),
            );
        }
    }
    Ok(Session { cosigners, remote })
}

fn owner_map(dir: &Path, network: KeyNetwork, users: u16) -> Result<BTreeMap<[u8; 33], SignerId>> {
    let mut owners = BTreeMap::new();
    for user in 0..users {
        owners.insert(
            Participant::load(&key_file(dir, SignerId::User(user)), network)?
                .plain()?
                .serialize(),
            SignerId::User(user),
        );
    }
    Ok(owners)
}

fn record_statement(
    name: &str,
    statement: &ArkTransitionV1,
    signed: &[Transaction],
) -> Result<StatementRecord> {
    let bytes = statement.encode()?;
    Ok(StatementRecord {
        name: name.to_owned(),
        digest: statement.digest()?.to_lower_hex_string(),
        bytes: bytes.len(),
        hex: bytes.to_lower_hex_string(),
        check: check_statement(statement, signed)?,
    })
}

/// Builds and signs the whole committed graph for the four-user lifecycle,
/// then lists the order in which the harness submits it to both nodes.
pub fn run_scenario(input: &ScenarioInput<'_>, out: &Path) -> Result<ScenarioOutput> {
    let params = Params::regtest(Shape::Nested);
    let network = input.network;
    let boarding_amount = |user: u16| -> u64 {
        input
            .funding
            .find("boarding", user)
            .map(|(_, record)| record.amount_sat)
            .unwrap_or(0)
    };
    let liquidity_sat = input.funding.find("liquidity", 0)?.1.amount_sat;
    let anchor_sat = input.funding.find("anchor-parent", 0)?.1.amount_sat;
    let asp_key = Participant::load(&key_file(input.dir, SignerId::Asp), network)?;
    let asp = asp_key.plain()?;
    let faucet = Participant::load(&faucet_file(input.dir), network)?;
    let total_users = ROUND_USERS + 1;
    let owners = owner_map(input.dir, network, total_users)?;
    let mut keys = Vec::new();
    for user in 0..total_users {
        keys.push(Participant::load(
            &key_file(input.dir, SignerId::User(user)),
            network,
        )?);
    }
    let owner_bytes: Vec<[u8; 33]> = keys
        .iter()
        .map(|k| k.plain().map(|p| p.serialize()))
        .collect::<Result<_>>()?;
    let [first, second] = input.observed else {
        return Err(Error::Construction(
            "observations from exactly two nodes are required".to_owned(),
        ));
    };
    let observed = first.utxos()?;
    if observed != second.utxos()? || first.best_hash != second.best_hash {
        return Err(Error::Construction(format!(
            "{} and {} disagree on the funding UTXOs or tip",
            first.node, second.node
        )));
    }
    let anchor_hash = <[u8; 32]>::from_hex(&first.best_hash)
        .map_err(|_| Error::Construction("anchor hash".to_owned()))?;
    let anchor = ChainAnchor {
        block_hash: anchor_hash,
        height: first.height,
        assumption: AnchorAssumption::ObservedConfirmed,
    };
    let mut graph = Graph::new();
    let funding_tx: Transaction = bitcoin::consensus::encode::deserialize_hex(&input.funding.hex)
        .map_err(|_| Error::Construction("funding hex".to_owned()))?;
    graph.learn(&funding_tx);
    let boarding_funding = |user: u16| -> Result<Funding> {
        let (outpoint, record) = input.funding.find("boarding", user)?;
        Ok(Funding {
            outpoint,
            amount_sat: record.amount_sat,
            script_pubkey: script_hex(&record.script_pubkey)?,
            kind: FundingKind::Boarding {
                owner: owner_bytes[usize::from(user)],
            },
        })
    };
    let liquidity = |round: u16| -> Result<Funding> {
        let (outpoint, record) = input.funding.find("liquidity", round)?;
        Ok(Funding {
            outpoint,
            amount_sat: record.amount_sat,
            script_pubkey: script_hex(&record.script_pubkey)?,
            kind: FundingKind::Liquidity,
        })
    };
    let round_users: Vec<u16> = (0..ROUND_USERS).collect();
    let r1_leaves: Vec<Leaf> = round_users
        .iter()
        .map(|user| Leaf {
            owner: owner_bytes[usize::from(*user)],
            amount_sat: boarding_amount(*user),
        })
        .collect();
    let boarding: Vec<Funding> = round_users
        .iter()
        .map(|user| boarding_funding(*user))
        .collect::<Result<_>>()?;
    let intents_r1 = |observed: &[Observed]| -> Result<BTreeMap<SignerId, Intent>> {
        let mut intents = BTreeMap::new();
        intents.insert(
            SignerId::Asp,
            Intent {
                observed: observed.to_vec(),
                ..Intent::default()
            },
        );
        for user in 0..ROUND_USERS {
            let funding = boarding_funding(user)?;
            intents.insert(
                SignerId::User(user),
                Intent {
                    receive: vec![boarding_amount(user)],
                    boarding: vec![(funding.outpoint, funding.amount_sat)],
                    observed: observed.to_vec(),
                    ..Intent::default()
                },
            );
        }
        Ok(intents)
    };
    let mut statements = Vec::new();
    let mut signing = Vec::new();
    let mut adversarial = Vec::new();

    let r0 = build_round(
        &params,
        asp,
        &RoundSpec {
            round: 0,
            sequence: 0,
            previous: [0; 32],
            participants: r1_leaves.clone(),
            boarding: boarding.clone(),
            liquidity: liquidity(0)?,
            old_vtxos: Vec::new(),
            coop_exits: Vec::new(),
            anchor: anchor.clone(),
        },
    )?;
    let mut session = connect(input, &round_users)?;
    let signed_r0 = sign_round(
        &r0,
        &mut session.cosigners,
        &intents_r1(&observed)?,
        &owners,
        0,
    )?;
    signing.push(SigningRecord {
        round: "r0".to_owned(),
        shape: "nested",
        traffic: signed_r0.traffic.clone(),
        remote_users: input.remote_users.to_vec(),
        remote_pids: session.remote.clone(),
    });
    statements.push(record_statement("r0", &r0, &signed_r0.all())?);
    let r0_digest = Some(r0.digest()?.to_lower_hex_string());
    graph.add(
        "r0-commitment",
        "commitment",
        &signed_r0.commitment,
        &["asp", "user-0", "user-1", "user-2", "user-3"],
        r0_digest,
    )?;
    let (liq0, _) = input.funding.find("liquidity", 0)?;
    let asp_script = key_path_script(asp_key.xonly()?);
    let r0_fee = graph.txs.last().and_then(|tx| tx.fee_sat).unwrap_or(0);
    let low = key_spend(
        &asp_key,
        &[(liq0, liquidity_sat)],
        vec![output(liquidity_sat - 300, asp_script.clone())],
        Sequence::ENABLE_RBF_NO_LOCKTIME,
        Version::TWO,
    )?;
    graph.add("asp-replace-low", "replacement", &low, &["asp"], None)?;
    let high = key_spend(
        &asp_key,
        &[(liq0, liquidity_sat)],
        vec![output(liquidity_sat - r0_fee - 10_000, asp_script.clone())],
        Sequence::ENABLE_RBF_NO_LOCKTIME,
        Version::TWO,
    )?;
    graph.add("asp-replace-high", "replacement", &high, &["asp"], None)?;

    adversarial.extend(adversarial::signer_faults(
        &r0,
        &mut session,
        &owners,
        &intents_r1(&observed)?,
        input,
    )?);

    let r1 = build_round(
        &params,
        asp,
        &RoundSpec {
            round: 1,
            sequence: 1,
            previous: [0; 32],
            participants: r1_leaves.clone(),
            boarding: boarding.clone(),
            liquidity: liquidity(1)?,
            old_vtxos: Vec::new(),
            coop_exits: Vec::new(),
            anchor: anchor.clone(),
        },
    )?;
    let signed_r1 = sign_round(
        &r1,
        &mut session.cosigners,
        &intents_r1(&observed)?,
        &owners,
        0,
    )?;
    signing.push(SigningRecord {
        round: "r1".to_owned(),
        shape: "nested",
        traffic: signed_r1.traffic.clone(),
        remote_users: input.remote_users.to_vec(),
        remote_pids: session.remote.clone(),
    });
    statements.push(record_statement("r1", &r1, &signed_r1.all())?);
    let r1_digest = r1.digest()?;
    let r1_tag = Some(r1_digest.to_lower_hex_string());
    graph.add(
        "r1-commitment",
        "commitment",
        &signed_r1.commitment,
        &["asp", "user-0", "user-1", "user-2", "user-3"],
        r1_tag.clone(),
    )?;
    for (index, tx) in signed_r1.tree.iter().enumerate() {
        graph.add(
            &format!("r1-tree-{index}"),
            "tree",
            tx,
            &["nested:asp+cosigners"],
            r1_tag.clone(),
        )?;
    }
    adversarial.extend(adversarial::statement_cases(
        &r1,
        &params,
        asp,
        &asp_key,
        &owner_bytes,
        &observed,
        input,
    )?);

    let flat_params = Params::regtest(Shape::Flat);
    let r1_flat = build_round(
        &flat_params,
        asp,
        &RoundSpec {
            round: 1,
            sequence: 1,
            previous: [0; 32],
            participants: r1_leaves.clone(),
            boarding: boarding.clone(),
            liquidity: liquidity(1)?,
            old_vtxos: Vec::new(),
            coop_exits: Vec::new(),
            anchor: anchor.clone(),
        },
    )?;
    let mut local = connect(
        &ScenarioInput {
            remote_users: &[],
            ..*input
        },
        &round_users,
    )?;
    let signed_flat = sign_round(
        &r1_flat,
        &mut local.cosigners,
        &intents_r1(&observed)?,
        &owners,
        0,
    )?;
    signing.push(SigningRecord {
        round: "r1-flat-comparison".to_owned(),
        shape: "flat",
        traffic: signed_flat.traffic.clone(),
        remote_users: Vec::new(),
        remote_pids: Vec::new(),
    });
    statements.push(record_statement("r1-flat", &r1_flat, &signed_flat.all())?);

    let vtxos = r1.vtxo_outpoints()?;
    let vtxo_script = |user: u16| -> Result<VtxoScript> { r1.vtxo_script(usize::from(user)) };
    let old = |user: u16| -> Result<OldVtxo> {
        Ok(OldVtxo {
            outpoint: vtxos[usize::from(user)],
            amount_sat: boarding_amount(user),
            owner: owner_bytes[usize::from(user)],
            script_pubkey: vtxo_script(user)?.script_pubkey()?,
        })
    };
    let b_exit_script = key_path_script(keys[1].xonly()?);
    let r2 = build_round(
        &params,
        asp,
        &RoundSpec {
            round: 2,
            sequence: 2,
            previous: r1_digest,
            participants: vec![
                Leaf {
                    owner: owner_bytes[2],
                    amount_sat: boarding_amount(0),
                },
                Leaf {
                    owner: owner_bytes[2],
                    amount_sat: boarding_amount(2),
                },
            ],
            boarding: Vec::new(),
            liquidity: liquidity(2)?,
            old_vtxos: vec![old(0)?, old(1)?, old(2)?],
            coop_exits: vec![(owner_bytes[1], b_exit_script.clone(), boarding_amount(1))],
            anchor: anchor.clone(),
        },
    )?;
    let mut intents_r2 = BTreeMap::new();
    intents_r2.insert(
        SignerId::Asp,
        Intent {
            observed: observed.clone(),
            ..Intent::default()
        },
    );
    intents_r2.insert(
        SignerId::User(0),
        Intent {
            forfeit: vec![(vtxos[0], boarding_amount(0))],
            observed: observed.clone(),
            ..Intent::default()
        },
    );
    intents_r2.insert(
        SignerId::User(1),
        Intent {
            forfeit: vec![(vtxos[1], boarding_amount(1))],
            coop_exit: vec![(b_exit_script.clone(), boarding_amount(1))],
            observed: observed.clone(),
            ..Intent::default()
        },
    );
    intents_r2.insert(
        SignerId::User(2),
        Intent {
            receive: vec![boarding_amount(0), boarding_amount(2)],
            forfeit: vec![(vtxos[2], boarding_amount(2))],
            observed: observed.clone(),
            ..Intent::default()
        },
    );
    let signed_r2 = sign_round(&r2, &mut session.cosigners, &intents_r2, &owners, 0)?;
    signing.push(SigningRecord {
        round: "r2".to_owned(),
        shape: "nested",
        traffic: signed_r2.traffic.clone(),
        remote_users: input.remote_users.to_vec(),
        remote_pids: session.remote.clone(),
    });
    statements.push(record_statement("r2", &r2, &signed_r2.all())?);
    let r2_tag = Some(r2.digest()?.to_lower_hex_string());
    graph.add(
        "r2-commitment",
        "commitment",
        &signed_r2.commitment,
        &["asp"],
        r2_tag.clone(),
    )?;
    for (index, tx) in signed_r2.forfeits.iter().enumerate() {
        graph.add(
            &format!("r2-forfeit-{index}"),
            "forfeit",
            tx,
            &[&format!("user-{index}"), "asp"],
            r2_tag.clone(),
        )?;
    }
    for (index, tx) in signed_r2.tree.iter().enumerate() {
        graph.add(
            &format!("r2-tree-{index}"),
            "tree",
            tx,
            &["nested:asp+cosigners"],
            r2_tag.clone(),
        )?;
    }
    let mut altered = signed_r2.commitment.clone();
    let exit_vout =
        usize::try_from(r2.coop_exits[0].vout).map_err(|_| Error::Range("exit vout"))?;
    altered.output[exit_vout].script_pubkey = asp_script.clone();
    graph.add(
        "r2-commitment-payout-altered",
        "adversarial",
        &altered,
        &["asp"],
        None,
    )?;

    let rate = params.fee_rate_sat_per_kvb;
    let exit_d = exit_tx(
        &vtxo_script(3)?,
        vtxos[3],
        boarding_amount(3),
        key_path_script(keys[3].xonly()?),
        rate,
        &keys[3],
    )?;
    graph.add("exit-d", "unilateral-exit", &exit_d, &["user-3"], None)?;
    let exit_b = exit_tx(
        &vtxo_script(1)?,
        vtxos[1],
        boarding_amount(1),
        b_exit_script.clone(),
        rate,
        &keys[1],
    )?;
    graph.add("exit-b", "unilateral-exit", &exit_b, &["user-1"], None)?;
    let (e_outpoint, _) = input.funding.find("boarding", REFUSED_USER)?;
    let e_script = r1.boarding_script(&owner_bytes[usize::from(REFUSED_USER)])?;
    let e_recovery = exit_tx(
        &e_script,
        e_outpoint,
        boarding_amount(REFUSED_USER),
        key_path_script(keys[usize::from(REFUSED_USER)].xonly()?),
        rate,
        &keys[usize::from(REFUSED_USER)],
    )?;
    graph.add(
        "e-boarding-recovery",
        "boarding-recovery",
        &e_recovery,
        &["user-4"],
        None,
    )?;
    let batch2 = r2.node_script(0, to_u16(r2.participants.len(), "participants")?)?;
    let batch2_value = signed_r2.commitment.output[0].value.to_sat();
    let sweep = sweep_tx(
        &batch2,
        OutPoint::new(signed_r2.commitment.compute_txid(), 0),
        batch2_value,
        10_000,
        &asp_key,
    )?;
    graph.add("asp-sweep-r2", "sweep", &sweep, &["asp"], None)?;

    let (parent_in, _) = input.funding.find("anchor-parent", 0)?;
    let (child_in, _) = input.funding.find("anchor-child", 1)?;
    let faucet_script = key_path_script(faucet.xonly()?);
    let zero_v2 = key_spend(
        &faucet,
        &[(parent_in, anchor_sat)],
        vec![output(anchor_sat, faucet_script.clone())],
        Sequence::MAX,
        Version::TWO,
    )?;
    graph.add("zero-fee-v2", "fee-floor", &zero_v2, &["faucet"], None)?;
    let parent = key_spend(
        &faucet,
        &[(parent_in, anchor_sat)],
        vec![
            output(anchor_sat, faucet_script.clone()),
            output(0, ScriptBuf::from_bytes(P2A_SCRIPT.to_vec())),
        ],
        Sequence::MAX,
        Version(3),
    )?;
    graph.add(
        "arkade-style-v3-parent",
        "anchor-package",
        &parent,
        &["faucet"],
        None,
    )?;
    let child = anchor_child(&faucet, &parent, child_in, anchor_sat, rate)?;
    graph.add(
        "arkade-style-v3-child",
        "anchor-package",
        &child,
        &["faucet"],
        None,
    )?;

    adversarial.extend(adversarial::round2_cases(
        &r2,
        &signed_r2,
        &params,
        asp,
        &asp_key,
        &owner_bytes,
        &observed,
        input,
    )?);
    drop(session);
    drop(local);

    let witnesses = [("r1", &r1), ("r2", &r2)];
    for (name, statement) in witnesses {
        let witness = nova_witness(statement)?;
        std::fs::write(
            out.join(format!("nova-witness-{name}.json")),
            sonic_rs::to_string_pretty(&witness)?,
        )?;
        std::fs::write(
            out.join(format!("statement-{name}.bin")),
            statement.encode()?,
        )?;
    }
    std::fs::write(out.join("statement-r1-flat.bin"), r1_flat.encode()?)?;

    let plays = vec![
        submit(
            "e-boarding-recovery",
            "reject",
            "relative-locktime",
            "refused boarding user E before the boarding delay",
        ),
        submit(
            "zero-fee-v2",
            "reject",
            "min-relay-fee",
            "a transaction with no fee reserve",
        ),
        Play::Package {
            parent: "arkade-style-v3-parent".to_owned(),
            child: "arkade-style-v3-child".to_owned(),
            note: "Arkade tree format: v3, zero fee, P2A anchor, CPFP child",
        },
        submit(
            "r0-commitment",
            "accept",
            "",
            "round 0 commitment enters both mempools",
        ),
        submit(
            "asp-replace-low",
            "reject",
            "replacement-fee",
            "operator double-spend of its liquidity with too little fee",
        ),
        submit(
            "asp-replace-high",
            "accept",
            "",
            "operator replaces the round 0 commitment",
        ),
        Play::AssertMempool {
            id: "r0-commitment".to_owned(),
            present: false,
            note: "replaced commitment left both mempools",
        },
        mine(&["asp-replace-high"], "confirm the replacement"),
        submit(
            "r0-commitment",
            "reject",
            "missing-inputs",
            "round 0 can no longer settle",
        ),
        Play::AssertUtxo {
            id: "funding".to_owned(),
            vout: 0,
            unspent: true,
            note: "boarding output A untouched by the aborted round",
        },
        submit(
            "r1-commitment",
            "accept",
            "",
            "round 1 settles four boarding outputs",
        ),
        mine(&["r1-commitment"], "confirm round 1"),
        submit(
            "r2-forfeit-0",
            "reject",
            "missing-inputs",
            "forfeit is unusable before its round commits",
        ),
        submit(
            "r2-commitment-payout-altered",
            "reject",
            "script-verification",
            "cooperative exit destination changed after signing",
        ),
        submit(
            "r2-commitment",
            "accept",
            "",
            "round 2: transfer, cooperative exit, refresh",
        ),
        mine(&["r2-commitment"], "confirm round 2"),
        submit(
            "r1-tree-0",
            "accept",
            "",
            "user D starts a unilateral exit without the operator",
        ),
        mine(&["r1-tree-0"], "confirm tree root"),
        submit("r1-tree-2", "accept", "", "D's branch"),
        mine(&["r1-tree-2"], "confirm D's branch"),
        submit(
            "exit-d",
            "reject",
            "relative-locktime",
            "premature unilateral exit",
        ),
        submit(
            "r2-forfeit-2",
            "accept",
            "",
            "operator claims C's refreshed round-1 VTXO exposed by D's exit",
        ),
        mine(&["r2-forfeit-2"], "confirm forfeit C"),
        Play::MineUntilAge {
            id: "r1-tree-2".to_owned(),
            vout: 1,
            age: u32::from(params.exit_delay),
            note: "exit delay for D",
        },
        submit("exit-d", "accept", "", "D recovers with only its own key"),
        mine(&["exit-d"], "confirm D's exit"),
        submit(
            "r1-tree-1",
            "accept",
            "",
            "B publishes the A/B branch after forfeiting VTXO B",
        ),
        mine(&["r1-tree-1"], "confirm A/B branch"),
        submit(
            "r2-forfeit-0",
            "accept",
            "",
            "operator claims forfeited VTXO A",
        ),
        submit(
            "r2-forfeit-1",
            "accept",
            "",
            "operator claims forfeited VTXO B",
        ),
        mine(&["r2-forfeit-0", "r2-forfeit-1"], "confirm forfeits"),
        submit(
            "r2-forfeit-1",
            "reject",
            "already-spent",
            "replayed forfeit",
        ),
        submit(
            "exit-b",
            "reject",
            "missing-inputs",
            "B's double spend of its forfeited VTXO",
        ),
        submit(
            "asp-sweep-r2",
            "reject",
            "relative-locktime",
            "premature operator reclaim of round 2",
        ),
        Play::MineUntilAge {
            id: "r2-commitment".to_owned(),
            vout: 0,
            age: u32::from(params.batch_expiry),
            note: "round 2 batch expiry",
        },
        submit(
            "r2-tree-0",
            "accept",
            "",
            "C's late unilateral exit after expiry competes with the sweep",
        ),
        mine(&["r2-tree-0"], "C's tree root confirms first"),
        Play::Reorg {
            depth: 1,
            note: "shallow reorganization removes C's tree root",
        },
        submit(
            "asp-sweep-r2",
            "accept",
            "",
            "operator sweep in the reorganized chain",
        ),
        mine(&["asp-sweep-r2"], "the sweep wins the competing spend"),
        submit(
            "r2-tree-0",
            "reject",
            "missing-inputs",
            "C's tree root now conflicts with a confirmed sweep",
        ),
        Play::AssertUtxo {
            id: "r2-commitment".to_owned(),
            vout: 0,
            unspent: false,
            note: "round 2 batch output spent by the sweep",
        },
        submit(
            "e-boarding-recovery",
            "accept",
            "",
            "refused user E recovers its boarding output",
        ),
        mine(&["e-boarding-recovery"], "confirm E's recovery"),
        Play::AssertUtxo {
            id: "exit-d".to_owned(),
            vout: 0,
            unspent: true,
            note: "D holds its recovered coins",
        },
        Play::AssertUtxo {
            id: "r2-commitment".to_owned(),
            vout: r2.coop_exits[0].vout,
            unspent: true,
            note: "B holds its cooperative exit",
        },
    ];
    Ok(ScenarioOutput {
        schema: "ark-nm2-scenario-v1",
        network: network.name(),
        params: ParamsRecord {
            exit_delay: params.exit_delay,
            boarding_delay: params.boarding_delay,
            batch_expiry: params.batch_expiry,
            fee_rate_sat_per_kvb: params.fee_rate_sat_per_kvb,
            fee_bound_sat: params.fee_bound_sat,
            connector_sat: params.connector_sat,
        },
        txs: graph.txs,
        plays,
        statements,
        signing,
        adversarial,
    })
}

/// Spends the P2A anchor (empty witness) together with a faucet input so the
/// package pays the relay fee for its zero-fee parent.
fn anchor_child(
    faucet: &Participant,
    parent: &Transaction,
    fee_input: OutPoint,
    amount: u64,
    rate: u64,
) -> Result<Transaction> {
    let script = key_path_script(faucet.xonly()?);
    let anchor = OutPoint::new(parent.compute_txid(), 1);
    let mut tx = crate::round::template(
        vec![
            crate::round::input(anchor, Sequence::MAX),
            crate::round::input(fee_input, Sequence::MAX),
        ],
        vec![output(0, script.clone())],
    );
    tx.version = Version(3);
    let vsize = crate::round::vsize_with(&tx, &[Vec::new(), crate::round::key_path_witness()]);
    let fee = fee_for(vsize + parent.vsize(), rate.saturating_mul(2))?;
    tx.output[0].value = Amount::from_sat(sub_sat(amount, fee, "anchor child")?);
    let prevouts = vec![
        output(0, ScriptBuf::from_bytes(P2A_SCRIPT.to_vec())),
        output(amount, script),
    ];
    let digest = crate::signing::sighash(&crate::signing::SpendTarget {
        tx: tx.clone(),
        prevouts,
        input: 1,
        leaf: None,
    })?;
    tx.input[1].witness = Witness::from_slice(&[faucet.sign_key_path(digest)?.to_vec()]);
    Ok(tx)
}

/// One round of `users` VTXOs from real funding, then a mass unilateral exit:
/// the commitment, every tree level in its own block, and every user's exit
/// after the delay, all submitted to both nodes.
pub fn run_scale(
    input: &ScenarioInput<'_>,
    users: u16,
    shape: Shape,
    out: &Path,
) -> Result<ScenarioOutput> {
    let params = Params::regtest(shape);
    let network = input.network;
    let asp_key = Participant::load(&key_file(input.dir, SignerId::Asp), network)?;
    let asp = asp_key.plain()?;
    let owners = owner_map(input.dir, network, users)?;
    let [first, second] = input.observed else {
        return Err(Error::Construction(
            "observations from exactly two nodes are required".to_owned(),
        ));
    };
    let observed = first.utxos()?;
    if observed != second.utxos()? || first.best_hash != second.best_hash {
        return Err(Error::Construction(
            "observers disagree on the funding UTXOs or tip".to_owned(),
        ));
    }
    let anchor = ChainAnchor {
        block_hash: <[u8; 32]>::from_hex(&first.best_hash)
            .map_err(|_| Error::Construction("anchor hash".to_owned()))?,
        height: first.height,
        assumption: AnchorAssumption::ObservedConfirmed,
    };
    let mut leaves = Vec::new();
    let mut boarding = Vec::new();
    let mut keys = Vec::new();
    for user in 0..users {
        let key = Participant::load(&key_file(input.dir, SignerId::User(user)), network)?;
        let owner = key.plain()?.serialize();
        let (outpoint, record) = input.funding.find("boarding", user)?;
        leaves.push(Leaf {
            owner,
            amount_sat: record.amount_sat,
        });
        boarding.push(Funding {
            outpoint,
            amount_sat: record.amount_sat,
            script_pubkey: script_hex(&record.script_pubkey)?,
            kind: FundingKind::Boarding { owner },
        });
        keys.push(key);
    }
    let (liquidity_outpoint, liquidity_record) = input.funding.find("liquidity", 0)?;
    let statement = build_round(
        &params,
        asp,
        &RoundSpec {
            round: 1,
            sequence: 1,
            previous: [0; 32],
            participants: leaves,
            boarding: boarding.clone(),
            liquidity: Funding {
                outpoint: liquidity_outpoint,
                amount_sat: liquidity_record.amount_sat,
                script_pubkey: script_hex(&liquidity_record.script_pubkey)?,
                kind: FundingKind::Liquidity,
            },
            old_vtxos: Vec::new(),
            coop_exits: Vec::new(),
            anchor,
        },
    )?;
    let mut intents = BTreeMap::new();
    intents.insert(
        SignerId::Asp,
        Intent {
            observed: observed.clone(),
            ..Intent::default()
        },
    );
    for (user, funding) in boarding.iter().enumerate() {
        intents.insert(
            SignerId::User(to_u16(user, "user")?),
            Intent {
                receive: vec![funding.amount_sat],
                boarding: vec![(funding.outpoint, funding.amount_sat)],
                observed: observed.clone(),
                ..Intent::default()
            },
        );
    }
    let all: Vec<u16> = (0..users).collect();
    let mut session = connect(input, &all)?;
    let signed = sign_round(&statement, &mut session.cosigners, &intents, &owners, 0)?;
    drop(session);
    let tag = Some(statement.digest()?.to_lower_hex_string());
    let mut graph = Graph::new();
    let funding_tx: Transaction = bitcoin::consensus::encode::deserialize_hex(&input.funding.hex)
        .map_err(|_| Error::Construction("funding hex".to_owned()))?;
    graph.learn(&funding_tx);
    graph.add(
        "commitment",
        "commitment",
        &signed.commitment,
        &["asp", "all-users"],
        tag.clone(),
    )?;
    let mut levels: BTreeMap<usize, Vec<String>> = BTreeMap::new();
    for (index, tx) in signed.tree.iter().enumerate() {
        let mut depth = 0;
        let mut parent = statement.tree[index].parent;
        while let Some(next) = parent {
            depth += 1;
            parent = statement.tree[usize::from(next)].parent;
        }
        let id = format!("tree-{index}");
        graph.add(&id, "tree", tx, &["nested:asp+cosigners"], tag.clone())?;
        levels.entry(depth).or_default().push(id);
    }
    let vtxos = statement.vtxo_outpoints()?;
    let mut exits = Vec::new();
    for (user, key) in keys.iter().enumerate() {
        let script = statement.vtxo_script(user)?;
        let tx = exit_tx(
            &script,
            vtxos[user],
            statement.participants[user].amount_sat,
            key_path_script(key.xonly()?),
            params.fee_rate_sat_per_kvb,
            key,
        )?;
        let id = format!("exit-{user}");
        graph.add(
            &id,
            "unilateral-exit",
            &tx,
            &[&format!("user-{user}")],
            None,
        )?;
        exits.push(id);
    }
    std::fs::write(out.join("statement-scale.bin"), statement.encode()?)?;
    std::fs::write(
        out.join("nova-witness-scale.json"),
        sonic_rs::to_string(&nova_witness(&statement)?)?,
    )?;
    let mut plays = vec![
        submit(
            "commitment",
            "accept",
            "",
            "round commitment with every boarding input",
        ),
        mine(&["commitment"], "confirm the round"),
    ];
    for ids in levels.values() {
        for id in ids {
            plays.push(Play::Submit {
                id: id.clone(),
                expect: "accept",
                stage: "",
                note: "mass exit: tree level",
            });
        }
        plays.push(Play::Mine {
            include: ids.clone(),
            note: "confirm one tree level",
        });
    }
    let last_level = levels.values().last().cloned().unwrap_or_default();
    if let Some(leaf) = last_level.first() {
        plays.push(Play::MineUntilAge {
            id: leaf.clone(),
            vout: 0,
            age: u32::from(params.exit_delay),
            note: "exit delay",
        });
    }
    for id in &exits {
        plays.push(Play::Submit {
            id: id.clone(),
            expect: "accept",
            stage: "",
            note: "mass exit: user leaves alone",
        });
    }
    plays.push(Play::Mine {
        include: exits.clone(),
        note: "confirm every exit",
    });
    for id in &exits {
        plays.push(Play::AssertUtxo {
            id: id.clone(),
            vout: 0,
            unspent: true,
            note: "user holds its coins",
        });
    }
    let mut traffic = signed.traffic.clone();
    traffic.seconds = signed.traffic.seconds;
    Ok(ScenarioOutput {
        schema: "ark-nm2-scale-v1",
        network: network.name(),
        params: ParamsRecord {
            exit_delay: params.exit_delay,
            boarding_delay: params.boarding_delay,
            batch_expiry: params.batch_expiry,
            fee_rate_sat_per_kvb: params.fee_rate_sat_per_kvb,
            fee_bound_sat: params.fee_bound_sat,
            connector_sat: params.connector_sat,
        },
        txs: graph.txs,
        plays,
        statements: vec![record_statement("scale", &statement, &signed.all())?],
        signing: vec![SigningRecord {
            round: format!("scale-{users}"),
            shape: shape.name(),
            traffic,
            remote_users: Vec::new(),
            remote_pids: Vec::new(),
        }],
        adversarial: Vec::new(),
    })
}
