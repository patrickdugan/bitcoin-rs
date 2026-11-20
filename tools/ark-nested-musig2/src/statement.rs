mod check;
mod nova;

pub use check::{CheckReport, Coverage, CoverageMethod, Finding, check_statement};
pub use nova::{
    NovaItem, NovaWitness, ProofEnvelope, VerificationResult, nova_witness, spend_id,
    verify_proof_envelope,
};

use bitcoin::hashes::Hash as _;
use bitcoin::secp256k1::XOnlyPublicKey;
use bitcoin::{OutPoint, ScriptBuf, Transaction, TxOut};
use bitcoin_hashes::{HashEngine as _, sha256};
use bitcoin_rs_nested_musig2::PlainPublicKey;

use crate::codec::{CodecError, Reader, Writer};
use crate::keys::KeyNetwork;
use crate::policy::{AggTree, Shape, SignerId};
use crate::scripts::{NodeScript, VtxoScript};
use crate::{Error, Result};

pub const STATEMENT_MAGIC: &[u8; 8] = b"ARKTRNV1";
pub const STATEMENT_VERSION: u16 = 1;
pub const STATEMENT_TAG: &[u8] = b"ArkTransitionV1/statement";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Policy {
    pub shape: Shape,
    pub asp: [u8; 33],
    pub exit_delay: u16,
    pub boarding_delay: u16,
    pub batch_expiry: u16,
    pub fee_rate_sat_per_kvb: u64,
    pub fee_bound_sat: u64,
    pub connector_sat: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Participant {
    pub owner: [u8; 33],
    pub amount_sat: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FundingKind {
    Boarding { owner: [u8; 33] },
    Liquidity,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Funding {
    pub outpoint: OutPoint,
    pub amount_sat: u64,
    pub script_pubkey: ScriptBuf,
    pub kind: FundingKind,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OldVtxo {
    pub outpoint: OutPoint,
    pub amount_sat: u64,
    pub owner: [u8; 33],
    pub script_pubkey: ScriptBuf,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoopExit {
    pub vout: u32,
    pub owner: [u8; 33],
    pub amount_sat: u64,
    pub script_pubkey: ScriptBuf,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TreeTx {
    pub lo: u16,
    pub hi: u16,
    pub parent: Option<u16>,
    pub parent_vout: u32,
    pub tx: Transaction,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Forfeit {
    pub old: u16,
    pub connector: u16,
    pub tx: Transaction,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AnchorAssumption {
    Unanchored,
    ObservedConfirmed,
}

impl AnchorAssumption {
    fn code(self) -> u8 {
        match self {
            Self::Unanchored => 0,
            Self::ObservedConfirmed => 1,
        }
    }

    fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(Self::Unanchored),
            1 => Some(Self::ObservedConfirmed),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Unanchored => "unanchored",
            Self::ObservedConfirmed => "funding-observed-confirmed-by-named-nodes",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainAnchor {
    pub block_hash: [u8; 32],
    pub height: u32,
    pub assumption: AnchorAssumption,
}

/// The canonical encoding is the only accepted form: decoding re-encodes and
/// rejects any difference, trailing bytes, unknown codes, and witness data in
/// transaction templates.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArkTransitionV1 {
    pub network: KeyNetwork,
    pub genesis: [u8; 32],
    pub round: u32,
    pub sequence: u32,
    pub previous: [u8; 32],
    pub policy: Policy,
    pub participants: Vec<Participant>,
    pub funding: Vec<Funding>,
    pub old_vtxos: Vec<OldVtxo>,
    pub commitment: Transaction,
    pub batch_vout: u32,
    pub connectors: Vec<u32>,
    pub coop_exits: Vec<CoopExit>,
    pub tree: Vec<TreeTx>,
    pub forfeits: Vec<Forfeit>,
    pub anchor: ChainAnchor,
}

impl ArkTransitionV1 {
    pub fn encode(&self) -> std::result::Result<Vec<u8>, CodecError> {
        let mut writer = Writer::default();
        writer.fixed(STATEMENT_MAGIC);
        writer.u16(STATEMENT_VERSION);
        writer.u8(self.network.code());
        writer.fixed(&self.genesis);
        writer.u32(self.round);
        writer.u32(self.sequence);
        writer.fixed(&self.previous);
        let policy = &self.policy;
        writer.u8(policy.shape.code());
        writer.fixed(&policy.asp);
        writer.u16(policy.exit_delay);
        writer.u16(policy.boarding_delay);
        writer.u16(policy.batch_expiry);
        writer.u64(policy.fee_rate_sat_per_kvb);
        writer.u64(policy.fee_bound_sat);
        writer.u64(policy.connector_sat);
        writer.count(self.participants.len())?;
        for participant in &self.participants {
            writer.fixed(&participant.owner);
            writer.u64(participant.amount_sat);
        }
        writer.count(self.funding.len())?;
        for funding in &self.funding {
            writer.outpoint(&funding.outpoint);
            writer.u64(funding.amount_sat);
            writer.script(&funding.script_pubkey)?;
            match &funding.kind {
                FundingKind::Boarding { owner } => {
                    writer.u8(1);
                    writer.fixed(owner);
                }
                FundingKind::Liquidity => writer.u8(2),
            }
        }
        writer.count(self.old_vtxos.len())?;
        for old in &self.old_vtxos {
            writer.outpoint(&old.outpoint);
            writer.u64(old.amount_sat);
            writer.fixed(&old.owner);
            writer.script(&old.script_pubkey)?;
        }
        writer.transaction(&self.commitment)?;
        writer.u32(self.batch_vout);
        writer.count(self.connectors.len())?;
        for connector in &self.connectors {
            writer.u32(*connector);
        }
        writer.count(self.coop_exits.len())?;
        for exit in &self.coop_exits {
            writer.u32(exit.vout);
            writer.fixed(&exit.owner);
            writer.u64(exit.amount_sat);
            writer.script(&exit.script_pubkey)?;
        }
        writer.count(self.tree.len())?;
        for node in &self.tree {
            writer.u16(node.lo);
            writer.u16(node.hi);
            writer.u16(node.parent.unwrap_or(u16::MAX));
            writer.u32(node.parent_vout);
            writer.transaction(&node.tx)?;
        }
        writer.count(self.forfeits.len())?;
        for forfeit in &self.forfeits {
            writer.u16(forfeit.old);
            writer.u16(forfeit.connector);
            writer.transaction(&forfeit.tx)?;
        }
        writer.fixed(&self.anchor.block_hash);
        writer.u32(self.anchor.height);
        writer.u8(self.anchor.assumption.code());
        Ok(writer.bytes)
    }

    pub fn decode(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        let mut reader = Reader::new(bytes);
        if reader.take(8, "magic")? != STATEMENT_MAGIC
            || reader.u16("version")? != STATEMENT_VERSION
        {
            return Err(CodecError::Version);
        }
        let network = KeyNetwork::from_code(reader.u8("network")?)
            .ok_or(CodecError::UnknownCode("network"))?;
        let genesis = reader.array("genesis")?;
        let round = reader.u32("round")?;
        let sequence = reader.u32("sequence")?;
        let previous = reader.array("previous")?;
        let policy = Policy {
            shape: Shape::from_code(reader.u8("shape")?).ok_or(CodecError::UnknownCode("shape"))?,
            asp: key33(reader.array("asp")?)?,
            exit_delay: reader.u16("exit delay")?,
            boarding_delay: reader.u16("boarding delay")?,
            batch_expiry: reader.u16("batch expiry")?,
            fee_rate_sat_per_kvb: reader.u64("fee rate")?,
            fee_bound_sat: reader.u64("fee bound")?,
            connector_sat: reader.u64("connector amount")?,
        };
        let mut participants = Vec::new();
        for _ in 0..reader.count("participants")? {
            participants.push(Participant {
                owner: key33(reader.array("participant")?)?,
                amount_sat: reader.u64("participant amount")?,
            });
        }
        let mut funding = Vec::new();
        for _ in 0..reader.count("funding")? {
            let outpoint = reader.outpoint("funding outpoint")?;
            let amount_sat = reader.u64("funding amount")?;
            let script_pubkey = reader.script("funding script")?;
            let kind = match reader.u8("funding kind")? {
                1 => FundingKind::Boarding {
                    owner: key33(reader.array("boarding owner")?)?,
                },
                2 => FundingKind::Liquidity,
                _ => return Err(CodecError::UnknownCode("funding kind")),
            };
            funding.push(Funding {
                outpoint,
                amount_sat,
                script_pubkey,
                kind,
            });
        }
        let mut old_vtxos = Vec::new();
        for _ in 0..reader.count("old vtxos")? {
            old_vtxos.push(OldVtxo {
                outpoint: reader.outpoint("old outpoint")?,
                amount_sat: reader.u64("old amount")?,
                owner: key33(reader.array("old owner")?)?,
                script_pubkey: reader.script("old script")?,
            });
        }
        let commitment = reader.transaction("commitment")?;
        let batch_vout = reader.u32("batch vout")?;
        let mut connectors = Vec::new();
        for _ in 0..reader.count("connectors")? {
            connectors.push(reader.u32("connector vout")?);
        }
        let mut coop_exits = Vec::new();
        for _ in 0..reader.count("cooperative exits")? {
            coop_exits.push(CoopExit {
                vout: reader.u32("exit vout")?,
                owner: key33(reader.array("exit owner")?)?,
                amount_sat: reader.u64("exit amount")?,
                script_pubkey: reader.script("exit script")?,
            });
        }
        let mut tree = Vec::new();
        for _ in 0..reader.count("tree")? {
            let lo = reader.u16("tree lo")?;
            let hi = reader.u16("tree hi")?;
            let parent = match reader.u16("tree parent")? {
                u16::MAX => None,
                index => Some(index),
            };
            tree.push(TreeTx {
                lo,
                hi,
                parent,
                parent_vout: reader.u32("tree parent vout")?,
                tx: reader.transaction("tree tx")?,
            });
        }
        let mut forfeits = Vec::new();
        for _ in 0..reader.count("forfeits")? {
            forfeits.push(Forfeit {
                old: reader.u16("forfeit old")?,
                connector: reader.u16("forfeit connector")?,
                tx: reader.transaction("forfeit tx")?,
            });
        }
        let anchor = ChainAnchor {
            block_hash: reader.array("anchor hash")?,
            height: reader.u32("anchor height")?,
            assumption: AnchorAssumption::from_code(reader.u8("anchor assumption")?)
                .ok_or(CodecError::UnknownCode("anchor assumption"))?,
        };
        reader.finish()?;
        let statement = Self {
            network,
            genesis,
            round,
            sequence,
            previous,
            policy,
            participants,
            funding,
            old_vtxos,
            commitment,
            batch_vout,
            connectors,
            coop_exits,
            tree,
            forfeits,
            anchor,
        };
        if statement.encode()? != bytes {
            return Err(CodecError::Transaction);
        }
        Ok(statement)
    }

    pub fn digest(&self) -> std::result::Result<[u8; 32], CodecError> {
        Ok(tagged_hash(STATEMENT_TAG, &self.encode()?))
    }

    pub fn asp_key(&self) -> Result<PlainPublicKey> {
        Ok(PlainPublicKey::from_slice(&self.policy.asp)?)
    }

    pub fn asp_xonly(&self) -> Result<XOnlyPublicKey> {
        Ok(XOnlyPublicKey::from_slice(&self.asp_key()?.xonly())?)
    }

    pub fn owner_keys(&self, lo: u16, hi: u16) -> Result<Vec<(SignerId, PlainPublicKey)>> {
        let mut keys = Vec::new();
        for index in lo..hi {
            let participant = self
                .participants
                .get(usize::from(index))
                .ok_or_else(|| Error::Construction("tree range exceeds participants".to_owned()))?;
            keys.push((
                SignerId::User(index),
                PlainPublicKey::from_slice(&participant.owner)?,
            ));
        }
        Ok(keys)
    }

    pub fn cosigner_tree(&self, lo: u16, hi: u16) -> Result<AggTree> {
        AggTree::build(
            self.policy.shape,
            &self.owner_keys(lo, hi)?,
            self.asp_key()?,
        )
    }

    pub fn node_script(&self, lo: u16, hi: u16) -> Result<NodeScript> {
        Ok(NodeScript {
            cosigners: self.cosigner_tree(lo, hi)?.root_context()?,
            asp: self.asp_xonly()?,
            expiry: self.policy.batch_expiry,
        })
    }

    pub fn vtxo_script(&self, participant: usize) -> Result<VtxoScript> {
        let owner = self
            .participants
            .get(participant)
            .ok_or_else(|| Error::Construction("participant index out of range".to_owned()))?;
        Ok(VtxoScript {
            owner: XOnlyPublicKey::from_slice(&PlainPublicKey::from_slice(&owner.owner)?.xonly())?,
            asp: self.asp_xonly()?,
            exit_delay: self.policy.exit_delay,
        })
    }

    pub fn boarding_script(&self, owner: &[u8; 33]) -> Result<VtxoScript> {
        Ok(VtxoScript {
            owner: XOnlyPublicKey::from_slice(&PlainPublicKey::from_slice(owner)?.xonly())?,
            asp: self.asp_xonly()?,
            exit_delay: self.policy.boarding_delay,
        })
    }

    pub fn owner_vtxo_script(&self, owner: &[u8; 33]) -> Result<VtxoScript> {
        Ok(VtxoScript {
            owner: XOnlyPublicKey::from_slice(&PlainPublicKey::from_slice(owner)?.xonly())?,
            asp: self.asp_xonly()?,
            exit_delay: self.policy.exit_delay,
        })
    }

    /// The expected script of the output covering participants `lo..hi`: a VTXO
    /// for a single participant, otherwise a cosigner node.
    pub fn range_script(&self, lo: u16, hi: u16) -> Result<ScriptBuf> {
        if hi.checked_sub(lo) == Some(1) {
            self.vtxo_script(usize::from(lo))?.script_pubkey()
        } else {
            self.node_script(lo, hi)?.script_pubkey()
        }
    }

    pub fn commitment_prevouts(&self) -> Vec<TxOut> {
        self.funding
            .iter()
            .map(|funding| TxOut {
                value: bitcoin::Amount::from_sat(funding.amount_sat),
                script_pubkey: funding.script_pubkey.clone(),
            })
            .collect()
    }

    pub fn tree_prevout(&self, index: usize) -> Result<TxOut> {
        let node = self
            .tree
            .get(index)
            .ok_or_else(|| Error::Construction("tree index out of range".to_owned()))?;
        let parent = match node.parent {
            None => &self.commitment,
            Some(parent) => {
                &self
                    .tree
                    .get(usize::from(parent))
                    .ok_or_else(|| Error::Construction("tree parent out of range".to_owned()))?
                    .tx
            }
        };
        parent
            .output
            .get(usize::try_from(node.parent_vout).map_err(|_| Error::Range("parent vout"))?)
            .cloned()
            .ok_or_else(|| Error::Construction("tree parent output absent".to_owned()))
    }

    pub fn forfeit_prevouts(&self, index: usize) -> Result<Vec<TxOut>> {
        let forfeit = self
            .forfeits
            .get(index)
            .ok_or_else(|| Error::Construction("forfeit index out of range".to_owned()))?;
        let old = self
            .old_vtxos
            .get(usize::from(forfeit.old))
            .ok_or_else(|| Error::Construction("forfeit old VTXO out of range".to_owned()))?;
        let connector_vout = self
            .connectors
            .get(usize::from(forfeit.connector))
            .ok_or_else(|| Error::Construction("forfeit connector out of range".to_owned()))?;
        let connector = self
            .commitment
            .output
            .get(usize::try_from(*connector_vout).map_err(|_| Error::Range("connector vout"))?)
            .cloned()
            .ok_or_else(|| Error::Construction("connector output absent".to_owned()))?;
        Ok(vec![
            connector,
            TxOut {
                value: bitcoin::Amount::from_sat(old.amount_sat),
                script_pubkey: old.script_pubkey.clone(),
            },
        ])
    }

    /// Outpoints of every VTXO this round creates, in participant order.
    pub fn vtxo_outpoints(&self) -> Result<Vec<OutPoint>> {
        let mut outpoints = vec![None; self.participants.len()];
        for node in &self.tree {
            let mid = split_point(node.lo, node.hi);
            let txid = node.tx.compute_txid();
            for (vout, (lo, hi)) in [(node.lo, mid), (mid, node.hi)].into_iter().enumerate() {
                if hi.checked_sub(lo) == Some(1) {
                    let slot = outpoints
                        .get_mut(usize::from(lo))
                        .ok_or_else(|| Error::Construction("VTXO index out of range".to_owned()))?;
                    *slot = Some(OutPoint::new(txid, crate::to_u32(vout, "vtxo vout")?));
                }
            }
        }
        outpoints
            .into_iter()
            .map(|outpoint| {
                outpoint
                    .ok_or_else(|| Error::Construction("participant has no VTXO leaf".to_owned()))
            })
            .collect()
    }

    /// Indices of tree transactions on the path from the batch output to a participant's VTXO, root first.
    pub fn branch(&self, participant: u16) -> Vec<usize> {
        let mut path: Vec<usize> = self
            .tree
            .iter()
            .enumerate()
            .filter(|(_, node)| node.lo <= participant && participant < node.hi)
            .map(|(index, _)| index)
            .collect();
        path.sort_by_key(|index| {
            let node = &self.tree[*index];
            std::cmp::Reverse(node.hi - node.lo)
        });
        path
    }
}

pub fn split_point(lo: u16, hi: u16) -> u16 {
    lo + (hi - lo).div_ceil(2)
}

fn key33(bytes: [u8; 33]) -> std::result::Result<[u8; 33], CodecError> {
    PlainPublicKey::from_slice(&bytes).map_err(|_| CodecError::Key)?;
    Ok(bytes)
}

pub fn tagged_hash(tag: &[u8], data: &[u8]) -> [u8; 32] {
    let tag_hash = sha256::Hash::hash(tag);
    let mut engine = sha256::Hash::engine();
    engine.input(tag_hash.as_byte_array());
    engine.input(tag_hash.as_byte_array());
    engine.input(data);
    sha256::Hash::from_engine(engine).to_byte_array()
}

pub fn strip_witness(tx: &Transaction) -> Transaction {
    let mut template = tx.clone();
    for input in &mut template.input {
        input.witness = bitcoin::Witness::new();
    }
    template
}
