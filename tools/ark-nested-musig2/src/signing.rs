use std::collections::BTreeMap;
use std::time::Instant;

use bitcoin::hashes::Hash as _;
use bitcoin::hex::DisplayHex as _;
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::{Transaction, TxOut};
use bitcoin_rs_nested_musig2::{
    self as nested, AggregateNonce, PartialSignature, PlainPublicKey, PublicNonce,
    RootSessionContext, SessionContext, Tweak,
};

use crate::client::Intent;
use crate::policy::{AggTree, SignerId};
use crate::scripts::leaf_hash;
use crate::statement::{ArkTransitionV1, FundingKind};
use crate::traffic::Traffic;
use crate::{Error, Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SignTarget {
    Tree(u16),
    Boarding(u16),
    Liquidity(u16),
    Forfeit(u16),
    Connector(u16),
}

impl SignTarget {
    pub fn label(self) -> String {
        match self {
            Self::Tree(index) => format!("t{index}"),
            Self::Boarding(index) => format!("b{index}"),
            Self::Liquidity(index) => format!("l{index}"),
            Self::Forfeit(index) => format!("f{index}"),
            Self::Connector(index) => format!("c{index}"),
        }
    }

    pub fn parse(label: &str) -> Option<Self> {
        let (kind, index) = label.split_at_checked(1)?;
        let index: u16 = index.parse().ok()?;
        match kind {
            "t" => Some(Self::Tree(index)),
            "b" => Some(Self::Boarding(index)),
            "l" => Some(Self::Liquidity(index)),
            "f" => Some(Self::Forfeit(index)),
            "c" => Some(Self::Connector(index)),
            _ => None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct NonceRequest {
    pub session: String,
    pub statement: [u8; 32],
    pub target: SignTarget,
    pub aggregate_key: [u8; 32],
}

#[derive(Clone, Debug)]
pub struct PartialRequest {
    pub session: String,
    pub statement: [u8; 32],
    pub target: SignTarget,
    pub nonce_path: Vec<AggregateNonce>,
    pub key_path: Vec<Vec<PlainPublicKey>>,
    pub tweak: [u8; 32],
}

#[derive(Clone, Debug)]
pub struct SchnorrRequest {
    pub statement: [u8; 32],
    pub target: SignTarget,
}

pub trait Cosigner {
    fn public_key(&self) -> PlainPublicKey;
    fn load(&mut self, statement: &ArkTransitionV1, intent: &Intent) -> Result<[u8; 32]>;
    fn nonce(&mut self, request: &NonceRequest) -> Result<PublicNonce>;
    fn partial(&mut self, request: &PartialRequest) -> Result<PartialSignature>;
    fn accept_tree(&mut self, statement: [u8; 32], signed: &[Transaction]) -> Result<()>;
    fn schnorr(&mut self, request: &SchnorrRequest) -> Result<[u8; 64]>;
    fn abort(&mut self, session: &str) -> Result<()>;
}

pub type Cosigners = BTreeMap<SignerId, Box<dyn Cosigner>>;

/// What one target signs: the transaction, its prevouts, the input, and the
/// tapscript leaf for script-path spends.
pub struct SpendTarget {
    pub tx: Transaction,
    pub prevouts: Vec<TxOut>,
    pub input: usize,
    pub leaf: Option<bitcoin::ScriptBuf>,
}

pub fn spend_target(statement: &ArkTransitionV1, target: SignTarget) -> Result<SpendTarget> {
    match target {
        SignTarget::Tree(index) => {
            let index = usize::from(index);
            let node = statement
                .tree
                .get(index)
                .ok_or_else(|| Error::Construction("tree target out of range".to_owned()))?;
            Ok(SpendTarget {
                tx: node.tx.clone(),
                prevouts: vec![statement.tree_prevout(index)?],
                input: 0,
                leaf: None,
            })
        }
        SignTarget::Boarding(index) | SignTarget::Liquidity(index) => {
            let input = usize::from(index);
            let funding = statement
                .funding
                .get(input)
                .ok_or_else(|| Error::Construction("funding target out of range".to_owned()))?;
            let leaf = match (&funding.kind, target) {
                (FundingKind::Boarding { owner }, SignTarget::Boarding(_)) => {
                    Some(statement.boarding_script(owner)?.cooperative_leaf())
                }
                (FundingKind::Liquidity, SignTarget::Liquidity(_)) => None,
                _ => {
                    return Err(Error::Construction(
                        "funding kind differs from target".to_owned(),
                    ));
                }
            };
            Ok(SpendTarget {
                tx: statement.commitment.clone(),
                prevouts: statement.commitment_prevouts(),
                input,
                leaf,
            })
        }
        SignTarget::Forfeit(index) | SignTarget::Connector(index) => {
            let position = usize::from(index);
            let forfeit = statement
                .forfeits
                .get(position)
                .ok_or_else(|| Error::Construction("forfeit target out of range".to_owned()))?;
            let old = statement
                .old_vtxos
                .get(usize::from(forfeit.old))
                .ok_or_else(|| Error::Construction("forfeit old VTXO out of range".to_owned()))?;
            let (input, leaf) = match target {
                SignTarget::Forfeit(_) => (
                    1,
                    Some(statement.owner_vtxo_script(&old.owner)?.cooperative_leaf()),
                ),
                _ => (0, None),
            };
            Ok(SpendTarget {
                tx: forfeit.tx.clone(),
                prevouts: statement.forfeit_prevouts(position)?,
                input,
                leaf,
            })
        }
    }
}

pub fn sighash(target: &SpendTarget) -> Result<[u8; 32]> {
    let mut cache = SighashCache::new(&target.tx);
    let prevouts = Prevouts::All(&target.prevouts);
    let digest = match &target.leaf {
        None => cache.taproot_key_spend_signature_hash(
            target.input,
            &prevouts,
            TapSighashType::Default,
        )?,
        Some(leaf) => cache.taproot_script_spend_signature_hash(
            target.input,
            &prevouts,
            leaf_hash(leaf),
            TapSighashType::Default,
        )?,
    };
    Ok(digest.to_byte_array())
}

pub struct TreeSignature {
    pub signature: [u8; 64],
    pub traffic: Traffic,
}

#[derive(Clone, Copy, Debug)]
pub enum Fault {
    None,
    SubstitutePartial,
    SubstituteAggregateNonce,
    ReplayNonce,
}

/// Runs one NestedMuSig2 session for a tree transaction's key-path input.
/// Every leaf occurrence draws a fresh nonce bound to the tweaked aggregate
/// key and the sighash; a failed session aborts every outstanding nonce.
pub fn sign_tree_tx(
    statement: &ArkTransitionV1,
    digest: [u8; 32],
    index: u16,
    cosigners: &mut Cosigners,
    owners: &BTreeMap<[u8; 33], SignerId>,
    attempt: u32,
    fault: Fault,
) -> Result<TreeSignature> {
    let started = Instant::now();
    let node = statement
        .tree
        .get(usize::from(index))
        .ok_or_else(|| Error::Construction("tree index out of range".to_owned()))?;
    let mut tree = statement.cosigner_tree(node.lo, node.hi)?;
    for entry in &mut tree.nodes {
        if let Some(SignerId::User(_)) = entry.signer {
            entry.signer =
                Some(
                    *owners
                        .get(&entry.key.serialize())
                        .ok_or_else(|| Error::Signing {
                            stage: "coordinator-topology",
                            detail: "tree leaf owner has no signer".to_owned(),
                        })?,
                );
        }
    }
    let script = statement.node_script(node.lo, node.hi)?;
    let output_key = script.output_key()?;
    let tweak_bytes = script.tweak_bytes()?;
    let tweak = Tweak::new(tweak_bytes, true)?;
    let target = SignTarget::Tree(index);
    let message = sighash(&spend_target(statement, target)?)?;
    let prefix = digest[..6].to_lower_hex_string();
    let leaves = tree.leaves();
    let sessions: BTreeMap<usize, String> = leaves
        .iter()
        .map(|leaf| {
            (
                *leaf,
                format!("{prefix}:{}:n{leaf}:a{attempt}", target.label()),
            )
        })
        .collect();
    let result = run_session(
        statement,
        digest,
        &tree,
        cosigners,
        &sessions,
        target,
        message,
        output_key,
        tweak,
        tweak_bytes,
        fault,
    );
    if result.is_err() {
        for leaf in &leaves {
            if let (Some(signer), Some(session)) = (tree.nodes[*leaf].signer, sessions.get(leaf)) {
                if let Some(cosigner) = cosigners.get_mut(&signer) {
                    let _ = cosigner.abort(session);
                }
            }
        }
    }
    let signature = result?;
    let mut traffic = Traffic::default();
    traffic.record_session(&tree, started.elapsed().as_secs_f64());
    Ok(TreeSignature { signature, traffic })
}

#[allow(clippy::too_many_arguments)]
fn run_session(
    statement: &ArkTransitionV1,
    digest: [u8; 32],
    tree: &AggTree,
    cosigners: &mut Cosigners,
    sessions: &BTreeMap<usize, String>,
    target: SignTarget,
    message: [u8; 32],
    output_key: [u8; 32],
    tweak: Tweak,
    tweak_bytes: [u8; 32],
    fault: Fault,
) -> Result<[u8; 64]> {
    let _ = statement;
    let mut public_nonces: BTreeMap<usize, PublicNonce> = BTreeMap::new();
    for (leaf, session) in sessions {
        let signer = tree.nodes[*leaf].signer.ok_or(Error::Signing {
            stage: "coordinator-topology",
            detail: "leaf without signer".to_owned(),
        })?;
        let cosigner = cosigners.get_mut(&signer).ok_or_else(|| Error::Signing {
            stage: "coordinator-topology",
            detail: format!("{} is not connected", signer.label()),
        })?;
        let nonce = cosigner.nonce(&NonceRequest {
            session: session.clone(),
            statement: digest,
            target,
            aggregate_key: output_key,
        })?;
        public_nonces.insert(*leaf, nonce);
    }
    let mut aggregate: BTreeMap<usize, AggregateNonce> = BTreeMap::new();
    let mut contribution: BTreeMap<usize, PublicNonce> = public_nonces.clone();
    for group in tree.groups_post_order() {
        let children: Vec<PublicNonce> = tree.nodes[group]
            .children
            .iter()
            .map(|child| contribution.get(child).copied())
            .collect::<Option<_>>()
            .ok_or(Error::Signing {
                stage: "nonce-aggregation",
                detail: "missing child nonce".to_owned(),
            })?;
        let combined = nested::nonce_agg(&children)?;
        aggregate.insert(group, combined);
        if tree.nodes[group].parent.is_some() {
            contribution.insert(
                group,
                nested::nonce_agg_ext(combined, tree.nodes[group].key)?,
            );
        }
    }
    let mut partials: BTreeMap<usize, PartialSignature> = BTreeMap::new();
    for (position, (leaf, session)) in sessions.iter().enumerate() {
        let edges = tree.path_edges(*leaf);
        let mut nonce_path: Vec<AggregateNonce> = edges
            .iter()
            .map(|(ancestor, _)| aggregate.get(ancestor).copied())
            .collect::<Option<_>>()
            .ok_or(Error::Signing {
                stage: "nonce-aggregation",
                detail: "missing ancestor nonce".to_owned(),
            })?;
        let key_path: Vec<Vec<PlainPublicKey>> = edges
            .iter()
            .map(|(ancestor, child)| tree.sibling_keys(*ancestor, *child))
            .collect();
        if matches!(fault, Fault::SubstituteAggregateNonce) && position == 0 {
            let decoy = nested::nonce_agg(&[public_nonces.values().next().copied().ok_or(
                Error::Signing {
                    stage: "nonce-aggregation",
                    detail: "no nonces".to_owned(),
                },
            )?])?;
            nonce_path[0] = decoy;
        }
        let signer = tree.nodes[*leaf].signer.ok_or(Error::Signing {
            stage: "coordinator-topology",
            detail: "leaf without signer".to_owned(),
        })?;
        let cosigner = cosigners.get_mut(&signer).ok_or_else(|| Error::Signing {
            stage: "coordinator-topology",
            detail: format!("{} is not connected", signer.label()),
        })?;
        let request = PartialRequest {
            session: session.clone(),
            statement: digest,
            target,
            nonce_path: nonce_path.clone(),
            key_path: key_path.clone(),
            tweak: tweak_bytes,
        };
        let mut partial = cosigner.partial(&request)?;
        if matches!(fault, Fault::ReplayNonce) && position == 0 {
            partial = cosigner.partial(&request)?;
        }
        if matches!(fault, Fault::SubstitutePartial) && position == 0 {
            partial = PartialSignature::from_slice(&[7_u8; 32])?;
        }
        let honest_context = SessionContext {
            nonce_path: edges
                .iter()
                .map(|(ancestor, _)| aggregate.get(ancestor).copied())
                .collect::<Option<_>>()
                .ok_or(Error::Signing {
                    stage: "nonce-aggregation",
                    detail: "missing ancestor nonce".to_owned(),
                })?,
            key_path,
            tweaks: vec![tweak],
            message: message.to_vec(),
        };
        let nonce = public_nonces.get(leaf).copied().ok_or(Error::Signing {
            stage: "nonce-aggregation",
            detail: "missing leaf nonce".to_owned(),
        })?;
        if !nested::partial_sig_verify(partial, nonce, tree.nodes[*leaf].key, &honest_context)? {
            return Err(Error::Signing {
                stage: "partial-verify",
                detail: format!("{} produced an invalid partial signature", signer.label()),
            });
        }
        partials.insert(*leaf, partial);
    }
    let mut signature = None;
    for group in tree.groups_post_order() {
        let children: Vec<PartialSignature> = tree.nodes[group]
            .children
            .iter()
            .map(|child| partials.get(child).copied())
            .collect::<Option<_>>()
            .ok_or(Error::Signing {
                stage: "partial-aggregation",
                detail: "missing child partial".to_owned(),
            })?;
        if tree.nodes[group].parent.is_some() {
            partials.insert(group, nested::aggregate_intermediate(&children)?);
        } else {
            let root_nonce = aggregate.get(&group).copied().ok_or(Error::Signing {
                stage: "partial-aggregation",
                detail: "missing root nonce".to_owned(),
            })?;
            signature = Some(
                nested::aggregate_root(
                    &children,
                    &RootSessionContext {
                        aggregate_nonce: root_nonce,
                        pubkeys: tree.child_keys(group),
                        tweaks: vec![tweak],
                        message: message.to_vec(),
                    },
                )
                .map_err(|error| Error::Signing {
                    stage: "aggregate-verify",
                    detail: error.to_string(),
                })?,
            );
        }
    }
    let signature = signature.ok_or(Error::Signing {
        stage: "partial-aggregation",
        detail: "tree has no root".to_owned(),
    })?;
    if !nested::schnorr_verify(&message, output_key, &signature) {
        return Err(Error::Signing {
            stage: "aggregate-verify",
            detail: "signature does not verify for the BIP341 output key".to_owned(),
        });
    }
    Ok(signature)
}
