use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use bitcoin::{OutPoint, ScriptBuf, Transaction};
use bitcoin_rs_nested_musig2::{
    self as nested, PartialSignature, PlainPublicKey, PublicNonce, SecretNonce, SessionContext,
    Tweak,
};

use crate::keys::Participant;
use crate::native;
use crate::policy::SignerId;
use crate::signing::{
    Cosigner, NonceRequest, PartialRequest, SchnorrRequest, SignTarget, sighash, spend_target,
};
use crate::statement::{ArkTransitionV1, FundingKind, check_statement, strip_witness};
use crate::{Error, Result};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rejection {
    pub stage: String,
    pub detail: String,
}

impl fmt::Display for Rejection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.stage, self.detail)
    }
}

pub fn reject(stage: &str, detail: impl Into<String>) -> Error {
    Error::Rejected(Rejection {
        stage: stage.to_owned(),
        detail: detail.into(),
    })
}

/// A UTXO as reported by a node's `gettxout`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Observed {
    pub outpoint: OutPoint,
    pub amount_sat: u64,
    pub script_pubkey: ScriptBuf,
    pub confirmations: u32,
}

/// What a participant agreed to before seeing the round: the VTXO amounts it
/// receives, the boarding outputs and old VTXOs it gives up, and the on-chain
/// payouts it expects.
#[derive(Clone, Debug, Default)]
pub struct Intent {
    pub receive: Vec<u64>,
    pub boarding: Vec<(OutPoint, u64)>,
    pub forfeit: Vec<(OutPoint, u64)>,
    pub coop_exit: Vec<(ScriptBuf, u64)>,
    pub observed: Vec<Observed>,
}

/// Funding outputs must match a confirmed UTXO exactly in script and value
/// before any signature is produced. This is the check whose absence caused
/// the historical Ark boarding failure.
pub fn verify_funding_observed(
    statement: &ArkTransitionV1,
    observed: &[Observed],
    only_owner: Option<&[u8; 33]>,
) -> Result<()> {
    for funding in &statement.funding {
        if let (Some(owner), FundingKind::Boarding { owner: funded }) = (only_owner, &funding.kind)
        {
            if owner != funded {
                continue;
            }
        }
        if only_owner.is_some() && matches!(funding.kind, FundingKind::Liquidity) {
            continue;
        }
        let seen = observed
            .iter()
            .find(|utxo| utxo.outpoint == funding.outpoint)
            .ok_or_else(|| reject("funding-observed-absent", funding.outpoint.to_string()))?;
        if seen.script_pubkey != funding.script_pubkey {
            return Err(reject(
                "funding-observed-script",
                funding.outpoint.to_string(),
            ));
        }
        if seen.amount_sat != funding.amount_sat {
            return Err(reject(
                "funding-observed-value",
                format!(
                    "{} observed {} claimed {}",
                    funding.outpoint, seen.amount_sat, funding.amount_sat
                ),
            ));
        }
        if seen.confirmations < 1 {
            return Err(reject(
                "funding-observed-unconfirmed",
                funding.outpoint.to_string(),
            ));
        }
    }
    Ok(())
}

struct Pending {
    nonce: SecretNonce,
    statement: [u8; 32],
    target: SignTarget,
    message: [u8; 32],
}

struct Validated {
    statement: ArkTransitionV1,
    allowed: BTreeSet<SignTarget>,
    branches: BTreeSet<u16>,
    tree_accepted: bool,
}

/// One signing role. Users validate the whole round against their intent;
/// the operator role validates structure and on-chain funding. Secret nonces
/// live only in memory, are consumed by the first partial-signature request,
/// and session identifiers are never reused.
pub struct RoleSigner {
    role: SignerId,
    key: Participant,
    public: PlainPublicKey,
    rounds: BTreeMap<[u8; 32], Validated>,
    pending: BTreeMap<String, Pending>,
    used: BTreeSet<String>,
}

impl RoleSigner {
    pub fn new(role: SignerId, key: Participant) -> Result<Self> {
        let public = key.plain()?;
        Ok(Self {
            role,
            key,
            public,
            rounds: BTreeMap::new(),
            pending: BTreeMap::new(),
            used: BTreeSet::new(),
        })
    }

    fn validated(&self, digest: &[u8; 32]) -> Result<&Validated> {
        self.rounds
            .get(digest)
            .ok_or_else(|| reject("client-unknown-statement", "statement was not validated"))
    }

    fn expected_aggregate(
        statement: &ArkTransitionV1,
        target: SignTarget,
    ) -> Result<([u8; 32], [u8; 32])> {
        let SignTarget::Tree(index) = target else {
            return Err(reject(
                "client-target-kind",
                "MuSig2 requested for a single-key target",
            ));
        };
        let node = statement
            .tree
            .get(usize::from(index))
            .ok_or_else(|| reject("client-unknown-target", target.label()))?;
        let script = statement.node_script(node.lo, node.hi)?;
        Ok((script.output_key()?, script.tweak_bytes()?))
    }
}

impl Cosigner for RoleSigner {
    fn public_key(&self) -> PlainPublicKey {
        self.public
    }

    fn load(&mut self, statement: &ArkTransitionV1, intent: &Intent) -> Result<[u8; 32]> {
        let report = check_statement(statement, &[])?;
        if !report.accepted {
            let failed = report
                .findings
                .iter()
                .find(|finding| !finding.ok)
                .map(|finding| format!("{}: {}", finding.rule, finding.detail))
                .unwrap_or_default();
            return Err(reject("client-statement-rules", failed));
        }
        let digest = statement.digest()?;
        let me = self.public.serialize();
        let mut allowed = BTreeSet::new();
        let mut branches = BTreeSet::new();
        match self.role {
            SignerId::Asp => {
                verify_funding_observed(statement, &intent.observed, None)?;
                for index in 0..statement.tree.len() {
                    allowed.insert(SignTarget::Tree(crate::to_u16(index, "tree")?));
                }
                for (index, funding) in statement.funding.iter().enumerate() {
                    let index = crate::to_u16(index, "funding")?;
                    allowed.insert(match funding.kind {
                        FundingKind::Boarding { .. } => SignTarget::Boarding(index),
                        FundingKind::Liquidity => SignTarget::Liquidity(index),
                    });
                }
                for index in 0..statement.forfeits.len() {
                    let index = crate::to_u16(index, "forfeit")?;
                    allowed.insert(SignTarget::Forfeit(index));
                    allowed.insert(SignTarget::Connector(index));
                }
            }
            SignerId::User(_) => {
                verify_funding_observed(statement, &intent.observed, Some(&me))?;
                let mut received: Vec<u64> = statement
                    .participants
                    .iter()
                    .filter(|participant| participant.owner == me)
                    .map(|participant| participant.amount_sat)
                    .collect();
                let mut expected = intent.receive.clone();
                received.sort_unstable();
                expected.sort_unstable();
                if received.len() < expected.len() {
                    return Err(reject(
                        "client-vtxo-missing",
                        format!("{} of {} VTXOs", received.len(), expected.len()),
                    ));
                }
                if received != expected {
                    return Err(reject(
                        "client-vtxo-amount",
                        format!("{received:?} != {expected:?}"),
                    ));
                }
                let boarding: BTreeSet<(OutPoint, u64)> = statement
                    .funding
                    .iter()
                    .filter(|funding| funding.kind == FundingKind::Boarding { owner: me })
                    .map(|funding| (funding.outpoint, funding.amount_sat))
                    .collect();
                if boarding != intent.boarding.iter().copied().collect() {
                    return Err(reject(
                        "client-boarding-mismatch",
                        format!("{} boarding inputs", boarding.len()),
                    ));
                }
                let forfeits: BTreeSet<(OutPoint, u64)> = statement
                    .old_vtxos
                    .iter()
                    .filter(|old| old.owner == me)
                    .map(|old| (old.outpoint, old.amount_sat))
                    .collect();
                if forfeits != intent.forfeit.iter().copied().collect() {
                    return Err(reject(
                        "client-forfeit-mismatch",
                        format!("{} forfeits", forfeits.len()),
                    ));
                }
                let exits: BTreeSet<(ScriptBuf, u64)> = statement
                    .coop_exits
                    .iter()
                    .filter(|exit| exit.owner == me)
                    .map(|exit| (exit.script_pubkey.clone(), exit.amount_sat))
                    .collect();
                if exits != intent.coop_exit.iter().cloned().collect() {
                    return Err(reject(
                        "client-coop-exit",
                        format!("{} cooperative exits", exits.len()),
                    ));
                }
                for (position, participant) in statement.participants.iter().enumerate() {
                    if participant.owner == me {
                        let position = crate::to_u16(position, "participant")?;
                        branches.insert(position);
                        for index in statement.branch(position) {
                            allowed.insert(SignTarget::Tree(crate::to_u16(index, "tree")?));
                        }
                    }
                }
                for (index, funding) in statement.funding.iter().enumerate() {
                    if funding.kind == (FundingKind::Boarding { owner: me }) {
                        allowed.insert(SignTarget::Boarding(crate::to_u16(index, "funding")?));
                    }
                }
                for (index, forfeit) in statement.forfeits.iter().enumerate() {
                    if statement
                        .old_vtxos
                        .get(usize::from(forfeit.old))
                        .is_some_and(|old| old.owner == me)
                    {
                        allowed.insert(SignTarget::Forfeit(crate::to_u16(index, "forfeit")?));
                    }
                }
            }
        }
        self.rounds.insert(
            digest,
            Validated {
                statement: statement.clone(),
                allowed,
                branches,
                tree_accepted: false,
            },
        );
        Ok(digest)
    }

    fn nonce(&mut self, request: &NonceRequest) -> Result<PublicNonce> {
        if self.used.contains(&request.session) || self.pending.contains_key(&request.session) {
            return Err(reject("client-session-reuse", request.session.clone()));
        }
        let round = self.validated(&request.statement)?;
        if !round.allowed.contains(&request.target) {
            return Err(reject("client-unknown-target", request.target.label()));
        }
        let (aggregate, _) = Self::expected_aggregate(&round.statement, request.target)?;
        if aggregate != request.aggregate_key {
            return Err(reject("client-aggregate-key", request.target.label()));
        }
        let message = sighash(&spend_target(&round.statement, request.target)?)?;
        let (nonce, public) = nested::nonce_gen(
            Some(self.key.secret()),
            self.public,
            Some(aggregate),
            Some(&message),
            Some(request.session.as_bytes()),
        )?;
        self.pending.insert(
            request.session.clone(),
            Pending {
                nonce,
                statement: request.statement,
                target: request.target,
                message,
            },
        );
        Ok(public)
    }

    fn partial(&mut self, request: &PartialRequest) -> Result<PartialSignature> {
        let pending = self
            .pending
            .remove(&request.session)
            .ok_or_else(|| reject("client-nonce-unavailable", request.session.clone()))?;
        self.used.insert(request.session.clone());
        if pending.statement != request.statement || pending.target != request.target {
            return Err(reject("client-session-binding", request.session.clone()));
        }
        let round = self.validated(&request.statement)?;
        let (_, tweak) = Self::expected_aggregate(&round.statement, request.target)?;
        if tweak != request.tweak {
            return Err(reject("client-tweak", request.target.label()));
        }
        let context = SessionContext {
            nonce_path: request.nonce_path.clone(),
            key_path: request.key_path.clone(),
            tweaks: vec![Tweak::new(tweak, true)?],
            message: pending.message.to_vec(),
        };
        nested::sign(pending.nonce, self.key.secret(), &context)
            .map_err(|error| reject("client-sign", error.to_string()))
    }

    fn accept_tree(&mut self, statement: [u8; 32], signed: &[Transaction]) -> Result<()> {
        let round = self
            .rounds
            .get_mut(&statement)
            .ok_or_else(|| reject("client-unknown-statement", "statement was not validated"))?;
        let mut needed = BTreeSet::new();
        for position in &round.branches {
            for index in round.statement.branch(*position) {
                needed.insert(index);
            }
        }
        if self.role == SignerId::Asp {
            needed.extend(0..round.statement.tree.len());
        }
        for index in needed {
            let template = &round.statement.tree[index].tx;
            let tx = signed
                .iter()
                .find(|tx| strip_witness(tx) == *template)
                .ok_or_else(|| {
                    reject("client-tree-unsigned", format!("tree transaction {index}"))
                })?;
            native::verify_all_inputs(tx, &[round.statement.tree_prevout(index)?]).map_err(
                |error| {
                    reject(
                        "client-tree-invalid",
                        format!("tree transaction {index}: {error}"),
                    )
                },
            )?;
        }
        round.tree_accepted = true;
        Ok(())
    }

    fn schnorr(&mut self, request: &SchnorrRequest) -> Result<[u8; 64]> {
        let round = self.validated(&request.statement)?;
        if !round.allowed.contains(&request.target) {
            return Err(reject("client-unknown-target", request.target.label()));
        }
        if matches!(request.target, SignTarget::Tree(_)) {
            return Err(reject("client-target-kind", "tree inputs need MuSig2"));
        }
        if !round.tree_accepted {
            return Err(reject(
                "client-tree-unsigned",
                "the signed exit tree must be held before boarding or forfeit signatures",
            ));
        }
        let target = spend_target(&round.statement, request.target)?;
        let digest = sighash(&target)?;
        match target.leaf {
            Some(_) => self.key.sign_script_path(digest),
            None => self.key.sign_key_path(digest),
        }
    }

    fn abort(&mut self, session: &str) -> Result<()> {
        if self.pending.remove(session).is_some() {
            self.used.insert(session.to_owned());
        }
        Ok(())
    }
}
