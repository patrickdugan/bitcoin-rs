use std::path::Path;

use bitcoin_rs_ark_nested_musig2::keys::{KeyNetwork, Participant};
use bitcoin_rs_ark_nested_musig2::policy::{Shape, SignerId};
use bitcoin_rs_ark_nested_musig2::remote::ProcessCosigner;
use bitcoin_rs_ark_nested_musig2::round::sign_round;
use bitcoin_rs_ark_nested_musig2::signing::{Cosigner, NonceRequest, PartialRequest, SignTarget};

use super::support::{SEED, TestError, rejection_stage, round};

fn binary() -> &'static Path {
    Path::new(env!("CARGO_BIN_EXE_ark-nm2"))
}

// Two users sign from separate operating-system processes; one process is
// killed after releasing a nonce and the restarted process has no nonce to sign with.
#[test]
fn two_process_signers_survive_a_crash_with_fresh_nonces() -> Result<(), TestError> {
    let directory = tempfile::tempdir()?;
    let mut fixture = round(4, Shape::Nested)?;
    let mut pids = Vec::new();
    for user in [2_u16, 3] {
        let path = directory.path().join(format!("user-{user}.key"));
        Participant::from_seed(&SEED, "user", u32::from(user))?.save(&path, KeyNetwork::Regtest)?;
        let process =
            ProcessCosigner::spawn(binary(), SignerId::User(user), &path, KeyNetwork::Regtest)?;
        pids.push(process.pid);
        fixture
            .cosigners
            .insert(SignerId::User(user), Box::new(process));
    }
    assert_ne!(pids[0], pids[1]);
    assert_ne!(pids[0], std::process::id());
    let signed = sign_round(
        &fixture.statement,
        &mut fixture.cosigners,
        &fixture.intents,
        &fixture.owners,
        0,
    )?;
    assert_eq!(signed.tree.len(), 3);

    let path = directory.path().join("user-3.key");
    let mut process =
        ProcessCosigner::spawn(binary(), SignerId::User(3), &path, KeyNetwork::Regtest)?;
    let intent = fixture
        .intents
        .get(&SignerId::User(3))
        .cloned()
        .unwrap_or_default();
    let digest = process.load(&fixture.statement, &intent)?;
    let node = &fixture.statement.tree[0];
    let script = fixture.statement.node_script(node.lo, node.hi)?;
    process.nonce(&NonceRequest {
        session: "crash-test".to_owned(),
        statement: digest,
        target: SignTarget::Tree(0),
        aggregate_key: script.output_key()?,
    })?;
    let before = process.pid;
    process.crash()?;
    process.restart()?;
    assert_ne!(before, process.pid);
    let after_restart = process.partial(&PartialRequest {
        session: "crash-test".to_owned(),
        statement: digest,
        target: SignTarget::Tree(0),
        nonce_path: Vec::new(),
        key_path: Vec::new(),
        tweak: script.tweak_bytes()?,
    });
    assert_eq!(rejection_stage(after_restart), "client-nonce-unavailable");
    process.shutdown()?;
    Ok(())
}
