use std::io::Read as _;
use std::process::ExitCode;
use std::str::FromStr as _;

use ark_core::{BoardingOutput, Vtxo};
use bitcoin::{Network, ScriptBuf, Sequence, XOnlyPublicKey, key::Secp256k1};
use serde_json::{Value, json};

const ARK_CORE_REV: &str = "c786942969dd16f9e94fc165a99a329a39ed183d";

#[derive(Debug, thiserror::Error)]
enum InteropError {
    #[error("reading standard input failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("request is not valid JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("request field {0} is missing or has the wrong type")]
    Field(&'static str),
    #[error("unknown network {0}")]
    Network(String),
    #[error("x-only key is invalid: {0}")]
    Key(#[from] bitcoin::secp256k1::Error),
    #[error("exit_blocks exceeds 65535")]
    Blocks(#[from] std::num::TryFromIntError),
    #[error("ark-core rejected the case: {0}")]
    ArkCore(#[from] ark_core::Error),
}

fn hexes(scripts: Vec<ScriptBuf>) -> Vec<String> {
    scripts.iter().map(|script| hex::encode(script.as_bytes())).collect()
}

fn run() -> Result<String, InteropError> {
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input)?;
    let request: Value = serde_json::from_str(&input)?;
    let network = match request["network"].as_str().ok_or(InteropError::Field("network"))? {
        "bitcoin" | "mainnet" => Network::Bitcoin,
        "testnet" => Network::Testnet,
        "signet" => Network::Signet,
        "regtest" => Network::Regtest,
        other => return Err(InteropError::Network(other.to_owned())),
    };
    let secp = Secp256k1::verification_only();
    let mut cases = Vec::new();
    for case in request["cases"].as_array().ok_or(InteropError::Field("cases"))? {
        let server = XOnlyPublicKey::from_str(case["server_xonly"].as_str().ok_or(InteropError::Field("server_xonly"))?)?;
        let owner = XOnlyPublicKey::from_str(case["owner_xonly"].as_str().ok_or(InteropError::Field("owner_xonly"))?)?;
        let blocks = u16::try_from(case["exit_blocks"].as_u64().ok_or(InteropError::Field("exit_blocks"))?)?;
        let delay = Sequence::from_height(blocks);
        let vtxo = Vtxo::new_default(&secp, server, owner, delay, network)?;
        let boarding = BoardingOutput::new(&secp, server, owner, delay, network)?;
        cases.push(json!({
            "server_xonly": hex::encode(server.serialize()),
            "owner_xonly": hex::encode(owner.serialize()),
            "exit_blocks": blocks,
            "script_pubkey": hex::encode(vtxo.script_pubkey().as_bytes()),
            "tapscripts": hexes(vtxo.tapscripts()),
            "ark_address": vtxo.to_ark_address().encode(),
            "boarding_script_pubkey": hex::encode(boarding.script_pubkey().as_bytes()),
            "boarding_tapscripts": hexes(boarding.tapscripts()),
            "boarding_address": boarding.address().to_string(),
        }));
    }
    Ok(serde_json::to_string_pretty(&json!({
        "schema": "arkade-interop-v1",
        "ark_core_rev": ARK_CORE_REV,
        "cases": cases,
    }))?)
}

fn main() -> ExitCode {
    match run() {
        Ok(output) => {
            println!("{output}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
