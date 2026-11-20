use std::path::PathBuf;
use std::process::ExitCode;
use std::str::FromStr as _;

use bitcoin::OutPoint;
use bitcoin::hex::DisplayHex as _;
use bitcoin_rs_ark_nested_musig2::keys::{KeyNetwork, Participant};
use bitcoin_rs_ark_nested_musig2::policy::{Shape, SignerId};
use bitcoin_rs_ark_nested_musig2::round::{Params, exit_tx, key_spend, output};
use bitcoin_rs_ark_nested_musig2::scenario::{
    BOARDING_BASE_SAT, FundingRecord, LIQUIDITY_SAT, ObservedRecord, ScenarioInput, bench,
    faucet_file, fund, key_file, run_scale, run_scenario,
};
use bitcoin_rs_ark_nested_musig2::scripts::{VtxoScript, key_path_address, key_path_script};
use bitcoin_rs_ark_nested_musig2::statement::{
    ArkTransitionV1, ProofEnvelope, check_statement, nova_witness, verify_proof_envelope,
};
use bitcoin_rs_ark_nested_musig2::{Error, remote};
use clap::{Parser, Subcommand, ValueEnum};
use serde::Serialize;

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum NetworkArg {
    Regtest,
    Testnet4,
}

impl NetworkArg {
    fn key(self) -> KeyNetwork {
        match self {
            Self::Regtest => KeyNetwork::Regtest,
            Self::Testnet4 => KeyNetwork::Testnet4,
        }
    }
}

#[derive(Parser)]
#[command(about = "Experimental Ark VTXO lifecycle with NestedMuSig2 cooperative signing")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Init {
        #[arg(long)]
        dir: PathBuf,
        #[arg(long)]
        users: u16,
        #[arg(long, value_enum)]
        network: NetworkArg,
    },
    Fund {
        #[arg(long)]
        dir: PathBuf,
        #[arg(long, value_enum)]
        network: NetworkArg,
        #[arg(long)]
        users: u16,
        #[arg(long)]
        rounds: u16,
        #[arg(long)]
        coinbase: String,
        #[arg(long)]
        coinbase_sat: u64,
        #[arg(long, default_value_t = BOARDING_BASE_SAT)]
        boarding_sat: u64,
        #[arg(long, default_value_t = LIQUIDITY_SAT)]
        liquidity_sat: u64,
    },
    Scenario {
        #[arg(long)]
        dir: PathBuf,
        #[arg(long, value_enum)]
        network: NetworkArg,
        #[arg(long)]
        funding: PathBuf,
        #[arg(long, num_args = 2)]
        observed: Vec<PathBuf>,
        #[arg(long, value_delimiter = ',')]
        remote_users: Vec<u16>,
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        scale: Option<u16>,
        #[arg(long, default_value = "nested")]
        shape: String,
    },
    Signer {
        #[arg(long)]
        user: u16,
        #[arg(long)]
        key: PathBuf,
        #[arg(long, value_enum)]
        network: NetworkArg,
    },
    Check {
        #[arg(long)]
        statement: PathBuf,
        #[arg(long)]
        signed: Option<PathBuf>,
    },
    NovaWitness {
        #[arg(long)]
        statement: PathBuf,
    },
    VerifyProof {
        #[arg(long)]
        statement: PathBuf,
        #[arg(long)]
        public: PathBuf,
        #[arg(long)]
        proof: PathBuf,
        #[arg(long)]
        witness: PathBuf,
        #[arg(long)]
        verifier: PathBuf,
        #[arg(long)]
        vk: String,
        #[arg(long, value_enum)]
        network: NetworkArg,
    },
    Bench {
        #[arg(long, value_delimiter = ',')]
        sizes: Vec<usize>,
        #[arg(long, value_delimiter = ',', default_value = "nested,flat")]
        shapes: Vec<String>,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    VtxoScript {
        #[arg(long)]
        server: String,
        #[arg(long)]
        owner: String,
        #[arg(long)]
        exit_blocks: u16,
    },
    NativeVerify {
        #[arg(long)]
        tx: String,
        #[arg(
            long = "prevout",
            help = "VALUE_SAT:SCRIPT_HEX, one per input in order"
        )]
        prevouts: Vec<String>,
    },
    CsvProbe {
        #[arg(long)]
        dir: PathBuf,
        #[arg(long, value_enum)]
        network: NetworkArg,
        #[arg(long)]
        coinbase: String,
        #[arg(long)]
        coinbase_sat: u64,
        #[arg(long, default_value_t = 12)]
        delay: u16,
    },
}

#[derive(Serialize)]
struct NativeVerifyOutput {
    schema: &'static str,
    txid: String,
    mandatory_flags: String,
    standard_flags: String,
}

#[derive(Serialize)]
struct CsvProbeOutput {
    schema: &'static str,
    delay: u16,
    funding_txid: String,
    funding_hex: String,
    spend_txid: String,
    spend_hex: String,
}

#[derive(Serialize)]
struct VtxoScriptOutput {
    schema: &'static str,
    script_pubkey: String,
    tapscripts: Vec<String>,
}

#[derive(Serialize)]
struct InitOutput {
    schema: &'static str,
    network: &'static str,
    faucet_address: String,
    asp_public_key: String,
    users: Vec<String>,
}

fn json(value: &impl Serialize) -> Result<String, Error> {
    Ok(sonic_rs::to_string_pretty(value)?)
}

fn read_statement(path: &PathBuf) -> Result<ArkTransitionV1, Error> {
    Ok(ArkTransitionV1::decode(&std::fs::read(path)?)?)
}

fn run() -> Result<String, Error> {
    match Args::parse().command {
        Command::Init {
            dir,
            users,
            network,
        } => {
            let network = network.key();
            let faucet = Participant::generate()?;
            faucet.save(&faucet_file(&dir), network)?;
            let asp = Participant::generate()?;
            asp.save(&key_file(&dir, SignerId::Asp), network)?;
            let mut keys = Vec::new();
            for user in 0..users {
                let key = Participant::generate()?;
                key.save(&key_file(&dir, SignerId::User(user)), network)?;
                keys.push(key.plain()?.serialize().to_lower_hex_string());
            }
            json(&InitOutput {
                schema: "ark-nm2-init-v1",
                network: network.name(),
                faucet_address: key_path_address(faucet.xonly()?, network.bitcoin()).to_string(),
                asp_public_key: asp.plain()?.serialize().to_lower_hex_string(),
                users: keys,
            })
        }
        Command::Fund {
            dir,
            network,
            users,
            rounds,
            coinbase,
            coinbase_sat,
            boarding_sat,
            liquidity_sat,
        } => {
            let outpoint = OutPoint::from_str(&coinbase)
                .map_err(|_| Error::Construction("coinbase must be txid:vout".to_owned()))?;
            json(&fund(
                &dir,
                network.key(),
                users,
                rounds,
                outpoint,
                coinbase_sat,
                &Params::regtest(Shape::Nested),
                boarding_sat,
                liquidity_sat,
            )?)
        }
        Command::Scenario {
            dir,
            network,
            funding,
            observed,
            remote_users,
            out,
            scale,
            shape,
        } => {
            let funding: FundingRecord = sonic_rs::from_str(&std::fs::read_to_string(funding)?)?;
            let observed: Vec<ObservedRecord> = observed
                .iter()
                .map(|path| Ok(sonic_rs::from_str(&std::fs::read_to_string(path)?)?))
                .collect::<Result<_, Error>>()?;
            let binary = std::env::current_exe()?;
            std::fs::create_dir_all(&out)?;
            let input = ScenarioInput {
                dir: &dir,
                network: network.key(),
                funding: &funding,
                observed: &observed,
                remote_users: &remote_users,
                binary: &binary,
            };
            let output = match scale {
                None => run_scenario(&input, &out)?,
                Some(users) => {
                    let shape = match shape.as_str() {
                        "nested" => Shape::Nested,
                        "flat" => Shape::Flat,
                        _ => {
                            return Err(Error::Construction(
                                "shape must be nested or flat".to_owned(),
                            ));
                        }
                    };
                    run_scale(&input, users, shape, &out)?
                }
            };
            let text = json(&output)?;
            std::fs::write(out.join("scenario.json"), &text)?;
            Ok(format!(
                "{{\"schema\":\"ark-nm2-scenario-summary-v1\",\"transactions\":{},\"plays\":{},\"adversarial\":{}}}",
                output.txs.len(),
                output.plays.len(),
                output.adversarial.len()
            ))
        }
        Command::Signer { user, key, network } => {
            remote::serve(SignerId::User(user), &key, network.key())?;
            Ok(String::new())
        }
        Command::Check { statement, signed } => {
            let statement = read_statement(&statement)?;
            let signed: Vec<bitcoin::Transaction> = match signed {
                None => Vec::new(),
                Some(path) => std::fs::read_to_string(path)?
                    .lines()
                    .filter(|line| !line.trim().is_empty())
                    .map(|line| {
                        bitcoin::consensus::encode::deserialize_hex(line.trim())
                            .map_err(|_| Error::Construction("signed transaction hex".to_owned()))
                    })
                    .collect::<Result<_, Error>>()?,
            };
            json(&check_statement(&statement, &signed)?)
        }
        Command::NovaWitness { statement } => json(&nova_witness(&read_statement(&statement)?)?),
        Command::VerifyProof {
            statement,
            public,
            proof,
            witness,
            verifier,
            vk,
            network,
        } => {
            let statement = read_statement(&statement)?;
            let public_json = std::fs::read_to_string(&public)?;
            json(&verify_proof_envelope(
                &statement,
                &ProofEnvelope {
                    expected_network: network.key(),
                    pinned_vk_digest: &vk,
                    public_json: &public_json,
                    public_path: &public,
                    proof_path: &proof,
                    witness_path: &witness,
                    verifier: &verifier,
                },
            )?)
        }
        Command::NativeVerify { tx, prevouts } => {
            let tx: bitcoin::Transaction = bitcoin::consensus::encode::deserialize_hex(&tx)
                .map_err(|_| Error::Construction("transaction hex".to_owned()))?;
            let prevouts = prevouts
                .iter()
                .map(|entry| {
                    let (value, script) = entry.split_once(':').ok_or_else(|| {
                        Error::Construction("prevout must be VALUE:SCRIPT".to_owned())
                    })?;
                    Ok(output(
                        value
                            .parse()
                            .map_err(|_| Error::Construction("prevout value".to_owned()))?,
                        bitcoin_rs_ark_nested_musig2::scenario::script_hex(script)?,
                    ))
                })
                .collect::<Result<Vec<_>, Error>>()?;
            let verdict = |standard| match bitcoin_rs_ark_nested_musig2::native::verify_with_flags(
                &tx, &prevouts, standard,
            ) {
                Ok(inputs) => format!("accepted {inputs} inputs"),
                Err(error) => error.to_string(),
            };
            json(&NativeVerifyOutput {
                schema: "ark-nm2-native-verify-v1",
                txid: tx.compute_txid().to_string(),
                mandatory_flags: verdict(false),
                standard_flags: verdict(true),
            })
        }
        Command::CsvProbe {
            dir,
            network,
            coinbase,
            coinbase_sat,
            delay,
        } => {
            let network = network.key();
            let faucet = Participant::load(&faucet_file(&dir), network)?;
            let asp = Participant::load(&key_file(&dir, SignerId::Asp), network)?;
            let outpoint = OutPoint::from_str(&coinbase)
                .map_err(|_| Error::Construction("coinbase must be txid:vout".to_owned()))?;
            let script = VtxoScript {
                owner: faucet.xonly()?,
                asp: asp.xonly()?,
                exit_delay: delay,
            };
            let amount = 1_000_000;
            let change = coinbase_sat
                .checked_sub(amount + 2_000)
                .ok_or(Error::Value("probe change"))?;
            let funding = key_spend(
                &faucet,
                &[(outpoint, coinbase_sat)],
                vec![
                    output(amount, script.script_pubkey()?),
                    output(change, key_path_script(faucet.xonly()?)),
                ],
                bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                bitcoin::transaction::Version::TWO,
            )?;
            let spend = exit_tx(
                &script,
                OutPoint::new(funding.compute_txid(), 0),
                amount,
                key_path_script(faucet.xonly()?),
                2_000,
                &faucet,
            )?;
            json(&CsvProbeOutput {
                schema: "ark-nm2-csv-probe-v1",
                delay,
                funding_txid: funding.compute_txid().to_string(),
                funding_hex: bitcoin::consensus::encode::serialize_hex(&funding),
                spend_txid: spend.compute_txid().to_string(),
                spend_hex: bitcoin::consensus::encode::serialize_hex(&spend),
            })
        }
        Command::VtxoScript {
            server,
            owner,
            exit_blocks,
        } => {
            let parse = |text: &str| -> Result<bitcoin::secp256k1::XOnlyPublicKey, Error> {
                Ok(bitcoin::secp256k1::XOnlyPublicKey::from_str(text)?)
            };
            let script = VtxoScript {
                owner: parse(&owner)?,
                asp: parse(&server)?,
                exit_delay: exit_blocks,
            };
            json(&VtxoScriptOutput {
                schema: "ark-nm2-vtxo-script-v1",
                script_pubkey: script.script_pubkey()?.to_hex_string(),
                tapscripts: vec![
                    script.cooperative_leaf().to_hex_string(),
                    script.exit_leaf().to_hex_string(),
                ],
            })
        }
        Command::Bench { sizes, shapes, out } => {
            let seed = [7_u8; 32];
            let mut rows = Vec::new();
            for size in sizes {
                for shape in &shapes {
                    let shape = match shape.as_str() {
                        "nested" => Shape::Nested,
                        "flat" => Shape::Flat,
                        _ => {
                            return Err(Error::Construction(
                                "shape must be nested or flat".to_owned(),
                            ));
                        }
                    };
                    rows.push(bench(size, shape, &seed, out.as_deref())?);
                }
            }
            json(&rows)
        }
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(output) => {
            if !output.is_empty() {
                println!("{output}");
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
