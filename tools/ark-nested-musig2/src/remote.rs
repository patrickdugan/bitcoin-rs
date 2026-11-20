use std::io::{BufRead as _, BufReader, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::str::FromStr as _;

use bitcoin::consensus::encode::{deserialize_hex, serialize_hex};
use bitcoin::hex::{DisplayHex as _, FromHex as _};
use bitcoin::{OutPoint, ScriptBuf, Transaction};
use bitcoin_rs_nested_musig2::{AggregateNonce, PartialSignature, PlainPublicKey, PublicNonce};
use serde::{Deserialize, Serialize};

use crate::client::{Intent, Observed, Rejection, RoleSigner};
use crate::keys::{KeyNetwork, Participant};
use crate::policy::SignerId;
use crate::signing::{Cosigner, NonceRequest, PartialRequest, SchnorrRequest, SignTarget};
use crate::statement::ArkTransitionV1;
use crate::{Error, Result};

#[derive(Serialize, Deserialize)]
pub struct WireObserved {
    pub outpoint: String,
    pub amount_sat: u64,
    pub script_pubkey: String,
    pub confirmations: u32,
}

#[derive(Serialize, Deserialize, Default)]
pub struct WireIntent {
    pub receive: Vec<u64>,
    pub boarding: Vec<(String, u64)>,
    pub forfeit: Vec<(String, u64)>,
    pub coop_exit: Vec<(String, u64)>,
    pub observed: Vec<WireObserved>,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    Pubkey,
    Load {
        statement: String,
        intent: WireIntent,
    },
    Nonce {
        session: String,
        statement: String,
        target: String,
        aggregate_key: String,
    },
    Partial {
        session: String,
        statement: String,
        target: String,
        nonce_path: Vec<String>,
        key_path: Vec<Vec<String>>,
        tweak: String,
    },
    AcceptTree {
        statement: String,
        txs: Vec<String>,
    },
    Schnorr {
        statement: String,
        target: String,
    },
    Abort {
        session: String,
    },
    Shutdown,
}

#[derive(Serialize, Deserialize)]
pub struct Response {
    pub ok: bool,
    pub value: Option<String>,
    pub stage: Option<String>,
    pub detail: Option<String>,
}

fn protocol(detail: impl Into<String>) -> Error {
    Error::Remote(detail.into())
}

fn hex_array<const N: usize>(text: &str) -> Result<[u8; N]> {
    <[u8; N]>::from_hex(text).map_err(|_| protocol("malformed fixed-length hex"))
}

fn parse_outpoint(text: &str) -> Result<OutPoint> {
    OutPoint::from_str(text).map_err(|_| protocol("malformed outpoint"))
}

fn parse_script(text: &str) -> Result<ScriptBuf> {
    Ok(ScriptBuf::from_bytes(
        Vec::<u8>::from_hex(text).map_err(|_| protocol("malformed script"))?,
    ))
}

fn parse_target(text: &str) -> Result<SignTarget> {
    SignTarget::parse(text).ok_or_else(|| protocol("malformed target"))
}

impl WireIntent {
    pub fn from_intent(intent: &Intent) -> Self {
        Self {
            receive: intent.receive.clone(),
            boarding: intent
                .boarding
                .iter()
                .map(|(o, a)| (o.to_string(), *a))
                .collect(),
            forfeit: intent
                .forfeit
                .iter()
                .map(|(o, a)| (o.to_string(), *a))
                .collect(),
            coop_exit: intent
                .coop_exit
                .iter()
                .map(|(s, a)| (s.to_hex_string(), *a))
                .collect(),
            observed: intent
                .observed
                .iter()
                .map(|utxo| WireObserved {
                    outpoint: utxo.outpoint.to_string(),
                    amount_sat: utxo.amount_sat,
                    script_pubkey: utxo.script_pubkey.to_hex_string(),
                    confirmations: utxo.confirmations,
                })
                .collect(),
        }
    }

    pub fn to_intent(&self) -> Result<Intent> {
        Ok(Intent {
            receive: self.receive.clone(),
            boarding: self
                .boarding
                .iter()
                .map(|(o, a)| Ok((parse_outpoint(o)?, *a)))
                .collect::<Result<_>>()?,
            forfeit: self
                .forfeit
                .iter()
                .map(|(o, a)| Ok((parse_outpoint(o)?, *a)))
                .collect::<Result<_>>()?,
            coop_exit: self
                .coop_exit
                .iter()
                .map(|(s, a)| Ok((parse_script(s)?, *a)))
                .collect::<Result<_>>()?,
            observed: self
                .observed
                .iter()
                .map(|utxo| {
                    Ok(Observed {
                        outpoint: parse_outpoint(&utxo.outpoint)?,
                        amount_sat: utxo.amount_sat,
                        script_pubkey: parse_script(&utxo.script_pubkey)?,
                        confirmations: utxo.confirmations,
                    })
                })
                .collect::<Result<_>>()?,
        })
    }
}

fn handle(signer: &mut RoleSigner, request: Request) -> Result<Option<String>> {
    match request {
        Request::Pubkey => Ok(Some(signer.public_key().serialize().to_lower_hex_string())),
        Request::Load { statement, intent } => {
            let bytes =
                Vec::<u8>::from_hex(&statement).map_err(|_| protocol("malformed statement hex"))?;
            let statement = ArkTransitionV1::decode(&bytes)?;
            let digest = signer.load(&statement, &intent.to_intent()?)?;
            Ok(Some(digest.to_lower_hex_string()))
        }
        Request::Nonce {
            session,
            statement,
            target,
            aggregate_key,
        } => {
            let nonce = signer.nonce(&NonceRequest {
                session,
                statement: hex_array(&statement)?,
                target: parse_target(&target)?,
                aggregate_key: hex_array(&aggregate_key)?,
            })?;
            Ok(Some(nonce.serialize().to_lower_hex_string()))
        }
        Request::Partial {
            session,
            statement,
            target,
            nonce_path,
            key_path,
            tweak,
        } => {
            let partial = signer.partial(&PartialRequest {
                session,
                statement: hex_array(&statement)?,
                target: parse_target(&target)?,
                nonce_path: nonce_path
                    .iter()
                    .map(|nonce| Ok(AggregateNonce::from_slice(&hex_array::<66>(nonce)?)?))
                    .collect::<Result<_>>()?,
                key_path: key_path
                    .iter()
                    .map(|level| {
                        level
                            .iter()
                            .map(|key| Ok(PlainPublicKey::from_slice(&hex_array::<33>(key)?)?))
                            .collect::<Result<Vec<_>>>()
                    })
                    .collect::<Result<_>>()?,
                tweak: hex_array(&tweak)?,
            })?;
            Ok(Some(partial.serialize().to_lower_hex_string()))
        }
        Request::AcceptTree { statement, txs } => {
            let txs: Vec<Transaction> = txs
                .iter()
                .map(|tx| deserialize_hex(tx).map_err(|_| protocol("malformed transaction")))
                .collect::<Result<_>>()?;
            signer.accept_tree(hex_array(&statement)?, &txs)?;
            Ok(None)
        }
        Request::Schnorr { statement, target } => {
            let signature = signer.schnorr(&SchnorrRequest {
                statement: hex_array(&statement)?,
                target: parse_target(&target)?,
            })?;
            Ok(Some(signature.to_lower_hex_string()))
        }
        Request::Abort { session } => {
            signer.abort(&session)?;
            Ok(None)
        }
        Request::Shutdown => Ok(None),
    }
}

/// The signer process: one JSON request per stdin line, one JSON response per
/// stdout line. Secret nonces never leave the process and are lost on exit.
pub fn serve(role: SignerId, key_path: &Path, network: KeyNetwork) -> Result<()> {
    let mut signer = RoleSigner::new(role, Participant::load(key_path, network)?)?;
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout().lock();
    for line in stdin.lock().lines() {
        let line = line?;
        let request: Request = match sonic_rs::from_str(&line) {
            Ok(request) => request,
            Err(error) => {
                write_response(
                    &mut stdout,
                    Err(protocol(format!("request is not valid JSON: {error}"))),
                )?;
                continue;
            }
        };
        let shutdown = matches!(request, Request::Shutdown);
        write_response(&mut stdout, handle(&mut signer, request))?;
        if shutdown {
            break;
        }
    }
    Ok(())
}

fn write_response(output: &mut impl std::io::Write, result: Result<Option<String>>) -> Result<()> {
    let response = match result {
        Ok(value) => Response {
            ok: true,
            value,
            stage: None,
            detail: None,
        },
        Err(Error::Rejected(rejection)) => Response {
            ok: false,
            value: None,
            stage: Some(rejection.stage),
            detail: Some(rejection.detail),
        },
        Err(error) => Response {
            ok: false,
            value: None,
            stage: Some("signer-error".to_owned()),
            detail: Some(error.to_string()),
        },
    };
    writeln!(output, "{}", sonic_rs::to_string(&response)?)?;
    output.flush()?;
    Ok(())
}

fn exchange(
    stdin: &mut ChildStdin,
    stdout: &mut BufReader<ChildStdout>,
    request: &Request,
) -> Result<Option<String>> {
    writeln!(stdin, "{}", sonic_rs::to_string(request)?)?;
    stdin.flush()?;
    let mut line = String::new();
    if stdout.read_line(&mut line)? == 0 {
        return Err(protocol("signer process closed its output"));
    }
    let response: Response = sonic_rs::from_str(line.trim_end())?;
    if response.ok {
        Ok(response.value)
    } else {
        Err(Error::Rejected(Rejection {
            stage: response.stage.unwrap_or_default(),
            detail: response.detail.unwrap_or_default(),
        }))
    }
}

/// A cosigner reached through a child process's stdin and stdout.
pub struct ProcessCosigner {
    binary: PathBuf,
    key_path: PathBuf,
    network: KeyNetwork,
    role: SignerId,
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    public: PlainPublicKey,
    pub pid: u32,
}

impl ProcessCosigner {
    pub fn spawn(
        binary: &Path,
        role: SignerId,
        key_path: &Path,
        network: KeyNetwork,
    ) -> Result<Self> {
        let SignerId::User(index) = role else {
            return Err(protocol("process signers are user roles"));
        };
        let mut child = Command::new(binary)
            .arg("signer")
            .arg("--user")
            .arg(index.to_string())
            .arg("--key")
            .arg(key_path)
            .arg("--network")
            .arg(network.name())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?;
        let mut stdin = child.stdin.take().ok_or_else(|| protocol("no stdin"))?;
        let mut stdout = BufReader::new(child.stdout.take().ok_or_else(|| protocol("no stdout"))?);
        let pid = child.id();
        let public = exchange(&mut stdin, &mut stdout, &Request::Pubkey)?
            .ok_or_else(|| protocol("no public key"))?;
        Ok(Self {
            binary: binary.to_path_buf(),
            key_path: key_path.to_path_buf(),
            network,
            role,
            child,
            stdin,
            stdout,
            public: PlainPublicKey::from_slice(&hex_array::<33>(&public)?)?,
            pid,
        })
    }

    fn call(&mut self, request: &Request) -> Result<Option<String>> {
        exchange(&mut self.stdin, &mut self.stdout, request)
    }

    /// Terminates the process without warning, losing every in-memory nonce.
    pub fn crash(&mut self) -> Result<()> {
        self.child.kill()?;
        self.child.wait()?;
        Ok(())
    }

    pub fn restart(&mut self) -> Result<()> {
        let _ = self.child.kill();
        let _ = self.child.wait();
        *self = Self::spawn(
            &self.binary.clone(),
            self.role,
            &self.key_path.clone(),
            self.network,
        )?;
        Ok(())
    }

    pub fn shutdown(mut self) -> Result<()> {
        let _ = self.call(&Request::Shutdown);
        self.child.wait()?;
        Ok(())
    }
}

impl Cosigner for ProcessCosigner {
    fn public_key(&self) -> PlainPublicKey {
        self.public
    }

    fn load(&mut self, statement: &ArkTransitionV1, intent: &Intent) -> Result<[u8; 32]> {
        let value = self.call(&Request::Load {
            statement: statement.encode()?.to_lower_hex_string(),
            intent: WireIntent::from_intent(intent),
        })?;
        hex_array(&value.ok_or_else(|| protocol("no digest"))?)
    }

    fn nonce(&mut self, request: &NonceRequest) -> Result<PublicNonce> {
        let value = self.call(&Request::Nonce {
            session: request.session.clone(),
            statement: request.statement.to_lower_hex_string(),
            target: request.target.label(),
            aggregate_key: request.aggregate_key.to_lower_hex_string(),
        })?;
        Ok(PublicNonce::from_slice(&hex_array::<66>(
            &value.ok_or_else(|| protocol("no nonce"))?,
        )?)?)
    }

    fn partial(&mut self, request: &PartialRequest) -> Result<PartialSignature> {
        let value = self.call(&Request::Partial {
            session: request.session.clone(),
            statement: request.statement.to_lower_hex_string(),
            target: request.target.label(),
            nonce_path: request
                .nonce_path
                .iter()
                .map(|n| n.serialize().to_lower_hex_string())
                .collect(),
            key_path: request
                .key_path
                .iter()
                .map(|level| {
                    level
                        .iter()
                        .map(|k| k.serialize().to_lower_hex_string())
                        .collect()
                })
                .collect(),
            tweak: request.tweak.to_lower_hex_string(),
        })?;
        Ok(PartialSignature::from_slice(&hex_array::<32>(
            &value.ok_or_else(|| protocol("no partial"))?,
        )?)?)
    }

    fn accept_tree(&mut self, statement: [u8; 32], signed: &[Transaction]) -> Result<()> {
        self.call(&Request::AcceptTree {
            statement: statement.to_lower_hex_string(),
            txs: signed.iter().map(serialize_hex).collect(),
        })?;
        Ok(())
    }

    fn schnorr(&mut self, request: &SchnorrRequest) -> Result<[u8; 64]> {
        let value = self.call(&Request::Schnorr {
            statement: request.statement.to_lower_hex_string(),
            target: request.target.label(),
        })?;
        hex_array(&value.ok_or_else(|| protocol("no signature"))?)
    }

    fn abort(&mut self, session: &str) -> Result<()> {
        self.call(&Request::Abort {
            session: session.to_owned(),
        })?;
        Ok(())
    }
}
