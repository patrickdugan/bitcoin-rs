use std::fs::{self, File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::str::FromStr as _;

use bitcoin::consensus::encode::serialize_hex;
use bitcoin::hashes::Hash as _;
use bitcoin::hex::{DisplayHex as _, FromHex as _};
use bitcoin::key::TweakedPublicKey;
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::TapTweakHash;
use bitcoin::{Address, Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut};
use bitcoin_rs_nested_musig2 as nested;
use clap::{Parser, Subcommand, ValueEnum};
use secp256k1::XOnlyPublicKey;
use secp256k1::rand::{RngCore as _, rngs::OsRng};
use serde::Serialize;
use zeroize::Zeroizing;

const KEY_MAGIC: &[u8; 8] = b"NM2STG01";
const KEY_COUNT: usize = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum StagingNetwork {
    Regtest,
    Testnet4,
}

impl StagingNetwork {
    fn bitcoin(self) -> Network {
        match self {
            Self::Regtest => Network::Regtest,
            Self::Testnet4 => Network::Testnet4,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Regtest => "regtest",
            Self::Testnet4 => "testnet4",
        }
    }

    fn code(self) -> u8 {
        match self {
            Self::Regtest => 0,
            Self::Testnet4 => 1,
        }
    }
}

#[derive(Parser)]
#[command(about = "Experimental depth-two NestedMuSig2 transaction staging")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Init(KeyArgs),
    Info(KeyArgs),
    Sign(SignArgs),
}

#[derive(clap::Args)]
struct KeyArgs {
    #[arg(long, value_enum)]
    network: StagingNetwork,
    #[arg(long)]
    keys: PathBuf,
}

#[derive(clap::Args)]
struct SignArgs {
    #[command(flatten)]
    key: KeyArgs,
    #[arg(long)]
    txid: bitcoin::Txid,
    #[arg(long)]
    vout: u32,
    #[arg(long)]
    amount_sat: u64,
    #[arg(long)]
    prevout_scriptpubkey: String,
    #[arg(long)]
    destination: String,
    #[arg(long)]
    fee_sat: u64,
    #[arg(long)]
    max_fee_sat: u64,
}

#[derive(Debug, thiserror::Error)]
enum Error {
    #[error("filesystem operation failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("NestedMuSig2 operation failed: {0}")]
    Nested(#[from] nested::Error),
    #[error("public-key encoding failed: {0}")]
    Secp(#[from] secp256k1::Error),
    #[error("JSON output failed: {0}")]
    Json(#[from] sonic_rs::Error),
    #[error("destination address is invalid: {0}")]
    Address(#[from] bitcoin::address::ParseError),
    #[error("prevout script encoding is invalid: {0}")]
    Hex(#[from] bitcoin::hex::HexToBytesError),
    #[error("Taproot sighash failed: {0}")]
    Sighash(#[from] bitcoin::sighash::TaprootError),
    #[error("operating-system randomness failed: {0}")]
    Random(#[from] secp256k1::rand::Error),
    #[error("key file must be a regular file with mode 0600 or stricter")]
    KeyPermissions,
    #[error("key file format is invalid")]
    KeyFormat,
    #[error("key file belongs to a different network")]
    KeyNetwork,
    #[error("destination belongs to a different network")]
    DestinationNetwork,
    #[error("prevout script does not match this signing tree")]
    PrevoutScript,
    #[error("fee must be positive, at most max-fee-sat, and less than input amount")]
    Fee,
    #[error("transaction output is below the dust threshold")]
    Dust,
    #[error("partial signature verification failed")]
    PartialSignature,
    #[error("aggregate signature verification failed: {0}")]
    AggregateSignature(#[source] secp256k1::Error),
    #[error("NestedMuSig2 root tweak differs from the Bitcoin Taproot output key")]
    TaprootKey,
    #[error("staging key files require Unix file permissions")]
    UnsupportedPlatform,
}

struct KeyMaterial {
    network: StagingNetwork,
    bytes: Zeroizing<[u8; KEY_COUNT * 32]>,
}

impl KeyMaterial {
    fn generate(network: StagingNetwork) -> Result<Self, Error> {
        let mut bytes = Zeroizing::new([0_u8; KEY_COUNT * 32]);
        for secret in bytes.as_chunks_mut::<32>().0 {
            loop {
                OsRng.try_fill_bytes(secret)?;
                if nested::public_key(secret).is_ok() {
                    break;
                }
            }
        }
        Ok(Self { network, bytes })
    }

    fn secret(&self, index: usize) -> Result<&[u8; 32], Error> {
        self.bytes
            .get(index * 32..(index + 1) * 32)
            .ok_or(Error::KeyFormat)?
            .try_into()
            .map_err(|_| Error::KeyFormat)
    }

    fn save(&self, path: &Path) -> Result<(), Error> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        if !cfg!(unix) {
            return Err(Error::UnsupportedPlatform);
        }
        let mut file = options.open(path)?;
        file.write_all(KEY_MAGIC)?;
        file.write_all(&[self.network.code()])?;
        file.write_all(self.bytes.as_ref())?;
        file.sync_all()?;
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        File::open(parent)?.sync_all()?;
        Ok(())
    }

    fn load(path: &Path, network: StagingNetwork) -> Result<Self, Error> {
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.file_type().is_file() {
            return Err(Error::KeyPermissions);
        }
        let mut file = File::open(path)?;
        let opened = file.metadata()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
            if opened.permissions().mode() & 0o077 != 0
                || opened.ino() != metadata.ino()
                || opened.dev() != metadata.dev()
            {
                return Err(Error::KeyPermissions);
            }
        }
        if !cfg!(unix) {
            return Err(Error::UnsupportedPlatform);
        }
        if opened.len() != 137 {
            return Err(Error::KeyFormat);
        }
        let mut header = [0_u8; 9];
        file.read_exact(&mut header)?;
        if &header[..8] != KEY_MAGIC {
            return Err(Error::KeyFormat);
        }
        if header[8] != network.code() {
            return Err(Error::KeyNetwork);
        }
        let mut bytes = Zeroizing::new([0_u8; KEY_COUNT * 32]);
        file.read_exact(bytes.as_mut())?;
        if file.read(&mut [0])? != 0 {
            return Err(Error::KeyFormat);
        }
        Ok(Self { network, bytes })
    }
}

struct Tree {
    leaves: [nested::PlainPublicKey; 4],
    groups: [nested::PlainPublicKey; 2],
    untweaked: nested::KeyAggContext,
    tweaked: nested::KeyAggContext,
    tweak: nested::Tweak,
    tweak_bytes: [u8; 32],
    address: Address,
}

#[derive(Serialize)]
struct PublicTree {
    schema: &'static str,
    network: &'static str,
    genesis_hash: String,
    profile: &'static str,
    leaf_public_keys: Vec<String>,
    group_public_keys: Vec<String>,
    internal_public_key: String,
    tap_tweak: String,
    output_public_key: String,
    address: String,
    script_pubkey: String,
}

impl Tree {
    fn new(keys: &KeyMaterial) -> Result<Self, Error> {
        let leaves = [
            nested::public_key(keys.secret(0)?)?,
            nested::public_key(keys.secret(1)?)?,
            nested::public_key(keys.secret(2)?)?,
            nested::public_key(keys.secret(3)?)?,
        ];
        let groups = [
            nested::key_agg(&leaves[..2])?.plain_key(),
            nested::key_agg(&leaves[2..])?.plain_key(),
        ];
        let untweaked = nested::key_agg(&groups)?;
        let internal = XOnlyPublicKey::from_slice(&untweaked.xonly_key())?;
        let tweak_bytes = TapTweakHash::from_key_and_tweak(internal, None).to_byte_array();
        let tweak = nested::Tweak::new(tweak_bytes, true)?;
        let tweaked = nested::apply_tweaks(&untweaked, &[tweak])?;
        let output_key = XOnlyPublicKey::from_slice(&tweaked.xonly_key())?;
        let address = Address::p2tr_tweaked(
            TweakedPublicKey::dangerous_assume_tweaked(output_key),
            keys.network.bitcoin(),
        );
        if address != Address::p2tr(secp256k1::SECP256K1, internal, None, keys.network.bitcoin()) {
            return Err(Error::TaprootKey);
        }
        Ok(Self {
            leaves,
            groups,
            untweaked,
            tweaked,
            tweak,
            tweak_bytes,
            address,
        })
    }

    fn public(&self, network: StagingNetwork) -> PublicTree {
        PublicTree {
            schema: "nested-musig2-staging-public-v1",
            network: network.name(),
            genesis_hash: bitcoin::blockdata::constants::genesis_block(network.bitcoin())
                .block_hash()
                .to_string(),
            profile: "depth-2-two-groups-of-two-local-signers",
            leaf_public_keys: self
                .leaves
                .iter()
                .map(|key| key.serialize().to_lower_hex_string())
                .collect(),
            group_public_keys: self
                .groups
                .iter()
                .map(|key| key.serialize().to_lower_hex_string())
                .collect(),
            internal_public_key: self.untweaked.plain_key().serialize().to_lower_hex_string(),
            tap_tweak: self.tweak_bytes.to_lower_hex_string(),
            output_public_key: self.tweaked.xonly_key().to_lower_hex_string(),
            address: self.address.to_string(),
            script_pubkey: self.address.script_pubkey().to_hex_string(),
        }
    }

    fn sign(&self, keys: &KeyMaterial, digest: &[u8; 32]) -> Result<[u8; 64], Error> {
        let mut secret_nonces = Vec::with_capacity(KEY_COUNT);
        let mut public_nonces = Vec::with_capacity(KEY_COUNT);
        for (index, public_key) in self.leaves.iter().enumerate() {
            let (secret_nonce, public_nonce) = nested::nonce_gen(
                Some(keys.secret(index)?),
                *public_key,
                Some(self.tweaked.xonly_key()),
                Some(digest),
                None,
            )?;
            secret_nonces.push(secret_nonce);
            public_nonces.push(public_nonce);
        }
        let group_nonces = [
            nested::nonce_agg(&public_nonces[..2])?,
            nested::nonce_agg(&public_nonces[2..])?,
        ];
        let external_nonces = [
            nested::nonce_agg_ext(group_nonces[0], self.groups[0])?,
            nested::nonce_agg_ext(group_nonces[1], self.groups[1])?,
        ];
        let root_nonce = nested::nonce_agg(&external_nonces)?;
        let mut partials = Vec::with_capacity(KEY_COUNT);
        for (index, secret_nonce) in secret_nonces.into_iter().enumerate() {
            let group_index = index / 2;
            let context = nested::SessionContext {
                nonce_path: vec![root_nonce, group_nonces[group_index]],
                key_path: vec![
                    vec![self.groups[1 - group_index]],
                    vec![self.leaves[index ^ 1]],
                ],
                tweaks: vec![self.tweak],
                message: digest.to_vec(),
            };
            let partial = nested::sign(secret_nonce, keys.secret(index)?, &context)?;
            if !nested::partial_sig_verify(
                partial,
                public_nonces[index],
                self.leaves[index],
                &context,
            )? {
                return Err(Error::PartialSignature);
            }
            partials.push(partial);
        }
        let group_signatures = [
            nested::aggregate_intermediate(&partials[..2])?,
            nested::aggregate_intermediate(&partials[2..])?,
        ];
        let signature = nested::aggregate_root(
            &group_signatures,
            &nested::RootSessionContext {
                aggregate_nonce: root_nonce,
                pubkeys: self.groups.to_vec(),
                tweaks: vec![self.tweak],
                message: digest.to_vec(),
            },
        )?;
        secp256k1::SECP256K1
            .verify_schnorr(
                &secp256k1::schnorr::Signature::from_slice(&signature)?,
                &secp256k1::Message::from_digest(*digest),
                &XOnlyPublicKey::from_slice(&self.tweaked.xonly_key())?,
            )
            .map_err(Error::AggregateSignature)?;
        Ok(signature)
    }
}

#[derive(Serialize)]
struct SignedTransaction {
    schema: &'static str,
    tree: PublicTree,
    previous_txid: String,
    previous_vout: u32,
    input_amount_sat: u64,
    destination: String,
    output_amount_sat: u64,
    fee_sat: u64,
    max_fee_sat: u64,
    sighash_type: &'static str,
    sighash: String,
    signature: String,
    txid: String,
    wtxid: String,
    vsize: usize,
    transaction_hex: String,
}

fn sign_transaction(args: SignArgs) -> Result<SignedTransaction, Error> {
    if args.fee_sat == 0 || args.fee_sat > args.max_fee_sat || args.fee_sat >= args.amount_sat {
        return Err(Error::Fee);
    }
    let keys = KeyMaterial::load(&args.key.keys, args.key.network)?;
    let tree = Tree::new(&keys)?;
    let prevout_script = ScriptBuf::from_bytes(Vec::<u8>::from_hex(&args.prevout_scriptpubkey)?);
    if prevout_script != tree.address.script_pubkey() {
        return Err(Error::PrevoutScript);
    }
    let unchecked = Address::from_str(&args.destination)?;
    if !unchecked.is_valid_for_network(args.key.network.bitcoin()) {
        return Err(Error::DestinationNetwork);
    }
    let destination = unchecked.assume_checked();
    let output_amount_sat = args.amount_sat - args.fee_sat;
    let output = TxOut {
        value: Amount::from_sat(output_amount_sat),
        script_pubkey: destination.script_pubkey(),
    };
    if output.value < output.script_pubkey.minimal_non_dust() {
        return Err(Error::Dust);
    }
    let mut transaction = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(args.txid, args.vout),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: bitcoin::Witness::new(),
        }],
        output: vec![output],
    };
    let prevouts = [TxOut {
        value: Amount::from_sat(args.amount_sat),
        script_pubkey: prevout_script,
    }];
    let digest = SighashCache::new(&transaction)
        .taproot_key_spend_signature_hash(0, &Prevouts::All(&prevouts), TapSighashType::Default)?
        .to_byte_array();
    let signature = tree.sign(&keys, &digest)?;
    transaction.input[0].witness.push(signature);
    Ok(SignedTransaction {
        schema: "nested-musig2-staging-transaction-v1",
        tree: tree.public(args.key.network),
        previous_txid: args.txid.to_string(),
        previous_vout: args.vout,
        input_amount_sat: args.amount_sat,
        destination: destination.to_string(),
        output_amount_sat,
        fee_sat: args.fee_sat,
        max_fee_sat: args.max_fee_sat,
        sighash_type: "SIGHASH_DEFAULT",
        sighash: digest.to_lower_hex_string(),
        signature: signature.to_lower_hex_string(),
        txid: transaction.compute_txid().to_string(),
        wtxid: transaction.compute_wtxid().to_string(),
        vsize: transaction.vsize(),
        transaction_hex: serialize_hex(&transaction),
    })
}

fn run() -> Result<(), Error> {
    let output = match Args::parse().command {
        Command::Init(args) => {
            let keys = KeyMaterial::generate(args.network)?;
            let tree = Tree::new(&keys)?;
            keys.save(&args.keys)?;
            sonic_rs::to_string_pretty(&tree.public(args.network))?
        }
        Command::Info(args) => {
            let keys = KeyMaterial::load(&args.keys, args.network)?;
            sonic_rs::to_string_pretty(&Tree::new(&keys)?.public(args.network))?
        }
        Command::Sign(args) => sonic_rs::to_string_pretty(&sign_transaction(args)?)?,
    };
    println!("{output}");
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    fn request(path: &Path, tree: &Tree) -> SignArgs {
        SignArgs {
            key: KeyArgs {
                network: StagingNetwork::Regtest,
                keys: path.to_path_buf(),
            },
            txid: bitcoin::Txid::from_byte_array([1; 32]),
            vout: 0,
            amount_sat: 100_000,
            prevout_scriptpubkey: tree.address.script_pubkey().to_hex_string(),
            destination: tree.address.to_string(),
            fee_sat: 1_000,
            max_fee_sat: 1_000,
        }
    }

    #[test]
    fn key_file_creation_preserves_existing_keys_and_binds_network() -> Result<(), Error> {
        let temporary = tempfile::tempdir()?;
        let path = temporary.path().join("keys.bin");
        let keys = KeyMaterial::generate(StagingNetwork::Regtest)?;
        keys.save(&path)?;
        assert_eq!(fs::metadata(&path)?.permissions().mode() & 0o777, 0o600);
        let original = Zeroizing::new(fs::read(&path)?);
        let other = KeyMaterial::generate(StagingNetwork::Regtest)?;
        assert!(
            matches!(other.save(&path), Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::AlreadyExists)
        );
        assert!(original.as_slice() == Zeroizing::new(fs::read(&path)?).as_slice());
        assert!(matches!(
            KeyMaterial::load(&path, StagingNetwork::Testnet4),
            Err(Error::KeyNetwork)
        ));
        let mut file = OpenOptions::new().append(true).open(&path)?;
        file.write_all(&[0])?;
        assert!(matches!(
            KeyMaterial::load(&path, StagingNetwork::Regtest),
            Err(Error::KeyFormat)
        ));
        Ok(())
    }

    #[test]
    fn key_file_loading_rejects_public_permissions_and_symlinks() -> Result<(), Error> {
        let temporary = tempfile::tempdir()?;
        let path = temporary.path().join("keys.bin");
        KeyMaterial::generate(StagingNetwork::Regtest)?.save(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644))?;
        assert!(matches!(
            KeyMaterial::load(&path, StagingNetwork::Regtest),
            Err(Error::KeyPermissions)
        ));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        let link = temporary.path().join("link.bin");
        symlink(&path, &link)?;
        assert!(matches!(
            KeyMaterial::load(&link, StagingNetwork::Regtest),
            Err(Error::KeyPermissions)
        ));
        Ok(())
    }

    #[test]
    fn signing_checks_fee_cap_and_the_funding_script() -> Result<(), Error> {
        let temporary = tempfile::tempdir()?;
        let path = temporary.path().join("keys.bin");
        let keys = KeyMaterial::generate(StagingNetwork::Regtest)?;
        keys.save(&path)?;
        let tree = Tree::new(&keys)?;
        let mut bad_fee = request(&path, &tree);
        bad_fee.fee_sat = 1001;
        assert!(matches!(sign_transaction(bad_fee), Err(Error::Fee)));
        let mut bad_script = request(&path, &tree);
        bad_script.prevout_scriptpubkey = "51".to_owned();
        assert!(matches!(
            sign_transaction(bad_script),
            Err(Error::PrevoutScript)
        ));
        Ok(())
    }

    #[test]
    fn repeated_authorization_uses_fresh_valid_signatures() -> Result<(), Error> {
        let temporary = tempfile::tempdir()?;
        let path = temporary.path().join("keys.bin");
        let keys = KeyMaterial::generate(StagingNetwork::Regtest)?;
        keys.save(&path)?;
        let tree = Tree::new(&keys)?;
        let first = sign_transaction(request(&path, &tree))?;
        let second = sign_transaction(request(&path, &tree))?;
        assert_eq!(first.txid, second.txid);
        assert_eq!(first.sighash, second.sighash);
        assert_ne!(first.signature, second.signature);
        assert_ne!(first.wtxid, second.wtxid);
        let key = XOnlyPublicKey::from_slice(&tree.tweaked.xonly_key())?;
        for signed in [first, second] {
            let signature = secp256k1::schnorr::Signature::from_slice(&Vec::<u8>::from_hex(
                &signed.signature,
            )?)?;
            let digest = Vec::<u8>::from_hex(&signed.sighash)?;
            let message = secp256k1::Message::from_digest_slice(&digest)?;
            secp256k1::Secp256k1::verification_only().verify_schnorr(&signature, &message, &key)?;
            assert_eq!(signed.output_amount_sat + signed.fee_sat, 100_000);
        }
        Ok(())
    }

    #[test]
    fn command_line_requires_the_test_network_and_fee_limit() {
        assert!(
            Args::try_parse_from([
                "nested-musig2",
                "init",
                "--network",
                "mainnet",
                "--keys",
                "keys.bin"
            ])
            .is_err()
        );
        assert!(
            Args::try_parse_from([
                "nested-musig2",
                "sign",
                "--network",
                "regtest",
                "--keys",
                "keys.bin",
                "--txid",
                "0101010101010101010101010101010101010101010101010101010101010101",
                "--vout",
                "0",
                "--amount-sat",
                "100000",
                "--prevout-scriptpubkey",
                "51",
                "--destination",
                "unparsed-address",
                "--fee-sat",
                "1000"
            ])
            .is_err()
        );
    }
}
