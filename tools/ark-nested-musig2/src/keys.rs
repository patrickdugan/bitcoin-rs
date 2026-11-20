use std::fs::{self, File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::path::Path;

use bitcoin::key::TapTweak as _;
use bitcoin::secp256k1::{Keypair, Message, SECP256K1, XOnlyPublicKey};
use bitcoin_hashes::{Hash as _, HashEngine as _, sha256};
use bitcoin_rs_nested_musig2::{self as nested, PlainPublicKey};
use secp256k1::rand::{RngCore as _, rngs::OsRng};
use zeroize::Zeroizing;

use crate::{Error, Result};

const KEY_MAGIC: &[u8; 8] = b"ARKNM2K1";
const KEY_FILE_LENGTH: u64 = 8 + 1 + 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyNetwork {
    Regtest,
    Testnet4,
}

impl KeyNetwork {
    pub fn bitcoin(self) -> bitcoin::Network {
        match self {
            Self::Regtest => bitcoin::Network::Regtest,
            Self::Testnet4 => bitcoin::Network::Testnet4,
        }
    }

    pub fn code(self) -> u8 {
        match self {
            Self::Regtest => 0,
            Self::Testnet4 => 1,
        }
    }

    pub fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(Self::Regtest),
            1 => Some(Self::Testnet4),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Regtest => "regtest",
            Self::Testnet4 => "testnet4",
        }
    }
}

/// Secret material for one role. The secret has no clone or serialization
/// interface other than the 0600 key file, and it is erased on drop.
pub struct Participant {
    secret: Zeroizing<[u8; 32]>,
}

impl Participant {
    pub fn generate() -> Result<Self> {
        let mut secret = Zeroizing::new([0_u8; 32]);
        loop {
            OsRng.try_fill_bytes(secret.as_mut())?;
            if nested::public_key(secret.as_ref()).is_ok() {
                return Ok(Self { secret });
            }
        }
    }

    pub fn from_seed(seed: &[u8; 32], label: &str, index: u32) -> Result<Self> {
        let mut counter = 0_u32;
        loop {
            let mut engine = sha256::Hash::engine();
            engine.input(b"ark-nested-musig2/bench-key");
            engine.input(seed);
            engine.input(label.as_bytes());
            engine.input(&index.to_le_bytes());
            engine.input(&counter.to_le_bytes());
            let secret = Zeroizing::new(sha256::Hash::from_engine(engine).to_byte_array());
            if nested::public_key(secret.as_ref()).is_ok() {
                return Ok(Self { secret });
            }
            counter = counter.checked_add(1).ok_or(Error::Range("seed counter"))?;
        }
    }

    pub fn secret(&self) -> &[u8; 32] {
        &self.secret
    }

    pub fn plain(&self) -> Result<PlainPublicKey> {
        Ok(nested::public_key(self.secret.as_ref())?)
    }

    pub fn keypair(&self) -> Result<Keypair> {
        Ok(Keypair::from_seckey_slice(SECP256K1, self.secret.as_ref())?)
    }

    pub fn xonly(&self) -> Result<XOnlyPublicKey> {
        Ok(self.keypair()?.x_only_public_key().0)
    }

    pub fn sign_script_path(&self, digest: [u8; 32]) -> Result<[u8; 64]> {
        let keypair = self.keypair()?;
        sign_with(&keypair, digest)
    }

    pub fn sign_key_path(&self, digest: [u8; 32]) -> Result<[u8; 64]> {
        let tweaked = self.keypair()?.tap_tweak(SECP256K1, None).to_keypair();
        sign_with(&tweaked, digest)
    }

    pub fn save(&self, path: &Path, network: KeyNetwork) -> Result<()> {
        if !cfg!(unix) {
            return Err(Error::UnsupportedPlatform);
        }
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let mut file = options.open(path)?;
        file.write_all(KEY_MAGIC)?;
        file.write_all(&[network.code()])?;
        file.write_all(self.secret.as_ref())?;
        file.sync_all()?;
        Ok(())
    }

    pub fn load(path: &Path, network: KeyNetwork) -> Result<Self> {
        if !cfg!(unix) {
            return Err(Error::UnsupportedPlatform);
        }
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
        if opened.len() != KEY_FILE_LENGTH {
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
        let mut secret = Zeroizing::new([0_u8; 32]);
        file.read_exact(secret.as_mut())?;
        if nested::public_key(secret.as_ref()).is_err() {
            return Err(Error::KeyFormat);
        }
        Ok(Self { secret })
    }
}

fn sign_with(keypair: &Keypair, digest: [u8; 32]) -> Result<[u8; 64]> {
    let mut auxiliary = Zeroizing::new([0_u8; 32]);
    OsRng.try_fill_bytes(auxiliary.as_mut())?;
    let signature =
        SECP256K1.sign_schnorr_with_aux_rand(&Message::from_digest(digest), keypair, &auxiliary);
    Ok(signature.serialize())
}

pub fn xonly_of(key: PlainPublicKey) -> Result<XOnlyPublicKey> {
    Ok(XOnlyPublicKey::from_slice(&key.xonly())?)
}
