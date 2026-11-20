use bitcoin::hashes::Hash as _;
use bitcoin::key::TweakedPublicKey;
use bitcoin::opcodes::all::{OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_CSV, OP_DROP};
use bitcoin::script::Builder;
use bitcoin::secp256k1::{SECP256K1, XOnlyPublicKey};
use bitcoin::taproot::{
    ControlBlock, LeafVersion, TapLeafHash, TapTweakHash, TaprootBuilder, TaprootSpendInfo,
};
use bitcoin::{Address, Network, ScriptBuf, Sequence};
use bitcoin_rs_nested_musig2::{self as nested, KeyAggContext, Tweak};

use crate::{Error, Result};

/// BIP341's provably unspendable internal key H, whose discrete logarithm is unknown.
pub const NUMS_XONLY: [u8; 32] = [
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
    0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
];

pub fn nums() -> Result<XOnlyPublicKey> {
    Ok(XOnlyPublicKey::from_slice(&NUMS_XONLY)?)
}

pub fn nums_compressed() -> [u8; 33] {
    let mut key = [2_u8; 33];
    key[1..].copy_from_slice(&NUMS_XONLY);
    key
}

pub fn csv_sequence(blocks: u16) -> Sequence {
    Sequence::from_height(blocks)
}

pub fn multisig_leaf(first: XOnlyPublicKey, second: XOnlyPublicKey) -> ScriptBuf {
    Builder::new()
        .push_x_only_key(&first)
        .push_opcode(OP_CHECKSIGVERIFY)
        .push_x_only_key(&second)
        .push_opcode(OP_CHECKSIG)
        .into_script()
}

pub fn csv_leaf(blocks: u16, key: XOnlyPublicKey) -> ScriptBuf {
    Builder::new()
        .push_int(i64::from(csv_sequence(blocks).to_consensus_u32()))
        .push_opcode(OP_CSV)
        .push_opcode(OP_DROP)
        .push_x_only_key(&key)
        .push_opcode(OP_CHECKSIG)
        .into_script()
}

/// The cooperative leaf needs the operator and the owner, in arkade-os/rust-sdk's
/// `<server> CHECKSIGVERIFY <owner> CHECKSIG` order; the exit leaf needs only the
/// owner after `exit_delay` blocks. Boarding outputs use the same template with
/// the longer boarding delay.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VtxoScript {
    pub owner: XOnlyPublicKey,
    pub asp: XOnlyPublicKey,
    pub exit_delay: u16,
}

impl VtxoScript {
    pub fn cooperative_leaf(&self) -> ScriptBuf {
        multisig_leaf(self.asp, self.owner)
    }

    pub fn exit_leaf(&self) -> ScriptBuf {
        csv_leaf(self.exit_delay, self.owner)
    }

    pub fn spend_info(&self) -> Result<TaprootSpendInfo> {
        TaprootBuilder::new()
            .add_leaf(1, self.cooperative_leaf())?
            .add_leaf(1, self.exit_leaf())?
            .finalize(SECP256K1, nums()?)
            .map_err(|_| Error::TaprootIncomplete)
    }

    pub fn script_pubkey(&self) -> Result<ScriptBuf> {
        Ok(ScriptBuf::new_p2tr_tweaked(self.spend_info()?.output_key()))
    }

    pub fn control_block(&self, leaf: &ScriptBuf) -> Result<ControlBlock> {
        self.spend_info()?
            .control_block(&(leaf.clone(), LeafVersion::TapScript))
            .ok_or(Error::TaprootIncomplete)
    }

    pub fn address(&self, network: Network) -> Result<Address> {
        Ok(Address::p2tr_tweaked(
            self.spend_info()?.output_key(),
            network,
        ))
    }
}

/// A batch-tree node output: the key path is the cosigners' aggregate, and the
/// only script leaf lets the operator sweep after `expiry` blocks.
#[derive(Clone, Copy, Debug)]
pub struct NodeScript {
    pub cosigners: KeyAggContext,
    pub asp: XOnlyPublicKey,
    pub expiry: u16,
}

impl NodeScript {
    pub fn internal_key(&self) -> Result<XOnlyPublicKey> {
        Ok(XOnlyPublicKey::from_slice(&self.cosigners.xonly_key())?)
    }

    pub fn sweep_leaf(&self) -> ScriptBuf {
        csv_leaf(self.expiry, self.asp)
    }

    pub fn spend_info(&self) -> Result<TaprootSpendInfo> {
        TaprootBuilder::new()
            .add_leaf(0, self.sweep_leaf())?
            .finalize(SECP256K1, self.internal_key()?)
            .map_err(|_| Error::TaprootIncomplete)
    }

    pub fn tweak_bytes(&self) -> Result<[u8; 32]> {
        let info = self.spend_info()?;
        Ok(
            TapTweakHash::from_key_and_tweak(self.internal_key()?, info.merkle_root())
                .to_byte_array(),
        )
    }

    pub fn tweak(&self) -> Result<Tweak> {
        Ok(Tweak::new(self.tweak_bytes()?, true)?)
    }

    pub fn output_key(&self) -> Result<[u8; 32]> {
        let tweaked = nested::apply_tweaks(&self.cosigners, &[self.tweak()?])?;
        let derived = tweaked.xonly_key();
        if derived
            != self
                .spend_info()?
                .output_key()
                .to_x_only_public_key()
                .serialize()
        {
            return Err(Error::Construction(
                "NestedMuSig2 tweak differs from the BIP341 output key".to_owned(),
            ));
        }
        Ok(derived)
    }

    pub fn script_pubkey(&self) -> Result<ScriptBuf> {
        Ok(ScriptBuf::new_p2tr_tweaked(self.spend_info()?.output_key()))
    }

    pub fn control_block(&self) -> Result<ControlBlock> {
        self.spend_info()?
            .control_block(&(self.sweep_leaf(), LeafVersion::TapScript))
            .ok_or(Error::TaprootIncomplete)
    }
}

pub fn key_path_script(key: XOnlyPublicKey) -> ScriptBuf {
    ScriptBuf::new_p2tr(SECP256K1, key, None)
}

pub fn key_path_address(key: XOnlyPublicKey, network: Network) -> Address {
    Address::p2tr(SECP256K1, key, None, network)
}

pub fn leaf_hash(script: &ScriptBuf) -> TapLeafHash {
    TapLeafHash::from_script(script, LeafVersion::TapScript)
}

pub fn tweaked_key(bytes: [u8; 32]) -> Result<TweakedPublicKey> {
    Ok(TweakedPublicKey::dangerous_assume_tweaked(
        XOnlyPublicKey::from_slice(&bytes)?,
    ))
}
