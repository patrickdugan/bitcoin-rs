//! Regtest-only activation of BIP 448 (BIP 446 `OP_TEMPLATEHASH`, BIP 348
//! `OP_CHECKSIGFROMSTACK`, BIP 349 `OP_INTERNALKEY`).
//!
//! The opcodes are defined by the script interpreter's `BIP448` verify flag.
//! On regtest the node turns that flag on for every tapscript it evaluates, in
//! block validation and in mempool admission alike. Every other network keeps
//! the three bytes as `OP_SUCCESS`.

use bitcoin_rs_primitives::Network;

/// Refusal to activate BIP 448 outside regtest.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("BIP 448 activation is limited to regtest, not {network:?}")]
pub struct Bip448ActivationError {
    pub network: Network,
}

/// Enables BIP 448 for this process. Call once at start-up, before any block
/// or transaction is validated.
pub fn activate_bip448(network: Network) -> Result<(), Bip448ActivationError> {
    if network != Network::Regtest {
        return Err(Bip448ActivationError { network });
    }
    bitcoin_rs_script::set_regtest_activation(true);
    Ok(())
}

#[cfg(test)]
mod tests {
    use bitcoin_rs_primitives::Network;

    use super::{Bip448ActivationError, activate_bip448};

    #[test]
    fn only_regtest_may_activate() {
        for network in [Network::Mainnet, Network::Testnet3, Network::Testnet4, Network::Signet] {
            assert_eq!(
                activate_bip448(network),
                Err(Bip448ActivationError { network })
            );
            assert!(!bitcoin_rs_script::regtest_activation());
        }
        assert_eq!(activate_bip448(Network::Regtest), Ok(()));
        assert!(bitcoin_rs_script::regtest_activation());
        bitcoin_rs_script::set_regtest_activation(false);
    }
}
