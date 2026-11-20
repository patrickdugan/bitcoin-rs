use bitcoin::Witness;
use bitcoin_rs_ark_nested_musig2::codec::CodecError;
use bitcoin_rs_ark_nested_musig2::keys::KeyNetwork;
use bitcoin_rs_ark_nested_musig2::policy::Shape;
use bitcoin_rs_ark_nested_musig2::statement::{ArkTransitionV1, check_statement, nova_witness};

use super::support::{TestError, round};

#[test]
fn canonical_encoding_round_trips_and_rejects_variants() -> Result<(), TestError> {
    let statement = round(4, Shape::Nested)?.statement;
    let bytes = statement.encode()?;
    assert_eq!(ArkTransitionV1::decode(&bytes)?, statement);
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert_eq!(
        ArkTransitionV1::decode(&trailing),
        Err(CodecError::Trailing { remaining: 1 })
    );
    let mut version = bytes.clone();
    version[8] = 2;
    assert_eq!(ArkTransitionV1::decode(&version), Err(CodecError::Version));
    let mut network = bytes.clone();
    network[10] = 9;
    assert_eq!(
        ArkTransitionV1::decode(&network),
        Err(CodecError::UnknownCode("network"))
    );
    assert!(ArkTransitionV1::decode(&bytes[..bytes.len() - 1]).is_err());
    let mut signed = statement.clone();
    signed.commitment.input[0].witness = Witness::from_slice(&[[1_u8; 64]]);
    assert_eq!(signed.encode(), Err(CodecError::Transaction));
    Ok(())
}

#[test]
fn digest_binds_network_round_and_outputs() -> Result<(), TestError> {
    let statement = round(4, Shape::Nested)?.statement;
    let digest = statement.digest()?;
    let mut other_network = statement.clone();
    other_network.network = KeyNetwork::Testnet4;
    let mut other_round = statement.clone();
    other_round.round += 1;
    let mut other_output = statement.clone();
    other_output.tree[1].tx.output[0].value = bitcoin::Amount::from_sat(1);
    for variant in [other_network, other_round, other_output] {
        assert_ne!(variant.digest()?, digest);
    }
    Ok(())
}

#[test]
fn native_checker_accepts_the_round_and_rejects_value_creation() -> Result<(), TestError> {
    let statement = round(4, Shape::Nested)?.statement;
    assert!(check_statement(&statement, &[])?.accepted);
    let mut inflated = statement.clone();
    let output = &mut inflated.tree[0].tx.output[0];
    output.value = bitcoin::Amount::from_sat(output.value.to_sat() + 1_000_000);
    let report = check_statement(&inflated, &[])?;
    assert!(!report.accepted);
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.rule == "value-conservation" && !f.ok)
    );
    Ok(())
}

#[test]
fn nova_witness_conserves_value_per_transaction() -> Result<(), TestError> {
    let statement = round(16, Shape::Nested)?.statement;
    let witness = nova_witness(&statement)?;
    let transactions = 1 + statement.tree.len();
    assert_eq!(
        witness.expect.tx_count,
        u64::try_from(transactions).unwrap_or(0)
    );
    assert_eq!(
        witness.expect.sum_in_sat,
        witness.expect.sum_out_sat + witness.expect.sum_fee_sat
    );
    Ok(())
}
