//! Utilities that help with testing the transaction builder and related objects

use crate::{EmptyMemoBuilder, InputCredentials, MemoPayload, TransactionBuilder, TxBuilderError};
use core::convert::TryFrom;
use mc_account_keys::{AccountKey, PublicAddress, DEFAULT_SUBADDRESS_INDEX};
use mc_crypto_keys::RistrettoPublic;
use mc_fog_report_validation_test_utils::FogPubkeyResolver;
use mc_transaction_core::{
    onetime_keys::*,
    tokens::Mob,
    tx::{Tx, TxOut, TxOutMembershipProof},
    Amount, BlockVersion, Token, TokenId,
};
use rand::{CryptoRng, RngCore};

/// Creates a TxOut that sends `value` to `recipient`.
///
/// Note: This is only used in test code
///
/// # Arguments
/// * `value` - Value of the output, in picoMOB.
/// * `recipient` - Recipient's address.
/// * `fog_resolver` - Set of prefetched fog public keys to choose from
/// * `rng` - Entropy for the encryption.
///
/// # Returns
/// * A transaction output, and the shared secret for this TxOut.
pub fn create_output<RNG: CryptoRng + RngCore, FPR: FogPubkeyResolver>(
    block_version: BlockVersion,
    amount: Amount,
    recipient: &PublicAddress,
    fog_resolver: &FPR,
    rng: &mut RNG,
) -> Result<(TxOut, RistrettoPublic), TxBuilderError> {
    let (hint, _pubkey_expiry) =
        crate::transaction_builder::create_fog_hint(recipient, fog_resolver, rng)?;
    crate::transaction_builder::create_output_with_fog_hint(
        block_version,
        amount,
        recipient,
        hint,
        |_| {
            Ok(if block_version.e_memo_feature_is_supported() {
                Some(MemoPayload::default())
            } else {
                None
            })
        },
        rng,
    )
}

/// Creates a ring of of TxOuts.
///
/// # Arguments
/// * `block_version` - The block version for the TxOut's
/// * `token_id` - The token id for the real element
/// * `ring_size` - Number of elements in the ring.
/// * `account` - Owner of one of the ring elements.
/// * `value` - Value of the real element.
/// * `fog_resolver` - Fog public keys
/// * `rng` - Randomness.
///
/// Returns (ring, real_index)
pub fn get_ring<RNG: CryptoRng + RngCore, FPR: FogPubkeyResolver>(
    block_version: BlockVersion,
    amount: Amount,
    ring_size: usize,
    account: &AccountKey,
    fog_resolver: &FPR,
    rng: &mut RNG,
) -> (Vec<TxOut>, usize) {
    let mut ring: Vec<TxOut> = Vec::new();

    // Create ring_size - 1 mixins with assorted token ids
    for idx in 0..ring_size - 1 {
        let address = AccountKey::random(rng).default_subaddress();
        let token_id = if block_version.masked_token_id_feature_is_supported() {
            TokenId::from(idx as u64)
        } else {
            Mob::ID
        };
        let amount = Amount {
            value: amount.value,
            token_id,
        };
        let (tx_out, _) =
            create_output(block_version, amount, &address, fog_resolver, rng).unwrap();
        ring.push(tx_out);
    }

    // Insert the real element.
    let real_index = (rng.next_u64() % ring_size as u64) as usize;
    let (tx_out, _) = create_output(
        block_version,
        amount,
        &account.default_subaddress(),
        fog_resolver,
        rng,
    )
    .unwrap();
    ring.insert(real_index, tx_out);
    assert_eq!(ring.len(), ring_size);

    (ring, real_index)
}

/// Creates an `InputCredentials` for an account.
///
/// # Arguments
/// * `block_version` - Block version to use for the tx outs
/// * `token_id` - Token id for the real element
/// * `account` - Owner of one of the ring elements.
/// * `value` - Value of the real element.
/// * `fog_resolver` - Fog public keys
/// * `rng` - Randomness.
///
/// Returns (input_credentials)
pub fn get_input_credentials<RNG: CryptoRng + RngCore, FPR: FogPubkeyResolver>(
    block_version: BlockVersion,
    amount: Amount,
    account: &AccountKey,
    fog_resolver: &FPR,
    rng: &mut RNG,
) -> InputCredentials {
    let (ring, real_index) = get_ring(block_version, amount, 3, account, fog_resolver, rng);
    let real_output = ring[real_index].clone();

    let onetime_private_key = recover_onetime_private_key(
        &RistrettoPublic::try_from(&real_output.public_key).unwrap(),
        account.view_private_key(),
        &account.subaddress_spend_private(DEFAULT_SUBADDRESS_INDEX),
    );

    let membership_proofs: Vec<TxOutMembershipProof> = ring
        .iter()
        .map(|_tx_out| {
            // TransactionBuilder does not validate membership proofs, but does require one
            // for each ring member.
            TxOutMembershipProof::default()
        })
        .collect();

    InputCredentials::new(
        ring,
        membership_proofs,
        real_index,
        onetime_private_key,
        *account.view_private_key(),
    )
    .unwrap()
}

// Uses TransactionBuilder to build a transaction.
pub fn get_transaction<RNG: RngCore + CryptoRng, FPR: FogPubkeyResolver + Clone>(
    block_version: BlockVersion,
    token_id: TokenId,
    num_inputs: usize,
    num_outputs: usize,
    sender: &AccountKey,
    recipient: &AccountKey,
    fog_resolver: FPR,
    rng: &mut RNG,
) -> Result<Tx, TxBuilderError> {
    let mut transaction_builder = TransactionBuilder::new(
        block_version,
        Amount::new(Mob::MINIMUM_FEE, token_id),
        fog_resolver.clone(),
        EmptyMemoBuilder::default(),
    )
    .unwrap();
    let input_value = 1000;
    let output_value = 10;

    // Inputs
    for _i in 0..num_inputs {
        let input_credentials = get_input_credentials(
            block_version,
            Amount {
                value: input_value,
                token_id,
            },
            sender,
            &fog_resolver,
            rng,
        );
        transaction_builder.add_input(input_credentials);
    }

    // Outputs
    for _i in 0..num_outputs {
        transaction_builder
            .add_output(
                Amount::new(output_value, token_id),
                &recipient.default_subaddress(),
                rng,
            )
            .unwrap();
    }

    // Set the fee so that sum(inputs) = sum(outputs) + fee.
    let fee = num_inputs as u64 * input_value - num_outputs as u64 * output_value;
    transaction_builder.set_fee(fee).unwrap();

    transaction_builder.build(rng)
}
