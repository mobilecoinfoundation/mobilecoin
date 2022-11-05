// Copyright (c) 2018-2022 The MobileCoin Foundation

//! MobileCoin transaction data types, transaction construction and validation
//! routines

#![no_std]
#![deny(missing_docs)]

extern crate alloc;

#[cfg(test)]
#[macro_use]
extern crate std;

#[macro_use]
extern crate lazy_static;

mod amount;
mod domain_separators;
mod fee_map;
mod input_rules;
mod memo;
mod revealed_tx_out;
mod token;
mod tx_error;

pub mod constants;
pub mod encrypted_fog_hint;
pub mod fog_hint;
pub mod membership_proofs;
pub mod mint;
pub mod range_proofs;
pub mod ring_ct;
pub mod tx;
pub mod tx_summary;
pub mod validation;

#[cfg(test)]
pub mod proptest_fixtures;

pub use amount::{AmountError, MaskedAmount, MaskedAmountV1, MaskedAmountV2};
pub use fee_map::{Error as FeeMapError, FeeMap, SMALLEST_MINIMUM_FEE_LOG2};
pub use input_rules::{InputRuleError, InputRules};
pub use memo::{EncryptedMemo, MemoError, MemoPayload};
pub use revealed_tx_out::{try_reveal_amount, RevealedTxOut, RevealedTxOutError};
pub use token::{tokens, Token};
pub use tx::MemoContext;
pub use tx_error::{NewMemoError, NewTxError, TxOutConversionError, ViewKeyMatchError};
pub use tx_summary::{TxInSummary, TxOutSummary, TxSummary};

// Re-export from transaction-types, and some from RingSignature crate.
pub use mc_crypto_ring_signature::{Commitment, CompressedCommitment};
pub use mc_transaction_types::*;

/// Re-export all of mc-crypto-ring-signature
pub mod ring_signature {
    pub use mc_crypto_ring_signature::*;
}

// Re-export the one-time keys module which historically lived in this crate
pub use mc_crypto_ring_signature::onetime_keys;

// Re-export some dependent types from mc-account-keys
pub use mc_account_keys::{AccountKey, PublicAddress};

use mc_crypto_keys::{KeyError, RistrettoPrivate, RistrettoPublic};
use onetime_keys::{create_shared_secret, recover_public_subaddress_spend_key};
use tx::TxOut;

/// Get the shared secret for a transaction output.
///
/// # Arguments
/// * `view_key` - The recipient's private View key.
/// * `tx_public_key` - The public key of the transaction.
pub fn get_tx_out_shared_secret(
    view_key: &RistrettoPrivate,
    tx_public_key: &RistrettoPublic,
) -> RistrettoPublic {
    create_shared_secret(tx_public_key, view_key)
}

/// Helper which checks if a particular subaddress of an account key matches a
/// TxOut
///
/// This is not the most efficient way to check when you have many subaddresses,
/// for that you should create a table and use
/// recover_public_subaddress_spend_key directly.
///
/// However some clients are only using one or two subaddresses.
/// Validating that a TxOut is owned by the change subaddress is a frequently
/// needed operation.
pub fn subaddress_matches_tx_out(
    acct: &AccountKey,
    subaddress_index: u64,
    output: &TxOut,
) -> Result<bool, KeyError> {
    let sub_addr_spend = recover_public_subaddress_spend_key(
        acct.view_private_key(),
        &RistrettoPublic::try_from(&output.target_key)?,
        &RistrettoPublic::try_from(&output.public_key)?,
    );
    Ok(sub_addr_spend == RistrettoPublic::from(&acct.subaddress_spend_private(subaddress_index)))
}
