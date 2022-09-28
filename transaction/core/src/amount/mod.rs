// Copyright (c) 2018-2022 The MobileCoin Foundation

//! A commitment to an output's amount, denominated in picoMOB.
//!
//! Amounts are implemented as Pedersen commitments. The associated private keys
//! are "masked" using a shared secret.

use crate::{Amount, BlockVersion, CompressedCommitment};
use mc_crypto_digestible::Digestible;
use mc_crypto_keys::RistrettoPublic;
use mc_crypto_ring_signature::Scalar;
use prost::Oneof;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

mod error;
pub use error::AmountError;

mod v1;
pub use v1::MaskedAmountV1;

mod v2;
pub use v2::MaskedAmountV2;

/// A masked amount in one of several possible versions
#[derive(Clone, Deserialize, Digestible, Eq, Hash, Oneof, PartialEq, Serialize, Zeroize)]
#[digestible(transparent)]
pub enum MaskedAmount {
    /// A v1 masked amount.
    /// Note: This tag must match the historical tag used for masked amounts
    #[prost(message, tag = "1")]
    V1(MaskedAmountV1),
    /// A v2 masked amount.
    /// Note: This tag must match what is listed in `tags` for the oneof field
    /// in TxOut
    #[prost(message, tag = "6")]
    V2(MaskedAmountV2),
}

impl MaskedAmount {
    /// Creates a commitment `value*H + blinding*G`, and "masks" the commitment
    /// secrets so that they can be recovered by the recipient.
    ///
    /// # Arguments
    /// * `block_version` - The block version rules we are targeting
    /// * `amount` - The amount information to be masked
    /// * `tx_out_shared_secret` - The shared secret, e.g. `rB` for transaction
    ///   private key `r` and recipient public key `B`.
    pub fn new(
        block_version: BlockVersion,
        amount: Amount,
        tx_out_shared_secret: &RistrettoPublic,
    ) -> Result<Self, AmountError> {
        Ok(if block_version.masked_amount_v2_is_supported() {
            Self::V2(MaskedAmountV2::new(amount, tx_out_shared_secret)?)
        } else {
            if !block_version.masked_token_id_feature_is_supported() && amount.token_id != 0 {
                return Err(AmountError::TokenIdNotSupportedAtBlockVersion);
            }
            let mut masked_amount = MaskedAmountV1::new(amount, tx_out_shared_secret)?;
            if !block_version.masked_token_id_feature_is_supported() {
                masked_amount.masked_token_id.clear();
            }
            Self::V1(masked_amount)
        })
    }

    /// Create a new masked amount from an amount and an amount shared secret.
    /// This only works if at least masked amount v2 is supported.
    ///
    /// # Arguments
    /// * `block_version` - The block version rules we are targeting
    /// * `amount` - The amount information to be masked
    /// * `amount_shared_secret` - The amount shared secret to derive blinding
    ///   factors from
    pub fn new_from_amount_shared_secret(
        block_version: BlockVersion,
        amount: Amount,
        amount_shared_secret: &[u8; 32],
    ) -> Result<Self, AmountError> {
        if block_version.masked_amount_v2_is_supported() {
            Ok(Self::V2(MaskedAmountV2::new_from_amount_shared_secret(
                amount,
                amount_shared_secret,
            )?))
        } else {
            Err(AmountError::AmountVersionTooOldForAmountSharedSecret)
        }
    }

    /// Returns the amount underlying the masked amount, given the shared
    /// secret.
    ///
    /// Value is denominated in picoMOB.
    ///
    /// # Arguments
    /// * `tx_out_shared_secret` - The shared secret, e.g. `rB`.
    pub fn get_value(
        &self,
        tx_out_shared_secret: &RistrettoPublic,
    ) -> Result<(Amount, Scalar), AmountError> {
        match &self {
            Self::V1(masked_amount) => masked_amount.get_value(tx_out_shared_secret),
            Self::V2(masked_amount) => masked_amount.get_value(tx_out_shared_secret),
        }
    }

    /// Returns the amount underlying the masked amount, given the amount shared
    /// secret. This only works at v2 and up.
    pub fn get_value_from_amount_shared_secret(
        &self,
        amount_shared_secret: &[u8; 32],
    ) -> Result<(Amount, Scalar), AmountError> {
        match &self {
            Self::V1(_) => Err(AmountError::AmountVersionTooOldForAmountSharedSecret),
            Self::V2(masked_amount) => {
                masked_amount.get_value_from_amount_shared_secret(amount_shared_secret)
            }
        }
    }

    /// Compute the amount shared secret from a TxOut shared secret, assuming
    /// that we are using the masked amount version appropriate for a given
    /// block version
    ///
    /// If a masked amount v3 is added then we need to select for its block
    /// version here
    pub fn compute_amount_shared_secret(
        block_version: BlockVersion,
        tx_out_shared_secret: &RistrettoPublic,
    ) -> Result<[u8; 32], AmountError> {
        if block_version.masked_amount_v2_is_supported() {
            Ok(MaskedAmountV2::compute_amount_shared_secret(
                tx_out_shared_secret,
            ))
        } else {
            Err(AmountError::AmountVersionTooOldForAmountSharedSecret)
        }
    }

    /// Get the masked value field
    pub fn get_masked_value(&self) -> &u64 {
        match self {
            Self::V1(masked_amount) => &masked_amount.masked_value,
            Self::V2(masked_amount) => &masked_amount.masked_value,
        }
    }

    /// Get the masked value field
    pub fn get_masked_value_mut(&mut self) -> &mut u64 {
        match self {
            Self::V1(masked_amount) => &mut masked_amount.masked_value,
            Self::V2(masked_amount) => &mut masked_amount.masked_value,
        }
    }

    /// Get the masked token id field
    pub fn masked_token_id(&self) -> &[u8] {
        match self {
            Self::V1(masked_amount) => &masked_amount.masked_token_id,
            Self::V2(masked_amount) => &masked_amount.masked_token_id,
        }
    }

    /// Get the compressed commtiment field
    pub fn commitment(&self) -> &CompressedCommitment {
        match self {
            Self::V1(masked_amount) => &masked_amount.commitment,
            Self::V2(masked_amount) => &masked_amount.commitment,
        }
    }

    /// Compute the crc32 of the compressed commitment
    pub fn commitment_crc32(&self) -> u32 {
        match &self {
            Self::V1(masked_amount) => masked_amount.commitment_crc32(),
            Self::V2(masked_amount) => masked_amount.commitment_crc32(),
        }
    }

    /// Recovers a V1 Amount from only the masked value and masked_token_id, and
    /// shared secret.
    ///
    /// Note: This fails and produces gibberish if the shared secret is wrong.
    ///
    /// * You should confirm by checking against the real commitment, or the the
    ///   crc32 of commitment.
    ///
    /// Arguments:
    /// * masked_value: u64
    /// * masked_token_id: &[u8], either 0 or 4 bytes
    /// * shared_secret: The shared secret curve point
    ///
    /// Returns:
    /// * MaskedAmount
    /// * Amount (token id and value)
    /// or
    /// * An amount error
    pub fn reconstruct_v1(
        masked_value: u64,
        masked_token_id: &[u8],
        shared_secret: &RistrettoPublic,
    ) -> Result<(Self, Amount), AmountError> {
        let (result, amount) =
            MaskedAmountV1::reconstruct(masked_value, masked_token_id, shared_secret)?;
        Ok((Self::V1(result), amount))
    }

    /// Recovers a V2 Amount from only the masked value and masked_token_id, and
    /// shared secret.
    ///
    /// Note: This fails and produces gibberish if the shared secret is wrong.
    ///
    /// * You should confirm by checking against the real commitment, or the the
    ///   crc32 of commitment.
    ///
    /// Arguments:
    /// * masked_value: u64
    /// * masked_token_id: &[u8], either 0 or 4 bytes
    /// * shared_secret: The shared secret curve point
    ///
    /// Returns:
    /// * MaskedAmount
    /// * Amount (token id and value)
    /// or
    /// * An amount error
    pub fn reconstruct_v2(
        masked_value: u64,
        masked_token_id: &[u8],
        shared_secret: &RistrettoPublic,
    ) -> Result<(Self, Amount), AmountError> {
        let (result, amount) =
            MaskedAmountV2::reconstruct(masked_value, masked_token_id, shared_secret)?;
        Ok((Self::V2(result), amount))
    }
}
