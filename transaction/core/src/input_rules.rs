// Copyright (c) 2022 The MobileCoin Foundation

//! Input rules, described in MCIP #31, specify any additional criteria that the
//! Tx must satisfy to be valid.
//!
//! Input rules make sense when a Tx is built collaboratively, with some inputs
//! coming from some parties, and some inputs come from others. They give
//! participants a way to make their signature contingent on certain rules being
//! followed, to facilitate trustless interactions.

use crate::{
    tx::{Tx, TxOut},
    BlockVersion, TxOutConversionError, AmountError, Amount
};
use alloc::vec::Vec;
use displaydoc::Display;
use mc_crypto_digestible::Digestible;
use prost::Message;
use serde::{Deserialize, Serialize};

/// A TxOut together with its amount shared secret, which can be used to reveal
/// the amount and token id and check them against the commitment data
#[derive(Clone, Digestible, PartialEq, Eq, Message, Serialize, Deserialize)]
pub struct RevealedTxOut {
    /// The TxOut which is being revealed
    #[prost(message, required, tag = "1")]
    pub tx_out: TxOut,

    /// The amount shared secret of this TxOut
    #[prost(bytes, tag = "2")]
    pub amount_shared_secret: Vec<u8>,
}    

impl RevealedTxOut {
    /// Attempt to reveal the amount of this RevealedTxOut
    pub fn reveal_amount(&self) -> Result<Amount, InputRuleError> {
        try_reveal_amount(&self.tx_out, self.amount_shared_secret.as_ref())
    }
}

// Helper function which tries to reveal the amount of a TxOut given its shared secret,
// and confirm this against the commitment data
fn try_reveal_amount(tx_out: &TxOut, amount_shared_secret: &[u8]) -> Result<Amount, InputRuleError> {
    let ss: &[u8; 32] = amount_shared_secret.try_into().map_err(|_| InputRuleError::InvalidAmountSharedSecret)?;
    let (amount, _) = tx_out.get_masked_amount()?.get_value_from_amount_shared_secret(ss)?;
    Ok(amount)
}

/// A representation of rules on a transaction, imposed by the signer of some
/// input in the transaction.
///
/// Any rule could conceivably be added here if it can be evaluated against a
/// `Tx`.
#[derive(Clone, Digestible, PartialEq, Eq, Message, Serialize, Deserialize)]
pub struct InputRules {
    /// Outputs that are required to appear in the Tx prefix for the transaction
    /// to be valid
    #[prost(message, repeated, tag = "1")]
    pub required_outputs: Vec<TxOut>,

    /// An upper bound on the tombstone block which must be respected for the
    /// transaction to be valid
    #[prost(fixed64, tag = "2")]
    pub max_tombstone_block: u64,

    /// Outputs permitted to be filled fractionally instead of fully (MCIP #42)
    #[prost(message, repeated, tag = "3")]
    pub fractional_outputs: Vec<RevealedTxOut>,

    /// A change output for any leftover from this input, if a fractional fill occurs (MCIP #42)
    #[prost(message, tag = "4")]
    pub fractional_change: Option<RevealedTxOut>,

    /// A maximum allowed value for the real change output. (MCIP #42)
    /// This can be used to impose a minimum traded amount on the counterparty to an SCI.
    /// This limit is ignored if set to zero.
    #[prost(fixed64, tag = "5")]
    pub max_allowed_change_value: u64,
}

/// Additional witness data which may help verify that input rules were followed. (MCIP #42)
#[derive(Clone, Digestible, PartialEq, Eq, Message, Serialize, Deserialize)]
pub struct InputRuleVerificationData {
    /// Outputs that are required to appear in the Tx prefix for the transaction
    /// to be valid
    #[prost(bytes, repeated, tag = "1")]
    pub real_output_amount_shared_secrets: Vec<Vec<u8>>,

    /// An upper bound on the tombstone block which must be respected for the
    /// transaction to be valid
    #[prost(bytes, tag = "2")]
    pub real_change_output_amount_shared_secret: Vec<u8>,
}

impl InputRules {
    /// Verify that a Tx conforms to the rules.
    pub fn verify(&self, _block_version: BlockVersion, tx: &Tx, verification_data: &InputRuleVerificationData) -> Result<(), InputRuleError> {
        // NOTE: If this function gets too busy, we should split it into several functions
        // NOTE: The tests for this function are in
        // transaction/core/tests/input_rules.rs

        // Verify max_tombstone_block
        if self.max_tombstone_block != 0 && tx.prefix.tombstone_block > self.max_tombstone_block {
            return Err(InputRuleError::MaxTombstoneBlockExceeded);
        }
        // Verify required_outputs
        for required_output in self.required_outputs.iter() {
            if !tx.prefix.outputs.iter().any(|x| x == required_output) {
                return Err(InputRuleError::MissingRequiredOutput);
            }
        }
        // Partial-Fill rules verification (MCIP #42)
        if let Some(fractional_change) = self.fractional_change.as_ref() {
            // There is a fractional change output. Let's try to unblind its amount.
            let fractional_change_amount = fractional_change.reveal_amount()?;
            // Let's check if there is a corresponding real change output.
            let real_change = tx.prefix.outputs.iter().find(|x| x.public_key == fractional_change.tx_out.public_key).ok_or(InputRuleError::MissingRealChangeOutput)?;
            // Let's try to unblind its amount.
            let real_change_amount = try_reveal_amount(real_change, verification_data.real_change_output_amount_shared_secret.as_ref())?;

            // Check the bounds of the real change amount
            if real_change_amount.token_id != fractional_change_amount.token_id {
                return Err(InputRuleError::RealOutputTokenIdMismatch);
            }
            if real_change_amount.value > fractional_change_amount.value {
                return Err(InputRuleError::RealOutputAmountExceedsFractional);
            }
            if self.max_allowed_change_value != 0 && real_change_amount.value > self.max_allowed_change_value {
                return Err(InputRuleError::RealChangeOutputAmountExceedsLimit);
            }

            // Compute fill-fraction num and denom. This is the fraction of the maximum possible trade that could have occurred
            // which did occur. This calculation is used later when checking if real output amounts respected the fill fraction.
            let fill_fraction_num = (fractional_change_amount.value - real_change_amount.value) as u128;
            let fill_fraction_denom = fractional_change_amount.value as u128;

            // Verify fractional_outputs
            if self.fractional_outputs.len() != verification_data.real_output_amount_shared_secrets.len() {
                return Err(InputRuleError::WrongNumberOfAmountSharedSecrets);
            }
            for fractional_output in self.fractional_outputs.iter() {
                // Try to unblind the fractional output amount.
                let fractional_output_amount = fractional_output.reveal_amount()?;
                // Let's check if there is a corresponding real output.
                let (idx, real_output) = tx.prefix.outputs.iter().enumerate().find(|(_idx, x)| x.public_key == fractional_change.tx_out.public_key).ok_or(InputRuleError::MissingRealOutput)?;
                // Let's try to unblind its amount.
                let real_output_amount = try_reveal_amount(real_output, verification_data.real_output_amount_shared_secrets[idx].as_ref())?;

                // Check the bounds of the real change amount
                if real_output_amount.token_id != fractional_output_amount.token_id {
                    return Err(InputRuleError::RealOutputTokenIdMismatch);
                }
                if real_output_amount.value > fractional_output_amount.value {
                    return Err(InputRuleError::RealOutputAmountExceedsFractional);
                }

                // Check that the fill fraction is respected.
                // Intuitively, what we are doing is checking that:
                //
                // real_output_value >= n/d * fractional_output_value,
                //
                // where n/d is the fill fraction. The fill fraction is 1 if
                // real_change_amount = 0, and proportionally less as more of
                // the input is returned as change.
                // However, to avoid numerical issues, we multiply this out and
                // verify this as a comparison of u128 values:
                //
                // real_output_value * d >= n * fractional_output_value
                if (real_output_amount.value as u128 * fill_fraction_denom) < (fractional_output_amount.value as u128 * fill_fraction_num) {
                    return Err(InputRuleError::RealOutputAmountDoesNotRespectFillFraction);
                }
            }
        } else {
            // If there is no fractional change output specified, then none of the related fractional output rules or rule verification data should be present.
            if !self.fractional_outputs.is_empty() { return Err(InputRuleError::FractionalOutputsNotExpected); }
            if self.max_allowed_change_value != 0 { return Err(InputRuleError::MaxAllowedChangeValueNotExpected); }
            if !verification_data.real_output_amount_shared_secrets.is_empty() { return Err(InputRuleError::WrongNumberOfAmountSharedSecrets); }
            if !verification_data.real_change_output_amount_shared_secret.is_empty() { return Err(InputRuleError::ChangeOutputSharedSecretNotExpected); }
        }

        Ok(())
    }
}

/// An error that occurs when checking input rules
#[derive(Clone, Debug, Display, Ord, PartialOrd, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub enum InputRuleError {
    /// The transaction is missing a required output
    MissingRequiredOutput,
    /// The tombstone block exceeds the limit
    MaxTombstoneBlockExceeded,
    /// Fractional outputs are not expected
    FractionalOutputsNotExpected,
    /// Change output shared secret is not expected
    ChangeOutputSharedSecretNotExpected,
    /// Max allowed change value is not expected
    MaxAllowedChangeValueNotExpected,
    /// Missing real change output corresponding to fractional change
    MissingRealChangeOutput,
    /// Missing change output shared secret
    MissingChangeOutputSharedSecret,
    /// There are the wrong number of amount shared secrets
    WrongNumberOfAmountSharedSecrets,
    /// Missing real output corresponding to fractional output
    MissingRealOutput,
    /// Real output token id did not match fraction output token id
    RealOutputTokenIdMismatch,
    /// Real output amount exceeds corresponding fractional output amount
    RealOutputAmountExceedsFractional,
    /// Real output amount does not respect fill fraction
    RealOutputAmountDoesNotRespectFillFraction,
    /// Real change output exceeds limit
    RealChangeOutputAmountExceedsLimit,
    /// The amount shared secret has the incorrect length
    InvalidAmountSharedSecret,
    /// TxOut conversion: {0}
    TxOutConversion(TxOutConversionError),
    /// Amount: {0}
    Amount(AmountError),
}

impl From<TxOutConversionError> for InputRuleError {
    fn from(src: TxOutConversionError) -> Self {
        Self::TxOutConversion(src)
    }
}

impl From<AmountError> for InputRuleError {
    fn from(src: AmountError) -> Self {
        Self::Amount(src)
    }
}
