// Copyright (c) 2022 The MobileCoin Foundation

//! Input rules, described in MCIP #31, specify any additional criteria that the
//! Tx must satisfy to be valid.
//!
//! Input rules make sense when a Tx is built collaboratively, with some inputs
//! coming from some parties, and some inputs come from others. They give
//! participants a way to make their signature contingent on certain rules being
//! followed, to facilitate trustless interactions.

use crate::{
    try_reveal_amount,
    tx::{Tx, TxOut},
    BlockVersion, RevealedTxOut, RevealedTxOutError,
};
use alloc::vec::Vec;
use displaydoc::Display;
use mc_crypto_digestible::Digestible;
use prost::Message;
use serde::{Deserialize, Serialize};

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

    /// Outputs required to appear in the TxPrefix, but which are permitted to
    /// be filled partially instead of fully, according to the "fill
    /// fraction" which is inferred using the "partial fill change" output
    /// (MCIP #42)
    #[prost(message, repeated, tag = "3")]
    pub partial_fill_outputs: Vec<RevealedTxOut>,

    /// A change output for any leftover from this input, which may occur during
    /// a partial fill (MCIP #42).
    ///
    /// This field must be present whenever partial fills are used, because the
    /// comparison of this "idealized" output and the corresponding "fractional"
    /// change which appears in the TxPrefix is what determines the "fill
    /// fraction", that is, the degree to which a counterparty is obliged to
    /// fill every partial fill output in these rules.
    ///
    /// It is an error to use any of the partial fill options without also
    /// setting this.
    #[prost(message, tag = "4")]
    pub partial_fill_change: Option<RevealedTxOut>,

    /// A minimum fill value for the partial fill rules. (MCIP #42)
    /// A counterparty who fills an SCI must keep at least this much of the
    /// offer and can't return all of it as change if this is set.
    /// This can be used to prevent griefing where someone fills your offer in
    /// exchange for dust.
    /// This minimum has no effect if set to 0.
    #[prost(fixed64, tag = "5")]
    pub min_partial_fill_value: u64,
}

impl InputRules {
    /// Verify that a Tx conforms to the rules.
    pub fn verify(&self, block_version: BlockVersion, tx: &Tx) -> Result<(), InputRuleError> {
        // NOTE: If this function gets too busy, we should split it up
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

        self.verify_partial_fill_rules(block_version, tx)?;

        Ok(())
    }

    // Partial-Fill rules verification (MCIP #42)
    fn verify_partial_fill_rules(
        &self,
        _block_version: BlockVersion,
        tx: &Tx,
    ) -> Result<(), InputRuleError> {
        if let Some(partial_fill_change) = self.partial_fill_change.as_ref() {
            // There is a partial fill change output. Let's try to unblind its amount.
            let (partial_fill_change_amount, _) = partial_fill_change.reveal_amount()?;
            // If the min fill value exceeds the fractional change, then the SCI is
            // ill-formed
            if partial_fill_change_amount.value < self.min_partial_fill_value {
                return Err(InputRuleError::MinPartialFillValueExceedsPartialFillChange);
            }

            // Let's check if there is a corresponding fractional change output.
            let fractional_change = tx
                .prefix
                .outputs
                .iter()
                .find(|x| partial_fill_change.tx_out.eq_ignoring_amount(x))
                .ok_or(InputRuleError::MissingFractionalChangeOutput)?;
            // Let's try to unblind its amount.
            let (fractional_change_amount, _) = try_reveal_amount(
                fractional_change,
                partial_fill_change.amount_shared_secret.as_ref(),
            )?;

            // Check the token id and bounds of the real change amount
            if fractional_change_amount.token_id != partial_fill_change_amount.token_id {
                return Err(InputRuleError::FractionalOutputTokenIdMismatch);
            }
            // Partial fill change amount - min fill value is an upper bound on how much
            // can be returned in the fractional change output.
            if fractional_change_amount.value
                > partial_fill_change_amount.value - self.min_partial_fill_value
            {
                return Err(InputRuleError::FractionalChangeOutputAmountExceedsLimit);
            }

            // Compute fill-fraction num and denom. This is the fraction of the maximum
            // possible trade that could have occurred which did occur. This
            // calculation is used later when checking if real output amounts respected the
            // fill fraction.
            let fill_fraction_num =
                (partial_fill_change_amount.value - fractional_change_amount.value) as u128;
            let fill_fraction_denom = partial_fill_change_amount.value as u128;

            // Verify partial_fill_outputs
            for partial_fill_output in self.partial_fill_outputs.iter() {
                // Try to unblind the partial fill output amount.
                let (partial_fill_output_amount, _) = partial_fill_output.reveal_amount()?;
                // Let's check if there is a corresponding fractional output.
                let fractional_output = tx
                    .prefix
                    .outputs
                    .iter()
                    .find(|x| partial_fill_output.tx_out.eq_ignoring_amount(x))
                    .ok_or(InputRuleError::MissingFractionalOutput)?;
                // Let's try to unblind its amount, using amount shared secret from the
                // fractional output (which should be the same)
                let (fractional_output_amount, _) = try_reveal_amount(
                    fractional_output,
                    partial_fill_output.amount_shared_secret.as_ref(),
                )?;

                // Check the token id of the real amount
                // (Note, we don't have to check if the real output amount exceeds fractional
                // output amount, because as long as the real output is at least
                // fill fraction times fractional amount, the originator is happy.)
                if fractional_output_amount.token_id != partial_fill_output_amount.token_id {
                    return Err(InputRuleError::FractionalOutputTokenIdMismatch);
                }

                // Check that the fill fraction is respected.
                // Intuitively, what we are doing is checking that:
                //
                // fractional_output_value >= n/d * partial_fill_output_value,
                //
                // where n/d is the fill fraction. The fill fraction is 1 if
                // fractional_change_amount = 0, and proportionally less as more of
                // the input is returned as change.
                // However, to avoid numerical issues, we multiply this out and
                // verify this as a comparison of u128 values:
                //
                // fractional_output_value * d >= n * partial_fill_output_value
                //
                // Note: I am not sure if u128 comparison lowers to constant time assembly
                // in x86-64, but I don't think it matters, because for a well-formed
                // client this check will always pass. This error condition will only
                // occur if the client made an arithmetic mistake. So this can't lead
                // to an information leak if a well-formed client builds the Tx.
                if (fractional_output_amount.value as u128 * fill_fraction_denom)
                    < (partial_fill_output_amount.value as u128 * fill_fraction_num)
                {
                    return Err(InputRuleError::FractionalOutputAmountDoesNotRespectFillFraction);
                }
            }
        } else {
            // If there is no partial fill change output specified, then none of the related
            // partial fill output rules or rule verification data should be present.
            if !self.partial_fill_outputs.is_empty() {
                return Err(InputRuleError::PartialFillOutputsNotExpected);
            }
            if self.min_partial_fill_value != 0 {
                return Err(InputRuleError::MinPartialFillValueNotExpected);
            }
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
    /// Partial fill outputs are not expected
    PartialFillOutputsNotExpected,
    /// Min partial fill value is not expected
    MinPartialFillValueNotExpected,
    /// Missing fractional change output corresponding to partial fill change
    MissingFractionalChangeOutput,
    /// Missing fractional output corresponding to partial fill output
    MissingFractionalOutput,
    /// Fractional output token id did not match fraction output token id
    FractionalOutputTokenIdMismatch,
    /// Min partial fill value exceeds partial fill change
    MinPartialFillValueExceedsPartialFillChange,
    /// Fractional output amount does not respect fill fraction
    FractionalOutputAmountDoesNotRespectFillFraction,
    /// Fractional change output exceeds limit
    FractionalChangeOutputAmountExceedsLimit,
    /// Revealed Tx Out: {0}
    RevealedTxOut(RevealedTxOutError),
}

impl From<RevealedTxOutError> for InputRuleError {
    fn from(src: RevealedTxOutError) -> Self {
        Self::RevealedTxOut(src)
    }
}
