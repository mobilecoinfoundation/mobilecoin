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
    BlockVersion,
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
}

impl InputRules {
    /// Verify that a Tx conforms to the rules.
    pub fn verify(&self, _block_version: BlockVersion, tx: &Tx) -> Result<(), InputRuleError> {
        // Verify required_outputs
        for required_output in self.required_outputs.iter() {
            if tx
                .prefix
                .outputs
                .iter()
                .find(|x| x == &required_output)
                .is_none()
            {
                return Err(InputRuleError::MissingRequiredOutput);
            }
        }
        // Verify max_tombstone_block
        if self.max_tombstone_block != 0 {
            if tx.prefix.tombstone_block > self.max_tombstone_block {
                return Err(InputRuleError::MaxTombstoneBlockExceeded);
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
}
