// Copyright (c) 2018-2022 The MobileCoin Foundation

//! An aggregate which represents an amount of some token in the MobileCoin
//! blockchain.

pub use error::AmountError;

use crate::TokenId;
use mc_crypto_digestible::Digestible;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

mod error;

/// An amount of some token, in the "base" (u64) denomination.
#[derive(Clone, Copy, Debug, Digestible, Eq, PartialEq, Zeroize)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Amount {
    /// The "raw" value of this amount as a u64
    pub value: u64,
    /// The token-id which is the denomination of this amount
    pub token_id: TokenId,
}

impl Amount {
    /// Create a new amount
    pub fn new(value: u64, token_id: TokenId) -> Self {
        Self { value, token_id }
    }
}

impl Default for Amount {
    fn default() -> Self {
        Amount::new(0, 0.into())
    }
}
