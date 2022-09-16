// Copyright (c) 2018-2022 The MobileCoin Foundation

//! An aggregate which represents an amount of some token in the MobileCoin
//! blockchain.

use crate::token::TokenId;
use mc_crypto_digestible::Digestible;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// An amount of some token, in the "base" (u64) denomination.
#[derive(Clone, Copy, Debug, Deserialize, Digestible, Eq, Serialize, PartialEq, Zeroize)]
pub struct Amount {
    /// The "raw" value of this amount as a u64
    #[serde(with = "serde_str")]
    pub value: u64,
    /// The token-id which is the denomination of this amount
    #[serde(with = "serde_str")]
    pub token_id: TokenId,
}

impl Amount {
    /// Create a new amount
    pub fn new(value: u64, token_id: TokenId) -> Self {
        Self { value, token_id }
    }
}
