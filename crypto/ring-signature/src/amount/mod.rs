// Copyright (c) 2018-2022 The MobileCoin Foundation

//! A commitment to an output's amount, denominated in picoMOB.
//!
//! Amounts are implemented as Pedersen commitments. The associated private keys
//! are "masked" using a shared secret.

use crate::token::TokenId;
use mc_crypto_digestible::Digestible;
use zeroize::Zeroize;

mod commitment;
mod compressed_commitment;

pub use commitment::Commitment;
pub use compressed_commitment::CompressedCommitment;

/// An amount of some token, in the "base" (u64) denomination.
#[derive(Clone, Copy, Debug, Digestible, Eq, PartialEq, Zeroize)]
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
