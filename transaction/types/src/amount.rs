//! [Amount] type
//! 
use crate::{TokenId};

use mc_crypto_digestible::Digestible;

use displaydoc::Display;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

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

/// An error which can occur when handling an amount commitment.
#[derive(Clone, Debug, Display, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum AmountError {
    /**
     * The masked value, token id, or shared secret are not consistent with
     * the commitment.
     */
    InconsistentCommitment,

    /**
     * The masked token id has an invalid number of bytes
     */
    InvalidMaskedTokenId,

    /**
     * The masked amount is missing
     */
    MissingMaskedAmount,

    /// Token Id is not supported at this block version
    TokenIdNotSupportedAtBlockVersion,

    /// Amount version is too old to have amount shared secret
    AmountVersionTooOldForAmountSharedSecret,
}
