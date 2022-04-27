// Copyright (c) 2018-2022 The MobileCoin Foundation

//! A new-type wrapper for representing TokenIds

use core::{fmt, hash::Hash, num::ParseIntError, ops::Deref, str::FromStr};
use mc_crypto_digestible::Digestible;
use serde::{Deserialize, Serialize};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

/// Token Id, used to identify different assets on on the blockchain.
#[derive(
    Clone, Copy, Debug, Deserialize, Digestible, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
)]
pub struct TokenId(u64);

impl From<u64> for TokenId {
    fn from(src: u64) -> Self {
        Self(src)
    }
}

impl From<&u64> for TokenId {
    fn from(src: &u64) -> Self {
        Self(*src)
    }
}

impl fmt::Display for TokenId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl TokenId {
    /// Represents the MobileCoin token id for MOB token
    pub const MOB: Self = Self(0);

    /// Represents the number of bytes in a well-formed TokenId
    pub const NUM_BYTES: usize = 8;
}

impl Deref for TokenId {
    type Target = u64;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl FromStr for TokenId {
    type Err = ParseIntError;
    fn from_str(src: &str) -> Result<Self, Self::Err> {
        let src = u64::from_str(src)?;
        Ok(TokenId(src))
    }
}

impl PartialEq<u64> for TokenId {
    fn eq(&self, other: &u64) -> bool {
        self.0 == *other
    }
}

impl PartialEq<TokenId> for u64 {
    fn eq(&self, other: &TokenId) -> bool {
        *self == other.0
    }
}

impl ConstantTimeEq for TokenId {
    fn ct_eq(&self, other: &TokenId) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl ConditionallySelectable for TokenId {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self(ConditionallySelectable::conditional_select(
            &a.0, &b.0, choice,
        ))
    }
}

/// A generic representation of a token.
pub trait Token {
    /// Token Id.
    const ID: TokenId;

    /// Default mininum fee for this token.
    const MINIMUM_FEE: u64;
}

/// Exports structures which expose constants related to tokens.
///
/// If changing this, please keep it in sync with the enum defined in
/// external.proto
pub mod tokens {
    use super::*;
    use crate::constants::MICROMOB_TO_PICOMOB;

    /// The MOB token.
    pub struct Mob;
    impl Token for Mob {
        /// Token Id.
        const ID: TokenId = TokenId::MOB;

        /// Minimum fee, deominated in picoMOB.
        const MINIMUM_FEE: u64 = 400 * MICROMOB_TO_PICOMOB;
    }
}
