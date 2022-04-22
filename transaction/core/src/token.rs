// Copyright (c) 2018-2021 The MobileCoin Foundation

use core::{fmt, hash::Hash, ops::Deref};
use mc_crypto_digestible::Digestible;
use serde::{Deserialize, Serialize};

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

impl fmt::Display for TokenId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl TokenId {
    pub const MOB: Self = Self(0);
}

impl Deref for TokenId {
    type Target = u64;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// A generic representation of a token.
pub trait Token {
    /// Token Id.
    const ID: TokenId;

    /// Default mininum fee for this token.
    const MINIMUM_FEE: u64;
}

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
