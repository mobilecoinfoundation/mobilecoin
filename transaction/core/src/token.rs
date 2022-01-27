// Copyright (c) 2018-2021 The MobileCoin Foundation

use core::fmt;
use mc_crypto_digestible::Digestible;
use serde::{Deserialize, Serialize};

/// Token Id, used to identify different assets on on the blockchain.
#[derive(
    Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Ord, Serialize, Deserialize, Digestible,
)]
pub struct TokenId(u32);

impl From<u32> for TokenId {
    fn from(src: u32) -> Self {
        Self(src)
    }
}

impl fmt::Display for TokenId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl TokenId {
    pub const MOB: Self = Self(0);
}

/// A generic representation of a token.
pub trait Token {
    /// Token Id.
    const ID: TokenId;

    /// Mininum fee for this token.
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
