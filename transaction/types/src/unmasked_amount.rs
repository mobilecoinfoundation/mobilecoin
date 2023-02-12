// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Unmasked amount types
use crate::{amount::Amount, TokenId};

use mc_crypto_digestible::Digestible;
use mc_crypto_ring_signature::CurveScalar;

#[cfg(feature = "prost")]
use prost::Message;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// The "unmasked" data of an amount commitment
#[derive(Clone, Digestible, Eq, PartialEq, Zeroize)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[cfg_attr(feature = "prost", derive(Message))]
#[cfg_attr(not(feature = "prost"), derive(Debug))]
pub struct UnmaskedAmount {
    /// The value of the amount commitment
    #[cfg_attr(feature = "prost", prost(fixed64, tag = 1))]
    pub value: u64,

    /// The token id of the amount commitment
    #[cfg_attr(feature = "prost", prost(fixed64, tag = 2))]
    pub token_id: u64,

    /// The blinding factor of the amount commitment
    #[cfg_attr(feature = "prost", prost(message, required, tag = 3))]
    pub blinding: CurveScalar,
}

impl From<&UnmaskedAmount> for Amount {
    fn from(src: &UnmaskedAmount) -> Self {
        Self {
            value: src.value,
            token_id: TokenId::from(src.token_id),
        }
    }
}
