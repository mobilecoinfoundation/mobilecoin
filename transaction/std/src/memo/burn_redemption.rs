// Copyright (c) 2022 The MobileCoin Foundation

//! Object for 0x0001 Burn Redemption memo type
//!
//! TODO: Link to MCIP
//! This was proposed for standardization in mobilecoinfoundation/mcips/pull/TBD

use super::RegisteredMemoType;
use crate::impl_memo_type_conversions;

/// A memo that the sender writes to associate a burn of an assert on the
/// MobileCoin blockchain with a redemption of another asset on a different
/// blockchain. The main intended use-case for this is burning of tokens that
/// are correlated with redemption of some other asset on a different
/// blockchain.
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct BurnRedemptionMemo {
    /// The memo data.
    /// The contents of the memo depend on the token being burnt, and as such do
    /// not have a strict schema.
    memo_data: [u8; 64],
}

impl RegisteredMemoType for BurnRedemptionMemo {
    const MEMO_TYPE_BYTES: [u8; 2] = [0x00, 0x01];
}

impl BurnRedemptionMemo {
    /// Create a new BurnRedemptionMemo.
    pub fn new(memo_data: [u8; 64]) -> Self {
        BurnRedemptionMemo { memo_data }
    }

    /// Get the memo data
    pub fn memo_data(&self) -> &[u8; 64] {
        &self.memo_data
    }
}

impl From<&[u8; 64]> for BurnRedemptionMemo {
    fn from(src: &[u8; 64]) -> Self {
        let mut memo_data = [0u8; 64];
        memo_data.copy_from_slice(src);
        Self { memo_data }
    }
}

impl From<BurnRedemptionMemo> for [u8; 64] {
    fn from(src: BurnRedemptionMemo) -> [u8; 64] {
        src.memo_data
    }
}

impl_memo_type_conversions! { BurnRedemptionMemo }
