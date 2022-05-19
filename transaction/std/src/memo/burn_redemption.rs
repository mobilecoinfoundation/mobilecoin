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
    memo_data: [u8; Self::MEMO_DATA_LEN],
}

impl RegisteredMemoType for BurnRedemptionMemo {
    const MEMO_TYPE_BYTES: [u8; 2] = [0x00, 0x01];
}

impl BurnRedemptionMemo {
    /// The length of the custom memo data.
    pub const MEMO_DATA_LEN: usize = 64;

    /// Create a new BurnRedemptionMemo.
    pub fn new(memo_data: [u8; Self::MEMO_DATA_LEN]) -> Self {
        BurnRedemptionMemo { memo_data }
    }

    /// Get the memo data
    pub fn memo_data(&self) -> &[u8; Self::MEMO_DATA_LEN] {
        &self.memo_data
    }
}

impl From<&[u8; Self::MEMO_DATA_LEN]> for BurnRedemptionMemo {
    fn from(src: &[u8; Self::MEMO_DATA_LEN]) -> Self {
        let mut memo_data = [0u8; Self::MEMO_DATA_LEN];
        memo_data.copy_from_slice(src);
        Self { memo_data }
    }
}

impl From<BurnRedemptionMemo> for [u8; BurnRedemptionMemo::MEMO_DATA_LEN] {
    fn from(src: BurnRedemptionMemo) -> [u8; BurnRedemptionMemo::MEMO_DATA_LEN] {
        src.memo_data
    }
}

impl_memo_type_conversions! { BurnRedemptionMemo }
