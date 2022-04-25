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
    /// The memo data
    /// TODO: The contents of this have not yet been determined. It will likely
    /// contain some or all of the following:
    /// 1) The type of address that the redeemed external asset will be sent to
    ///   (e.g. ERC20 wallet, ERC20 contract, etc.)
    /// 2) The external blockchain on which the redemptio is taking place
    ///    (e.g. Ethereum, Polygon, etc.)
    /// 3) Address receiving the redeemed asset This is just a placeholder for
    ///    now.
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
