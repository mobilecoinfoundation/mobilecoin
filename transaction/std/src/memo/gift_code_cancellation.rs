// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Object for 0x0202 Gift Code Cancellation memo type
//!
//! This was proposed for standardization in mobilecoinfoundation/mcips/pull/32

use crate::{impl_memo_type_conversions, RegisteredMemoType};
use std::convert::TryInto;

/// Memo representing the cancellation of a gift code. If a gift code is
/// never redeemed, the sender may cancel it by sending the TxOut back
/// to their primary address. This memo will be written to the
/// reserved change address with 8 bytes reserved for a u64 that
/// represents the index of the cancelled gift code TxOut
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct GiftCodeCancellationMemo {
    /// The data representing the gift code memo
    memo_data: [u8; Self::MEMO_DATA_LEN],
}

impl RegisteredMemoType for GiftCodeCancellationMemo {
    const MEMO_TYPE_BYTES: [u8; 2] = [0x02, 0x02];
}

impl GiftCodeCancellationMemo {
    /// The length of the custom memo data
    pub const MEMO_DATA_LEN: usize = 64;

    /// Create a new gift code memo
    pub fn new(global_index: u64) -> Self {
        GiftCodeCancellationMemo::from(global_index)
    }

    /// Get global TxOut index of the cancelled gift code
    pub fn cancelled_gift_code_index(&self) -> u64 {
        u64::from_le_bytes(self.memo_data[0..8].try_into().unwrap())
    }
}

impl From<&[u8; Self::MEMO_DATA_LEN]> for GiftCodeCancellationMemo {
    fn from(src: &[u8; Self::MEMO_DATA_LEN]) -> Self {
        let mut memo_data = [0u8; Self::MEMO_DATA_LEN];
        memo_data.copy_from_slice(src);
        Self { memo_data }
    }
}

impl From<GiftCodeCancellationMemo> for [u8; GiftCodeCancellationMemo::MEMO_DATA_LEN] {
    fn from(src: GiftCodeCancellationMemo) -> [u8; GiftCodeCancellationMemo::MEMO_DATA_LEN] {
        src.memo_data
    }
}

impl From<u64> for GiftCodeCancellationMemo {
    fn from(src: u64) -> Self {
        let mut memo_data = [0u8; Self::MEMO_DATA_LEN];
        memo_data[0..8].copy_from_slice(&src.to_le_bytes());
        Self { memo_data }
    }
}

impl_memo_type_conversions! { GiftCodeCancellationMemo }

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_gift_code_cancellation_memo_to_and_from_u64() {
        let index: u64 = 666;
        let memo = GiftCodeCancellationMemo::from(index);

        // Check recovered index is correct
        assert_eq!(memo.cancelled_gift_code_index(), index);
    }

    #[test]
    fn test_gift_code_cancellation_memo_at_min_max_bounds_succeed() {
        let index_min: u64 = 0;
        let index_max = u64::MAX;
        let memo_min = GiftCodeCancellationMemo::new(index_min);
        let memo_max = GiftCodeCancellationMemo::new(index_max);

        // Check recovered indices are correct
        assert_eq!(memo_min.cancelled_gift_code_index(), index_min);
        assert_eq!(memo_max.cancelled_gift_code_index(), index_max);
    }

    #[test]
    fn test_gift_code_cancellation_memo_from_corrupted_bytes_fails() {
        let index: u64 = 666;
        let mut memo_bytes = [0u8; GiftCodeCancellationMemo::MEMO_DATA_LEN];
        memo_bytes[0..8].copy_from_slice(&index.to_le_bytes());
        memo_bytes[5] = 124;
        let memo = GiftCodeCancellationMemo::from(&memo_bytes);

        // Check recovered index is erroneous
        assert_ne!(memo.cancelled_gift_code_index(), index);
    }

    #[test]
    fn test_gift_code_cancellation_memo_from_valid_bytes_is_ok() {
        let index: u64 = 666;
        let mut memo_bytes = [0u8; GiftCodeCancellationMemo::MEMO_DATA_LEN];
        memo_bytes[0..8].copy_from_slice(&index.to_le_bytes());
        let memo = GiftCodeCancellationMemo::from(&memo_bytes);

        // Check recovered index is okay
        assert_eq!(memo.cancelled_gift_code_index(), index);
    }
}
