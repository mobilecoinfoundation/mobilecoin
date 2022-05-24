// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Object for 0x0202 Gift Code Cancellation memo type
//!
//! This was proposed for standardization in mobilecoinfoundation/mcips/pull/32

use crate::{impl_memo_type_conversions, RegisteredMemoType};
use mc_transaction_core::MemoError;
use std::convert::TryInto;

/// Memo representing the cancellation of a gift code. If a gift code is
/// never redeemed, the sender may cancel it by sending the TxOut back
/// to their primary address. This memo will be written to the
/// reserved change address with 8 little endian bytes reserved for a u64
/// that represents the index of the cancelled gift code TxOut and 7 big
/// endian bytes reserved for recording the fee paid to cancel the gift
/// code as a 56 bit number.
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct GiftCodeCancellationMemo {
    /// The data representing the gift code memo
    memo_data: [u8; Self::MEMO_DATA_LEN],
}

impl RegisteredMemoType for GiftCodeCancellationMemo {
    const MEMO_TYPE_BYTES: [u8; 2] = [0x02, 0x02];
}

impl GiftCodeCancellationMemo {
    /// Number of bytes in the memo
    pub const MEMO_DATA_LEN: usize = 64;

    /// Number of bytes used to represent the global index of the TxOut used to
    /// fund the cancelled gift code
    pub const INDEX_DATA_LEN: usize = 8;

    /// Number of bytes used to represent the fee paid for gift code
    /// cancellation
    pub const FEE_DATA_LEN: usize = 7;

    /// Maximum value of the fee we can record
    pub const MAX_FEE: u64 = u64::MAX >> 8;

    /// Create a new gift code cancellation memo
    pub fn new(global_index: u64, fee: u64) -> Result<Self, MemoError> {
        // Check if the fee we're setting is greater than the max fee
        if fee > Self::MAX_FEE {
            return Err(MemoError::MaxFeeExceeded(Self::MAX_FEE, fee));
        }

        let mut memo_data = [0u8; Self::MEMO_DATA_LEN];

        // Put global index of the previously funded gift code into memo
        memo_data[..Self::INDEX_DATA_LEN]
            .copy_from_slice(&global_index.to_le_bytes()[..Self::INDEX_DATA_LEN]);

        // Put fee into memo
        memo_data[Self::INDEX_DATA_LEN..(Self::INDEX_DATA_LEN + Self::FEE_DATA_LEN)]
            .copy_from_slice(&fee.to_be_bytes()[1..(Self::FEE_DATA_LEN + 1)]);

        Ok(Self { memo_data })
    }

    /// Get global index of the TxOut used to fund the gift code
    pub fn cancelled_gift_code_index(&self) -> u64 {
        u64::from_le_bytes(self.memo_data[..8].try_into().unwrap())
    }

    /// Get fee amount paid to cancel the gift code
    pub fn get_fee(&self) -> u64 {
        let mut fee_bytes = [0u8; 8];
        fee_bytes[1..8].copy_from_slice(
            &self.memo_data[Self::INDEX_DATA_LEN..(Self::INDEX_DATA_LEN + Self::FEE_DATA_LEN)],
        );
        u64::from_be_bytes(fee_bytes)
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
        // Set cancellation index and fee
        let index = 666;
        let fee = 20;
        let memo = GiftCodeCancellationMemo::new(index, fee).unwrap();

        // Check recovered index is correct
        assert_eq!(memo.cancelled_gift_code_index(), index);

        // Check recovered fee is correct
        assert_eq!(memo.get_fee(), fee);
    }

    #[test]
    fn test_gift_code_cancellation_memo_at_min_max_bounds_succeed() {
        // Set fee and minimum and maximum indices
        let index_min = 0;
        let index_max = u64::MAX;
        let fee = 20;
        let memo_min = GiftCodeCancellationMemo::new(index_min, fee).unwrap();
        let memo_max = GiftCodeCancellationMemo::new(index_max, fee).unwrap();

        // Check recovered indices are correct
        assert_eq!(memo_min.cancelled_gift_code_index(), index_min);
        assert_eq!(memo_max.cancelled_gift_code_index(), index_max);

        // Check recovered fees are correct
        assert_eq!(memo_min.get_fee(), fee);
        assert_eq!(memo_max.get_fee(), fee);
    }

    #[test]
    fn test_gift_code_cancellation_memo_from_corrupted_bytes_fails() {
        // Insert bytes representing the index and the fee into an empty array
        let index: u64 = 666;
        let fee: u64 = 20;
        let fee_bytes = fee.to_be_bytes();
        let mut memo_bytes = [0u8; GiftCodeCancellationMemo::MEMO_DATA_LEN];
        memo_bytes[0..GiftCodeCancellationMemo::INDEX_DATA_LEN]
            .copy_from_slice(&index.to_le_bytes());
        memo_bytes[GiftCodeCancellationMemo::INDEX_DATA_LEN
            ..(GiftCodeCancellationMemo::INDEX_DATA_LEN + GiftCodeCancellationMemo::FEE_DATA_LEN)]
            .copy_from_slice(&fee_bytes[1..(GiftCodeCancellationMemo::FEE_DATA_LEN + 1)]);

        // Corrupt the bytes
        memo_bytes[5] = 124;
        memo_bytes[10] = 124;

        // Recover the memo
        let memo = GiftCodeCancellationMemo::from(&memo_bytes);

        // Check recovered index is incorrect
        assert_ne!(memo.cancelled_gift_code_index(), index);

        // Check recovered fee is incorrect
        assert_ne!(memo.get_fee(), fee);
    }

    #[test]
    fn test_gift_code_cancellation_memo_from_valid_bytes_is_ok() {
        // Insert bytes representing the index and the fee into an empty array
        let index: u64 = 666;
        let fee: u64 = 20;
        let fee_bytes = fee.to_be_bytes();
        let mut memo_bytes = [0u8; GiftCodeCancellationMemo::MEMO_DATA_LEN];
        memo_bytes[0..GiftCodeCancellationMemo::INDEX_DATA_LEN]
            .copy_from_slice(&index.to_le_bytes());
        memo_bytes[GiftCodeCancellationMemo::INDEX_DATA_LEN
            ..(GiftCodeCancellationMemo::INDEX_DATA_LEN + GiftCodeCancellationMemo::FEE_DATA_LEN)]
            .copy_from_slice(&fee_bytes[1..(GiftCodeCancellationMemo::FEE_DATA_LEN + 1)]);

        // Recover the memo
        let memo = GiftCodeCancellationMemo::from(&memo_bytes);

        // Check recovered index is correct
        assert_eq!(memo.cancelled_gift_code_index(), index);

        // Check recovered fee is correct
        assert_eq!(memo.get_fee(), fee);
    }

    #[test]
    fn test_gift_code_cancellation_memo_fee_boundaries() {
        // Create index and create fees close to the maximum
        let index = 666;
        let fee_max_minus_one = GiftCodeCancellationMemo::MAX_FEE - 1;
        let fee_max = GiftCodeCancellationMemo::MAX_FEE;
        let fee_max_plus_one: u64 = GiftCodeCancellationMemo::MAX_FEE + 1;

        // Attempt to instantiate cancellation memos
        let memo_max_minus_one = GiftCodeCancellationMemo::new(index, fee_max_minus_one).unwrap();
        let memo_max = GiftCodeCancellationMemo::new(index, fee_max).unwrap();
        let memo_max_plus_one = GiftCodeCancellationMemo::new(index, fee_max_plus_one);

        // Check recovered index is correct from memos initialized with valid fees
        assert_eq!(memo_max_minus_one.cancelled_gift_code_index(), index);
        assert_eq!(memo_max.cancelled_gift_code_index(), index);

        // Check recovered fee is correct from memos initialized with valid fees
        assert_eq!(memo_max_minus_one.get_fee(), fee_max_minus_one);
        assert_eq!(memo_max.get_fee(), fee_max);

        // Check memo initialized with bad fee fails
        assert!(matches!(
            memo_max_plus_one,
            Err(MemoError::MaxFeeExceeded(_, _))
        ));
    }
}
