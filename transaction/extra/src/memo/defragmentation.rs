// Copyright (c) 2018-2023 The MobileCoin Foundation

//! Object for 0x0003 Defragmentation memo type
//!
//! This was proposed for standardization in mobilecoinfoundation/mcips/pull/61

use super::RegisteredMemoType;
use crate::impl_memo_type_conversions;
use displaydoc::Display;

/// Memo denoting a defragmentation transaction. This memo contains
/// the amount and fee of a defragmentation transaction as well as
/// an optional defragmentation ID number. The defragmentation ID number
/// can be used to group multiple defragmentation transactions together.
/// If, for example, 3 defragmentation transactions are needed in order to
/// send the desired amount, the same ID should be used all 3 times. Then,
/// the total paid in fees as well as the total outlay can be added up
/// from the three memos with matching defragmentation ID. If used,
/// the defragmentation ID should be selected randomly. If unused, this
/// value defaults to 0. This memo has type bytes 0x0003.
///
/// This memo is written to both the main defragmentation TxOut as well
/// as the change TxOut (which has 0 value in a defragmentation
/// transaction). The memo written to the main TxOut will have the fee
/// and total outlay recorded in their respective fields. The change
/// TxOut will have a memo with 0 fee and 0 outlay. This makes
/// calculating the total fee and total outlays easier, as the change
/// TxOut does not need to be manually detected and ignored. Both the
/// main and change memos will receive the same value for the
/// defragmentation ID.
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct DefragmentationMemo {
    /// The fee paid to perform the defragmentation transaction (picoMOB)
    /// We assume that the high order byte of fee is zero, and use this
    /// to compress the memo into 32 bytes.
    fee: u64,
    /// The fee plus the amount sent in the defragmentation transaction
    /// (picoMOB)
    total_outlay: u64,
    /// The defragmentation ID used to group multiple rounds together
    defrag_id: u64,
}

impl RegisteredMemoType for DefragmentationMemo {
    const MEMO_TYPE_BYTES: [u8; 2] = [0x00, 0x03];
}

impl DefragmentationMemo {
    /// The length of the memo data.
    pub const MEMO_DATA_LEN: usize = 64;

    /// Creates a new DegragmentationMemo with the specified values.
    /// If the fee exceeds 56 bits, an error will be thrown
    pub fn new(
        fee: u64,
        total_outlay: u64,
        defrag_id: u64,
    ) -> Result<Self, DefragmentationMemoError> {
        let mut result = Self {
            fee: 0,
            total_outlay,
            defrag_id,
        };
        result.set_fee(fee)?;
        Ok(result)
    }

    /// Returns the fee recorded in this memo
    pub fn get_fee(&self) -> u64 {
        self.fee
    }

    /// Sets the fee recorded in this memo
    /// If the value given cannot be represented in 56 bits, an error is thrown
    pub fn set_fee(&mut self, value: u64) -> Result<(), DefragmentationMemoError> {
        if value.to_be_bytes()[0] != 0u8 {
            return Err(DefragmentationMemoError::FeeTooLarge);
        }
        self.fee = value;
        Ok(())
    }

    /// Returns the total outlay of the defragmentation transaction
    pub fn get_total_outlay(&self) -> u64 {
        self.total_outlay
    }

    /// Sets the total outlay
    pub fn set_total_outlay(&mut self, value: u64) {
        self.total_outlay = value;
    }

    /// Returns the defragmentation ID
    pub fn get_defrag_id(&self) -> u64 {
        self.defrag_id
    }

    /// Sets the defragmentation ID
    pub fn set_defrag_id(&mut self, value: u64) {
        self.defrag_id = value;
    }
}

impl From<&[u8; DefragmentationMemo::MEMO_DATA_LEN]> for DefragmentationMemo {
    // The layout of the memo data in 64 bytes is:
    // [0-7): fee
    // [7-15): total outlay
    // [15-23): defrag ID
    // [23-64) unused
    fn from(src: &[u8; DefragmentationMemo::MEMO_DATA_LEN]) -> Self {
        let fee = {
            let mut fee_bytes = [0u8; 8];
            fee_bytes[1..].copy_from_slice(&src[..7]);
            u64::from_be_bytes(fee_bytes)
        };
        let total_outlay =
            u64::from_be_bytes(src[7..15].try_into().expect("BUG! arithmetic error"));
        let defrag_id = u64::from_be_bytes(src[15..23].try_into().expect("BUG! arithmetic error"));
        Self {
            fee,
            total_outlay,
            defrag_id,
        }
    }
}

impl From<DefragmentationMemo> for [u8; DefragmentationMemo::MEMO_DATA_LEN] {
    fn from(src: DefragmentationMemo) -> [u8; DefragmentationMemo::MEMO_DATA_LEN] {
        let mut memo_data = [0u8; DefragmentationMemo::MEMO_DATA_LEN];
        memo_data[..7].copy_from_slice(&src.fee.to_be_bytes()[1..]);
        memo_data[7..15].copy_from_slice(&src.total_outlay.to_be_bytes());
        memo_data[15..23].copy_from_slice(&src.defrag_id.to_be_bytes());
        memo_data
    }
}

/// An error that can occur when configuring a destination memo
#[derive(Display, Debug)]
pub enum DefragmentationMemoError {
    /// The fee amount is too large to be represented in the DefragmentationMemo
    FeeTooLarge,
}

impl_memo_type_conversions! { DefragmentationMemo }
