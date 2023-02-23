// Copyright (c) 2018-2023 The MobileCoin Foundation

//! Object for 0x0003 Defragmentation memo type
//!
//! This was proposed for standardization in mobilecoinfoundation/mcips/pull/61

use super::RegisteredMemoType;
use crate::impl_memo_type_conversions;
use displaydoc::Display;

/// TODO: doc
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct DefragmentationMemo {
    /// TODO: doc
    fee: u64,
    /// TODO: doc
    total_outlay: u64,
    /// TODO: doc
    defrag_id: u64,
}

impl RegisteredMemoType for DefragmentationMemo {
    const MEMO_TYPE_BYTES: [u8; 2] = [0x00, 0x03];
}

impl DefragmentationMemo {
    /// The length of the custom memo data.
    pub const MEMO_DATA_LEN: usize = 64;

    /// TODO: doc
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

    /// TODO: doc
    pub fn get_fee(&self) -> u64 {
        self.fee
    }

    /// TODO: doc
    pub fn set_fee(&mut self, value: u64) -> Result<(), DefragmentationMemoError> {
        if value.to_be_bytes()[0] != 0u8 {
            return Err(DefragmentationMemoError::FeeTooLarge);
        }
        self.fee = value;
        Ok(())
    }

    /// TODO: doc
    pub fn get_total_outlay(&self) -> u64 {
        self.total_outlay
    }

    /// TODO: doc
    pub fn set_total_outlay(&mut self, value: u64) {
        self.total_outlay = value;
    }

    /// TODO: doc
    pub fn get_defrag_id(&self) -> u64 {
        self.defrag_id
    }

    /// TODO: doc
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
        let total_outlay = u64::from_be_bytes(src[7..15].try_into().expect("BUG! arithmetic error"));
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
