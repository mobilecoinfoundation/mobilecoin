// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Object for 0x0002 Gift Code Sender memo type
//!
//! This was proposed for standardization in mobilecoinfoundation/mcips/pull/32

use crate::{impl_memo_type_conversions, RegisteredMemoType};
use mc_transaction_core::MemoError;
use std::{convert::TryFrom, str};

/// A gift code is considered "redeemed" when the receiver of
/// a gift code message uses the private spend key of the gift
/// code TxOut (originally sent to the sender's reserved gift
/// subaddress) to send the TxOut to them themselves. When that
/// happens, the receiver can write an optional 64 byte null
/// terminated utf-8 string in the memo field of an associated
/// change TxOut to record any desired info about the gift code
/// redemption.
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct GiftCodeSenderMemo {
    /// The data representing the gift code memo
    memo_data: [u8; Self::MEMO_DATA_LEN],
}

impl RegisteredMemoType for GiftCodeSenderMemo {
    const MEMO_TYPE_BYTES: [u8; 2] = [0x00, 0x02];
}

impl GiftCodeSenderMemo {
    /// The length of the custom memo data.
    pub const MEMO_DATA_LEN: usize = 64;

    /// Create a new gift code memo
    pub fn new(note_data: &'static str) -> Result<Self, MemoError> {
        GiftCodeSenderMemo::try_from(note_data)
    }

    /// Get the memo data
    pub fn memo_data(&self) -> &[u8; Self::MEMO_DATA_LEN] {
        &self.memo_data
    }

    /// Get the sender note
    pub fn sender_note(&self) -> Result<&str, MemoError> {
        Ok(str::from_utf8(&self.memo_data)?.trim_matches(char::from(0)))
    }
}

impl From<&[u8; Self::MEMO_DATA_LEN]> for GiftCodeSenderMemo {
    fn from(src: &[u8; Self::MEMO_DATA_LEN]) -> Self {
        let mut memo_data = [0u8; Self::MEMO_DATA_LEN];
        memo_data.copy_from_slice(src);
        Self { memo_data }
    }
}

impl From<GiftCodeSenderMemo> for [u8; GiftCodeSenderMemo::MEMO_DATA_LEN] {
    fn from(src: GiftCodeSenderMemo) -> [u8; GiftCodeSenderMemo::MEMO_DATA_LEN] {
        src.memo_data
    }
}

impl TryFrom<&str> for GiftCodeSenderMemo {
    type Error = MemoError;

    fn try_from(src: &str) -> Result<Self, MemoError> {
        if src.len() > Self::MEMO_DATA_LEN {
            return Err(MemoError::BadLength(src.len()));
        }

        let mut memo_data = [0u8; Self::MEMO_DATA_LEN];
        memo_data[0..src.len()].copy_from_slice(src.as_bytes());
        Ok(Self { memo_data })
    }
}

impl_memo_type_conversions! { GiftCodeSenderMemo }

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_gift_code_sender_memo_to_and_from_str() {
        let note = "Dear Kitty, you received cash money MeowbleCoin UwU";
        let memo = GiftCodeSenderMemo::try_from(note).unwrap();
        assert_eq!(memo.sender_note().unwrap(), note);
    }
}
