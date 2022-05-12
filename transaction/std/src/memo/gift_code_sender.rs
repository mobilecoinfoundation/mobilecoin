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
    pub fn new(note_data: &str) -> Result<Self, MemoError> {
        GiftCodeSenderMemo::try_from(note_data)
    }

    /// Get the sender note
    pub fn sender_note(&self) -> Result<&str, MemoError> {
        let index = if let Some(terminator) = &self.memo_data.iter().position(|b| b == &0u8) {
            *terminator
        } else {
            Self::MEMO_DATA_LEN
        };

        str::from_utf8(&self.memo_data[0..index]).map_err(Into::into)
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
        // Create memo with note
        let note = "Dear Kitty, you received cash money MeowbleCoin UwU";
        let memo = GiftCodeSenderMemo::new(note).unwrap();

        // Check that the note is extracted properly
        assert_eq!(memo.sender_note().unwrap(), note);
    }

    #[test]
    fn test_gift_code_sender_memo_with_blank_note_is_ok() {
        // Create memo with blank note
        let note = "";
        let memo = GiftCodeSenderMemo::new(note).unwrap();

        // Check that the note is extracted properly
        assert_eq!(memo.sender_note().unwrap(), note);
    }

    #[test]
    fn test_gift_code_sender_memo_with_only_null_bytes_is_okay() {
        // Create memo from null bytes
        let memo_bytes = [0u8; GiftCodeSenderMemo::MEMO_DATA_LEN];
        let memo = GiftCodeSenderMemo::from(&memo_bytes);
        let note = "";

        // Check that the note is extracted properly to a blank note
        assert_eq!(memo.sender_note().unwrap(), note);
    }

    #[test]
    fn test_gift_code_sender_note_terminates_at_first_null() {
        // Create note from bytes with two null bytes
        let mut note_bytes = [b'6'; 8];
        note_bytes[3] = 0;
        note_bytes[6] = 0;
        let note = "666";

        // Create memo from note bytes
        let mut memo_bytes = [0u8; GiftCodeSenderMemo::MEMO_DATA_LEN];
        memo_bytes[0..8].copy_from_slice(&note_bytes);
        let memo = GiftCodeSenderMemo::from(&memo_bytes);

        // Check that the note is extracted properly and terminated at first null
        assert_eq!(memo.sender_note().unwrap(), note);
    }

    #[test]
    fn test_gift_code_sender_memo_created_with_notes_near_max_byte_lengths() {
        // Create notes near max length
        const LEN_EXACT: usize = GiftCodeSenderMemo::MEMO_DATA_LEN;
        const LEN_MINUS_ONE: usize = GiftCodeSenderMemo::MEMO_DATA_LEN - 1;
        const LEN_PLUS_ONE: usize = GiftCodeSenderMemo::MEMO_DATA_LEN + 1;
        let note_len_minus_one = str::from_utf8(&[b'6'; LEN_MINUS_ONE]).unwrap();
        let note_len_exact = str::from_utf8(&[b'6'; LEN_EXACT]).unwrap();
        let note_len_plus_one = str::from_utf8(&[b'6'; LEN_PLUS_ONE]).unwrap();

        // Create memos from notes
        let memo_len_minus_one = GiftCodeSenderMemo::new(note_len_minus_one).unwrap();
        let memo_len_exact = GiftCodeSenderMemo::new(note_len_exact).unwrap();
        let memo_len_plus_one = GiftCodeSenderMemo::new(note_len_plus_one);

        // Check note lengths match or error on creation if too large
        assert_eq!(
            memo_len_minus_one.sender_note().unwrap(),
            note_len_minus_one
        );
        assert_eq!(memo_len_exact.sender_note().unwrap(), note_len_exact);
        assert!(matches!(
            memo_len_plus_one,
            Err(MemoError::BadLength(LEN_PLUS_ONE))
        ));
    }

    #[test]
    fn test_gift_code_sender_memo_with_corrupted_bytes_fails() {
        // Create note bytes and corrupt them
        let mut note_bytes = [b'6'; GiftCodeSenderMemo::MEMO_DATA_LEN - 1];
        let note = str::from_utf8(&[b'6'; GiftCodeSenderMemo::MEMO_DATA_LEN - 1]).unwrap();
        note_bytes[42] = 42;

        // Create memo from corrupted bytes
        let mut memo_bytes = [0u8; GiftCodeSenderMemo::MEMO_DATA_LEN];
        memo_bytes[0..(GiftCodeSenderMemo::MEMO_DATA_LEN - 1)].copy_from_slice(&note_bytes);
        let memo = GiftCodeSenderMemo::from(&memo_bytes);

        // Check that the note is erroneous
        assert_ne!(memo.sender_note().unwrap(), note);
    }

    #[test]
    fn test_gift_code_sender_memo_from_valid_bytes_is_okay() {
        // Create note from bytes
        let note_bytes = [b'6'; GiftCodeSenderMemo::MEMO_DATA_LEN - 1];
        let note = str::from_utf8(&note_bytes).unwrap();

        // Create memo from note bytes
        let mut memo_bytes = [0u8; GiftCodeSenderMemo::MEMO_DATA_LEN];
        memo_bytes[0..(GiftCodeSenderMemo::MEMO_DATA_LEN - 1)].copy_from_slice(&note_bytes);
        let memo = GiftCodeSenderMemo::from(&memo_bytes);

        // Check that the note is extracted properly
        assert_eq!(memo.sender_note().unwrap(), note);
    }
}
