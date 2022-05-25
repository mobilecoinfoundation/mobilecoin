// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Object for 0x0002 Gift Code Sender memo type
//!
//! This was proposed for standardization in mobilecoinfoundation/mcips/pull/32

use crate::{impl_memo_type_conversions, RegisteredMemoType};
use mc_transaction_core::MemoError;
use std::str;

/// A gift code is considered "redeemed" when the receiver of
/// a gift code message uses the private spend key of the gift
/// code TxOut (originally sent to the sender's reserved gift
/// subaddress) to send the TxOut to them themselves. When that
/// happens, the gift code sender memo is written to the change
/// TxOut that the receiver sends the gift code to. The sender
/// memo includes 7 big endian bytes to store a 56 bit number
/// representing the fee paid to send the gift code to
/// themselves and 57 bytes representing a utf-8 string used
/// to record any desired information about the gift code.
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct GiftCodeSenderMemo {
    /// The data representing the gift code memo
    memo_data: [u8; Self::MEMO_DATA_LEN],
}

impl RegisteredMemoType for GiftCodeSenderMemo {
    const MEMO_TYPE_BYTES: [u8; 2] = [0x00, 0x02];
}

impl GiftCodeSenderMemo {
    /// Number of bytes in the memo
    pub const MEMO_DATA_LEN: usize = 64;

    /// Number of bytes used to represent the fee paid for gift code redemption
    pub const FEE_DATA_LEN: usize = 7;

    /// Number of bytes used to represent the utf-8 note
    pub const NOTE_DATA_LEN: usize = 57;

    /// The max fee (i.e. the maximum value a 56 bit number can contain)
    pub const MAX_FEE: u64 = u64::MAX >> 8;

    /// Create a new gift code sender memo
    pub fn new(fee: u64, note: &str) -> Result<Self, MemoError> {
        // Check if the fee we're setting is greater than the max fee
        if fee > Self::MAX_FEE {
            return Err(MemoError::MaxFeeExceeded(Self::MAX_FEE, fee));
        }
        // Check if note is of valid length
        if note.len() > Self::NOTE_DATA_LEN {
            return Err(MemoError::BadLength(note.len()));
        }

        let mut memo_data = [0u8; Self::MEMO_DATA_LEN];

        // Put fee into memo
        memo_data[0..Self::FEE_DATA_LEN].copy_from_slice(&fee.to_be_bytes()[1..]);

        // Put note into memo
        memo_data[Self::FEE_DATA_LEN..(Self::FEE_DATA_LEN + note.len())]
            .copy_from_slice(note.as_bytes());

        Ok(Self { memo_data })
    }

    /// Get the sender note
    pub fn sender_note(&self) -> Result<&str, MemoError> {
        let index = if let Some(terminator) = &self
            .memo_data
            .iter()
            .enumerate()
            .position(|(i, b)| i >= Self::FEE_DATA_LEN && b == &0u8)
        {
            *terminator
        } else {
            Self::MEMO_DATA_LEN
        };

        str::from_utf8(&self.memo_data[Self::FEE_DATA_LEN..index]).map_err(Into::into)
    }

    /// Get fee amount paid
    pub fn get_fee(&self) -> u64 {
        let mut fee_bytes = [0u8; 8];
        // Copy the 7 fee bytes into a u64 array, leaving the most significant bit 0
        fee_bytes[1..].copy_from_slice(&self.memo_data[..Self::FEE_DATA_LEN]);
        u64::from_be_bytes(fee_bytes)
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

impl_memo_type_conversions! { GiftCodeSenderMemo }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gift_code_sender_memo_to_and_from_str() {
        // Create memo with note
        let fee = 10;
        let note = "Dear Kitty, you received cash money MeowbleCoin UwU";
        let memo = GiftCodeSenderMemo::new(fee, note).unwrap();

        // Check that the note is extracted correctly
        assert_eq!(memo.sender_note().unwrap(), note);

        // Check that the fee is extracted correctly
        assert_eq!(memo.get_fee(), fee);
    }

    #[test]
    fn test_gift_code_sender_memo_with_blank_note_is_ok() {
        // Create memo with blank
        let fee = 10;
        let note = "";
        let memo = GiftCodeSenderMemo::new(fee, note).unwrap();

        // Check that the note is extracted correctly
        assert_eq!(memo.sender_note().unwrap(), note);

        // Check that the fee is extracted correctly
        assert_eq!(memo.get_fee(), fee);
    }

    #[test]
    fn test_gift_code_sender_memo_with_only_null_bytes_is_okay() {
        // Create memo from null bytes
        let memo_bytes = [0u8; GiftCodeSenderMemo::MEMO_DATA_LEN];
        let memo = GiftCodeSenderMemo::from(&memo_bytes);
        let fee = 0;
        let note = "";

        // Check that the note is extracted properly to a blank note
        assert_eq!(memo.sender_note().unwrap(), note);

        // Check that the fee is extracted correctly
        assert_eq!(memo.get_fee(), fee);
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
        memo_bytes[GiftCodeSenderMemo::FEE_DATA_LEN..(GiftCodeSenderMemo::FEE_DATA_LEN + 8)]
            .copy_from_slice(&note_bytes);
        let memo = GiftCodeSenderMemo::from(&memo_bytes);

        // Check that the note is extracted correctly and terminated at first null
        assert_eq!(memo.sender_note().unwrap(), note);
    }

    #[test]
    fn test_gift_code_sender_memo_created_with_notes_near_max_byte_lengths() {
        // Create notes near max length
        const LEN_EXACT: usize = GiftCodeSenderMemo::NOTE_DATA_LEN;
        const LEN_MINUS_ONE: usize = GiftCodeSenderMemo::NOTE_DATA_LEN - 1;
        const LEN_PLUS_ONE: usize = GiftCodeSenderMemo::NOTE_DATA_LEN + 1;
        let note_len_minus_one = str::from_utf8(&[b'6'; LEN_MINUS_ONE]).unwrap();
        let note_len_exact = str::from_utf8(&[b'6'; LEN_EXACT]).unwrap();
        let note_len_plus_one = str::from_utf8(&[b'6'; LEN_PLUS_ONE]).unwrap();
        let fee = 42;

        // Create memos from notes
        let memo_len_minus_one = GiftCodeSenderMemo::new(fee, note_len_minus_one).unwrap();
        let memo_len_exact = GiftCodeSenderMemo::new(fee, note_len_exact).unwrap();
        let memo_len_plus_one = GiftCodeSenderMemo::new(fee, note_len_plus_one);

        // Check note lengths match or error on creation if too large
        assert_eq!(
            memo_len_minus_one.sender_note().unwrap(),
            note_len_minus_one
        );
        assert_eq!(memo_len_exact.sender_note().unwrap(), note_len_exact);
        assert_eq!(
            memo_len_plus_one,
            Err(MemoError::BadLength(LEN_PLUS_ONE))
        );

        // Assert derived fees match for successful memos
        assert_eq!(memo_len_minus_one.get_fee(), fee);
        assert_eq!(memo_len_exact.get_fee(), fee);
    }

    #[test]
    fn test_gift_code_sender_memo_from_valid_bytes_is_okay() {
        // Create note from bytes
        let note_bytes = [b'6'; GiftCodeSenderMemo::NOTE_DATA_LEN - 1];
        let fee: u64 = 666;
        let fee_bytes = fee.to_be_bytes();
        let note = str::from_utf8(&note_bytes).unwrap();

        // Create memo from note bytes
        let mut memo_bytes = [0u8; GiftCodeSenderMemo::MEMO_DATA_LEN];
        memo_bytes[..GiftCodeSenderMemo::FEE_DATA_LEN].copy_from_slice(&fee_bytes[1..]);
        memo_bytes[GiftCodeSenderMemo::FEE_DATA_LEN
            ..(GiftCodeSenderMemo::FEE_DATA_LEN + GiftCodeSenderMemo::NOTE_DATA_LEN - 1)]
            .copy_from_slice(&note_bytes);
        let memo = GiftCodeSenderMemo::from(&memo_bytes);

        // Check that the note is extracted correctly
        assert_eq!(memo.sender_note().unwrap(), note);

        // Check that the fee is extracted correctly
        assert_eq!(memo.get_fee(), fee);
    }

    #[test]
    fn test_gift_code_sender_memo_created_with_fees_near_max_fee() {
        // Create notes near max length
        const MAX_FEE: u64 = GiftCodeSenderMemo::MAX_FEE;
        const MAX_FEE_MINUS_ONE: u64 = GiftCodeSenderMemo::MAX_FEE - 1;
        const MAX_FEE_PLUS_ONE: u64 = GiftCodeSenderMemo::MAX_FEE + 1;
        let note = "noted";

        // Create memos from notes
        let memo_max_fee_minus_one = GiftCodeSenderMemo::new(MAX_FEE_MINUS_ONE, note).unwrap();
        let memo_max_fee = GiftCodeSenderMemo::new(MAX_FEE, note).unwrap();
        let memo_max_fee_plus_one = GiftCodeSenderMemo::new(MAX_FEE_PLUS_ONE, note);

        // Check fees reconstruct correctly or cause error
        assert_eq!(memo_max_fee_minus_one.get_fee(), MAX_FEE_MINUS_ONE);
        assert_eq!(memo_max_fee.get_fee(), MAX_FEE);
        assert_eq!(
            memo_max_fee_plus_one,
            Err(MemoError::MaxFeeExceeded(MAX_FEE, MAX_FEE_PLUS_ONE))
        );

        // Check notes match for successful memos
        assert_eq!(memo_max_fee.sender_note().unwrap(), note);
        assert_eq!(memo_max_fee_minus_one.sender_note().unwrap(), note);
    }
}
