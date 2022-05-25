// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Object for 0x0201 Gift Code Funding memo type
//!
//! This was proposed for standardization in mobilecoinfoundation/mcips/pull/32

use crate::{impl_memo_type_conversions, RegisteredMemoType};
use mc_crypto_hashes::{Blake2b512, Digest};
use mc_crypto_keys::RistrettoPublic;
use mc_transaction_core::MemoError;
use std::{convert::TryInto, str};

/// MobileCoin account owners can create a special TxOut called a "gift code".
/// This TxOut is sent to a special subaddress at index u64::MAX - 2 reserved
/// for gift codes. After this is done, the onetime private key, shared secret
/// and universal index of the TxOut is sent to the intended recipient.
/// This allows people who don't yet have a MobileCoin account to receive
/// MobileCoin. When the sender makes the initial TxOut to the gift code
/// subaddress, this memo will be written to the subaddress reserved for change
/// TxOuts indicating that a gift code was funded. It includes the first 4
/// bytes of the hash of the TxOut to indicate which TxOut the gift code is,
/// the next 7 big endian bytes to track the fee paid to fund the gift code and
/// the remaining 53 bytes used to represent an optional utf-8 string.
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct GiftCodeFundingMemo {
    /// The data representing the gift code memo
    memo_data: [u8; Self::MEMO_DATA_LEN],
}

impl RegisteredMemoType for GiftCodeFundingMemo {
    const MEMO_TYPE_BYTES: [u8; 2] = [0x02, 0x01];
}

impl GiftCodeFundingMemo {
    /// Number of bytes in the memo
    pub const MEMO_DATA_LEN: usize = 64;

    /// Number of bytes used to represent the gift code TxOut hash
    pub const HASH_DATA_LEN: usize = 4;

    /// Number of bytes used to represent the fee paid when funding the gift
    /// code
    pub const FEE_DATA_LEN: usize = 7;

    /// Number of bytes used to represent the utf-8 note
    pub const NOTE_DATA_LEN: usize = 53;

    /// Byte offset of the note
    pub const NOTE_OFFSET: usize = Self::HASH_DATA_LEN + Self::FEE_DATA_LEN;

    /// The max fee (i.e. the maximum value a 56 bit number can contain)
    pub const MAX_FEE: u64 = u64::MAX >> 8;

    /// Create a new gift funding memo
    pub fn new(
        tx_out_public_key: &RistrettoPublic,
        fee: u64,
        note: &str,
    ) -> Result<Self, MemoError> {
        // Check if the fee we're setting is greater than the max fee
        if fee > Self::MAX_FEE {
            return Err(MemoError::MaxFeeExceeded(Self::MAX_FEE, fee));
        }
        // Check if note is of valid length and initialize memo data
        if note.len() > Self::NOTE_DATA_LEN {
            return Err(MemoError::BadLength(note.len()));
        }

        let mut memo_data = [0u8; Self::MEMO_DATA_LEN];

        // Compute TxOut hash and put it into the memo data
        memo_data[..Self::HASH_DATA_LEN]
            .copy_from_slice(&tx_out_public_key_short_hash(tx_out_public_key));

        // Put fee into memo
        memo_data[Self::HASH_DATA_LEN..Self::NOTE_OFFSET]
            .copy_from_slice(&fee.to_be_bytes()[1..=Self::FEE_DATA_LEN]);

        // Put note into memo
        memo_data[Self::NOTE_OFFSET..(Self::NOTE_OFFSET + note.len())]
            .copy_from_slice(note.as_bytes());

        Ok(Self { memo_data })
    }

    /// Check if a given public key matches the hash of the gift code TxOut
    pub fn public_key_matches(&self, tx_out_public_key: &RistrettoPublic) -> bool {
        tx_out_public_key_short_hash(tx_out_public_key) == self.memo_data[..Self::HASH_DATA_LEN]
    }

    /// Get fee amount paid to fund the gift code
    pub fn get_fee(&self) -> u64 {
        let mut fee_bytes = [0u8; 8];
        // Copy the 7 fee bytes into a u64 array, leaving the most significant byte 0
        fee_bytes[1..=GiftCodeFundingMemo::FEE_DATA_LEN]
            .copy_from_slice(&self.memo_data[Self::HASH_DATA_LEN..Self::NOTE_OFFSET]);
        u64::from_be_bytes(fee_bytes)
    }

    /// Get funding note from memo
    pub fn funding_note(&self) -> Result<&str, MemoError> {
        let index = if let Some(terminator) = &self
            .memo_data
            .iter()
            .enumerate()
            .position(|(i, b)| i >= Self::NOTE_OFFSET && b == &0u8)
        {
            *terminator
        } else {
            Self::MEMO_DATA_LEN
        };

        str::from_utf8(&self.memo_data[Self::NOTE_OFFSET..index]).map_err(Into::into)
    }
}

// Compute first four bytes of TxOut hash
fn tx_out_public_key_short_hash(
    tx_out_public_key: &RistrettoPublic,
) -> [u8; GiftCodeFundingMemo::HASH_DATA_LEN] {
    let mut hasher = Blake2b512::new();
    hasher.update("mc-gift-funding-tx-pub-key");
    hasher.update(tx_out_public_key.as_ref().compress().as_bytes());
    hasher.finalize().as_slice()[..GiftCodeFundingMemo::HASH_DATA_LEN]
        .try_into()
        .unwrap()
}

impl From<&[u8; Self::MEMO_DATA_LEN]> for GiftCodeFundingMemo {
    fn from(src: &[u8; Self::MEMO_DATA_LEN]) -> Self {
        let mut memo_data = [0u8; Self::MEMO_DATA_LEN];
        memo_data.copy_from_slice(src);
        Self { memo_data }
    }
}

impl From<GiftCodeFundingMemo> for [u8; GiftCodeFundingMemo::MEMO_DATA_LEN] {
    fn from(src: GiftCodeFundingMemo) -> [u8; GiftCodeFundingMemo::MEMO_DATA_LEN] {
        src.memo_data
    }
}

impl_memo_type_conversions! { GiftCodeFundingMemo }

#[cfg(test)]
mod tests {
    use super::*;
    use mc_util_from_random::FromRandom;
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn test_gift_code_funding_memo_data_outputs_match() {
        // Create memo from note and key
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let note = "Cash money MeowbleCoin for Kitty";
        let key = RistrettoPublic::from_random(&mut rng);
        let fee = 666;
        let memo = GiftCodeFundingMemo::new(&key, fee, note).unwrap();

        // Check that the public key can be verified
        assert!(memo.public_key_matches(&key));

        // Check the fee is correct
        assert_eq!(memo.get_fee(), 666);

        // Check that the note is correct
        assert_eq!(memo.funding_note().unwrap(), note);
    }

    #[test]
    fn test_gift_code_funding_memo_with_blank_note_is_ok() {
        // Initialize key
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let key = RistrettoPublic::from_random(&mut rng);

        // Create memo with blank note
        let note = "";
        let fee = 666;
        let memo = GiftCodeFundingMemo::new(&key, fee, note).unwrap();

        // Check that the public key can be verified
        assert!(memo.public_key_matches(&key));

        // Check the fee is correct
        assert_eq!(memo.get_fee(), 666);

        // Check that the note is correct
        assert_eq!(memo.funding_note().unwrap(), note);
    }

    #[test]
    fn test_gift_code_funding_memo_note_with_only_null_memo_bytes_is_okay() {
        // Initialize hash bytes
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let key = RistrettoPublic::from_random(&mut rng);
        let fee: u64 = 666;
        let hash_bytes = tx_out_public_key_short_hash(&key);
        let fee_bytes = fee.to_be_bytes();

        // Put only hash and fee bytes into memo_bytes, leaving note bytes empty
        let mut memo_bytes = [0u8; GiftCodeFundingMemo::MEMO_DATA_LEN];
        memo_bytes[..GiftCodeFundingMemo::HASH_DATA_LEN].copy_from_slice(&hash_bytes);
        memo_bytes[GiftCodeFundingMemo::HASH_DATA_LEN..GiftCodeFundingMemo::NOTE_OFFSET]
            .copy_from_slice(&fee_bytes[1..]);

        let memo = GiftCodeFundingMemo::from(&memo_bytes);

        // Check that the public key can be verified
        assert!(memo.public_key_matches(&key));

        // Check that the fee is correct
        assert_eq!(memo.get_fee(), fee);

        // Check that a blank note is extracted correctly
        let note = "";
        assert_eq!(memo.funding_note().unwrap(), note);
    }

    #[test]
    fn test_gift_code_funding_memo_note_terminates_at_first_null() {
        // Create note from bytes and put two nulls in it
        let mut note_bytes = [b'6'; 8];
        note_bytes[3] = 0;
        note_bytes[6] = 0;
        let note = "666";

        // Create hash & fee bytes
        let fee: u64 = 666;
        let fee_bytes = fee.to_be_bytes();
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let key = RistrettoPublic::from_random(&mut rng);
        let hash_bytes = tx_out_public_key_short_hash(&key);

        // Create memo from hash, fee & note bytes
        let mut memo_bytes = [0u8; GiftCodeFundingMemo::MEMO_DATA_LEN];
        memo_bytes[..GiftCodeFundingMemo::HASH_DATA_LEN].copy_from_slice(&hash_bytes);
        memo_bytes[GiftCodeFundingMemo::HASH_DATA_LEN..GiftCodeFundingMemo::NOTE_OFFSET]
            .copy_from_slice(&fee_bytes[1..]);
        memo_bytes[GiftCodeFundingMemo::NOTE_OFFSET..(GiftCodeFundingMemo::NOTE_OFFSET + 8)]
            .copy_from_slice(&note_bytes);
        let memo = GiftCodeFundingMemo::from(&memo_bytes);

        // Check that the hash is correctly verified
        assert!(memo.public_key_matches(&key));

        // Check that the fee is correct
        assert_eq!(memo.get_fee(), fee);

        // Check that the note is correct and terminated at first null
        assert_eq!(memo.funding_note().unwrap(), note);
    }

    #[test]
    fn test_gift_code_funding_memo_verified_with_wrong_public_key_doesnt_match() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let note = "Cash money MeowbleCoin for Kitty";
        let fee = 666;
        let key = RistrettoPublic::from_random(&mut rng);
        let other_key = RistrettoPublic::from_random(&mut rng);
        let memo = GiftCodeFundingMemo::new(&key, fee, note).unwrap();

        // Check that a non-matching public key cannot be correctly verified
        assert!(!memo.public_key_matches(&other_key));
    }

    #[test]
    fn test_gift_code_funding_memo_created_with_notes_near_max_byte_lengths() {
        // Create notes near max length
        const LEN_EXACT: usize = GiftCodeFundingMemo::NOTE_DATA_LEN;
        const LEN_MINUS_ONE: usize = GiftCodeFundingMemo::NOTE_DATA_LEN - 1;
        const LEN_PLUS_ONE: usize = GiftCodeFundingMemo::NOTE_DATA_LEN + 1;
        let note_len_minus_one = str::from_utf8(&[b'6'; LEN_MINUS_ONE]).unwrap();
        let note_len_exact = str::from_utf8(&[b'6'; LEN_EXACT]).unwrap();
        let note_len_plus_one = str::from_utf8(&[b'6'; LEN_PLUS_ONE]).unwrap();
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let key = RistrettoPublic::from_random(&mut rng);
        let fee = 666;

        // Create memos from notes
        let memo_len_minus_one = GiftCodeFundingMemo::new(&key, fee, note_len_minus_one).unwrap();
        let memo_len_exact = GiftCodeFundingMemo::new(&key, fee, note_len_exact).unwrap();
        let memo_len_plus_one = GiftCodeFundingMemo::new(&key, fee, note_len_plus_one);

        // Check notes are correct or error on creation if note is too large
        assert_eq!(
            memo_len_minus_one.funding_note().unwrap(),
            note_len_minus_one
        );
        assert_eq!(memo_len_exact.funding_note().unwrap(), note_len_exact);
        assert_eq!(memo_len_plus_one, Err(MemoError::BadLength(LEN_PLUS_ONE)));

        // Check fees are correct for successful memos
        assert_eq!(memo_len_minus_one.get_fee(), fee);
        assert_eq!(memo_len_exact.get_fee(), fee);

        // Check public keys are correct for successful memos
        assert!(memo_len_minus_one.public_key_matches(&key));
        assert!(memo_len_exact.public_key_matches(&key));
    }

    #[test]
    fn test_gift_code_funding_memo_created_with_overlapping_byte_allocations_fail() {
        // Create hash bytes, fee bytes, and note
        let note = str::from_utf8(&[b'6'; GiftCodeFundingMemo::NOTE_DATA_LEN]).unwrap();
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let key = RistrettoPublic::from_random(&mut rng);
        let fee: u64 = 666;
        let hash_bytes = tx_out_public_key_short_hash(&key);
        let fee_bytes = fee.to_be_bytes();

        // Purposely overlap public key, fee, and note bytes
        let mut memo_bytes = [0u8; GiftCodeFundingMemo::MEMO_DATA_LEN];
        memo_bytes[..GiftCodeFundingMemo::HASH_DATA_LEN].copy_from_slice(&hash_bytes);
        memo_bytes
            [(GiftCodeFundingMemo::HASH_DATA_LEN - 1)..(GiftCodeFundingMemo::NOTE_OFFSET - 1)]
            .copy_from_slice(&fee_bytes[1..]);
        memo_bytes
            [(GiftCodeFundingMemo::NOTE_OFFSET - 1)..(GiftCodeFundingMemo::MEMO_DATA_LEN - 1)]
            .copy_from_slice(&[b'6'; GiftCodeFundingMemo::NOTE_DATA_LEN]);

        let memo = GiftCodeFundingMemo::from(&memo_bytes);

        // Check that the hash isn't correctly verified
        assert!(!memo.public_key_matches(&key));

        // Check that fee isn't correct
        assert_ne!(fee, memo.get_fee());

        // Check that the note isn't correct
        assert_ne!(memo.funding_note().unwrap(), note);
    }

    #[test]
    fn test_gift_code_funding_memo_fees_close_to_max_fee_process_as_expected() {
        // Create notes near max length
        const MAX_FEE: u64 = GiftCodeFundingMemo::MAX_FEE;
        const MAX_FEE_MINUS_ONE: u64 = GiftCodeFundingMemo::MAX_FEE - 1;
        const MAX_FEE_PLUS_ONE: u64 = GiftCodeFundingMemo::MAX_FEE + 1;
        let note = "noted";
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let key = RistrettoPublic::from_random(&mut rng);

        // Create memos from notes
        let memo_max_fee_minus_one =
            GiftCodeFundingMemo::new(&key, MAX_FEE_MINUS_ONE, note).unwrap();
        let memo_max_fee = GiftCodeFundingMemo::new(&key, MAX_FEE, note).unwrap();
        let memo_max_fee_plus_one = GiftCodeFundingMemo::new(&key, MAX_FEE_PLUS_ONE, note);

        // Check fees reconstruct correctly or cause error
        assert_eq!(memo_max_fee_minus_one.get_fee(), MAX_FEE_MINUS_ONE);
        assert_eq!(memo_max_fee.get_fee(), MAX_FEE);
        assert_eq!(
            memo_max_fee_plus_one,
            Err(MemoError::MaxFeeExceeded(MAX_FEE, MAX_FEE_PLUS_ONE))
        );

        // Check notes are correct for successful memos
        assert_eq!(memo_max_fee.funding_note().unwrap(), note);
        assert_eq!(memo_max_fee_minus_one.funding_note().unwrap(), note);

        // Check public keys are verified for successful memos
        assert!(memo_max_fee.public_key_matches(&key));
        assert!(memo_max_fee_minus_one.public_key_matches(&key))
    }

    #[test]
    fn test_gift_code_funding_memo_from_valid_bytes_is_okay() {
        // Initialize note and hash bytes
        let note_bytes = [b'6'; GiftCodeFundingMemo::NOTE_DATA_LEN];
        let note = str::from_utf8(&note_bytes).unwrap();
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let key = RistrettoPublic::from_random(&mut rng);
        let hash_bytes = tx_out_public_key_short_hash(&key);
        let fee: u64 = 666;
        let fee_bytes = fee.to_be_bytes();

        // Populate memo with hash and note bytes
        let mut memo_bytes = [0u8; GiftCodeFundingMemo::MEMO_DATA_LEN];
        memo_bytes[..GiftCodeFundingMemo::HASH_DATA_LEN].copy_from_slice(&hash_bytes);
        memo_bytes[GiftCodeFundingMemo::HASH_DATA_LEN..GiftCodeFundingMemo::NOTE_OFFSET]
            .copy_from_slice(&fee_bytes[1..]);
        memo_bytes[GiftCodeFundingMemo::NOTE_OFFSET..GiftCodeFundingMemo::MEMO_DATA_LEN]
            .copy_from_slice(&note_bytes);
        let memo = GiftCodeFundingMemo::from(&memo_bytes);

        // Check that the hash is correctly verified
        assert!(memo.public_key_matches(&key));

        // Check that the fee is correct
        assert_eq!(memo.get_fee(), fee);

        // Check that the note is correct
        assert_eq!(memo.funding_note().unwrap(), note);
    }
}
