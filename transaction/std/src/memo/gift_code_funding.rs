// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Object for 0x0201 Gift Code Funding memo type
//!
//! This was proposed for standardization in mobilecoinfoundation/mcips/pull/32

use crate::{impl_memo_type_conversions, RegisteredMemoType};
use mc_crypto_hashes::{Blake2b512, Digest};
use mc_crypto_keys::RistrettoPublic;
use mc_transaction_core::MemoError;
use std::{convert::TryInto, str};

/// Mobilecoin account owners can create a special TxOut called a "gift code".
/// This TxOut is sent to a special subaddress at index u64::MAX - 2 and the
/// TxOut private key is sent to the intended recipient. This allows people who
/// don't yet have a Mobilecoin account to receive Mobilecoin. When the sender
/// makes the initial TxOut to the gift code subaddress, this memo will be
/// written to the subaddress reserved for change TxOuts indicating that a gift
/// code was funded. It includes the first 4 bytes of the hash of the TxOut to
/// indicate which TxOut the gift code is at and 60 bytes representing a null
/// terminated utf-8 string
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct GiftCodeFundingMemo {
    /// The data representing the gift code memo
    memo_data: [u8; Self::MEMO_DATA_LEN],
}

impl RegisteredMemoType for GiftCodeFundingMemo {
    const MEMO_TYPE_BYTES: [u8; 2] = [0x02, 0x01];
}

impl GiftCodeFundingMemo {
    /// Create a new gift funding code memo
    pub fn new(tx_out_public_key: &RistrettoPublic, note: &str) -> Result<Self, MemoError> {
        // Check if note is of valid length and initialize memo data
        if note.len() > Self::NOTE_DATA_LEN {
            return Err(MemoError::BadLength(note.len()));
        }
        let mut memo_data = [0u8; Self::MEMO_DATA_LEN];
        // Compute TxOut hash and store it into the memo data
        memo_data[0..Self::HASH_DATA_LEN]
            .copy_from_slice(&tx_out_public_key_short_hash(tx_out_public_key));

        // Put note into memo
        let offset = Self::HASH_DATA_LEN;
        memo_data[offset..(offset + note.len())].copy_from_slice(note.as_bytes());

        Ok(Self { memo_data })
    }

    /// The Length of the TxOut hash
    pub const HASH_DATA_LEN: usize = 4;

    /// The length of the custom memo data
    pub const MEMO_DATA_LEN: usize = 64;

    /// Length of the utf-8 note
    pub const NOTE_DATA_LEN: usize = 60;

    /// Get the memo data
    pub fn memo_data(&self) -> &[u8; Self::MEMO_DATA_LEN] {
        &self.memo_data
    }

    /// Check if a given public key matches
    pub fn public_key_matches(&self, tx_out_public_key: &RistrettoPublic) -> bool {
        tx_out_public_key_short_hash(tx_out_public_key) == self.memo_data[0..Self::HASH_DATA_LEN]
    }

    /// Get funding note from memo
    pub fn funding_note(&self) -> Result<&str, MemoError> {
        let note = str::from_utf8(&self.memo_data[Self::HASH_DATA_LEN..])?;
        if let Some(note) = note.split_once(char::from(0)) {
            return Ok(note.0);
        }
        Ok(note)
    }
}

// Compute first four bytes of TxOut hash
fn tx_out_public_key_short_hash(
    tx_out_public_key: &RistrettoPublic,
) -> [u8; GiftCodeFundingMemo::HASH_DATA_LEN] {
    let mut hasher = Blake2b512::new();
    hasher.update("mc-gift-funding-tx-pub-key");
    hasher.update(tx_out_public_key.as_ref().compress().as_bytes());
    hasher.finalize().as_slice()[0..GiftCodeFundingMemo::HASH_DATA_LEN]
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
        let memo = GiftCodeFundingMemo::new(&key, note).unwrap();

        // Check that the note is extracted properly
        assert_eq!(memo.funding_note().unwrap(), note);

        // Check that the public key can be verified
        assert!(memo.public_key_matches(&key));
    }

    #[test]
    fn test_gift_code_funding_memo_with_blank_note_is_ok() {
        // Initialize key
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let key = RistrettoPublic::from_random(&mut rng);

        // Create memo with blank note
        let note = "";
        let memo = GiftCodeFundingMemo::new(&key, note).unwrap();

        // Check that the note is extracted properly
        assert_eq!(memo.funding_note().unwrap(), note);

        // Check that the public key can be verified
        assert!(memo.public_key_matches(&key));
    }

    #[test]
    fn test_gift_code_funding_memo_with_only_null_memo_bytes_is_okay() {
        // Initialize hash bytes
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let key = RistrettoPublic::from_random(&mut rng);
        let hash_bytes = tx_out_public_key_short_hash(&key);

        // Put only hash bytes into memo_bytes, leaving the rest empty & make memo
        // object
        let mut memo_bytes = [0u8; GiftCodeFundingMemo::MEMO_DATA_LEN];
        memo_bytes[0..GiftCodeFundingMemo::HASH_DATA_LEN].copy_from_slice(&hash_bytes);
        let memo = GiftCodeFundingMemo::from(&memo_bytes);

        // Check that a blank note is extracted properly
        let note = "";
        assert_eq!(memo.funding_note().unwrap(), note);

        // Check that the public key can be verified
        assert!(memo.public_key_matches(&key));
    }

    #[test]
    fn test_gift_code_funding_note_terminates_at_first_null() {
        // Create note from bytes and put two nulls in it
        let mut note_bytes = [b'6'; 8];
        note_bytes[3] = 0;
        note_bytes[6] = 0;
        let note = "666";

        // Create hash bytes
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let key = RistrettoPublic::from_random(&mut rng);
        let hash_bytes = tx_out_public_key_short_hash(&key);

        // Create memo from hash & note bytes
        let mut memo_bytes = [0u8; GiftCodeFundingMemo::MEMO_DATA_LEN];
        memo_bytes[0..GiftCodeFundingMemo::HASH_DATA_LEN].copy_from_slice(&hash_bytes);
        memo_bytes[GiftCodeFundingMemo::HASH_DATA_LEN..(GiftCodeFundingMemo::HASH_DATA_LEN + 8)]
            .copy_from_slice(&note_bytes);
        let memo = GiftCodeFundingMemo::from(&memo_bytes);

        // Check that the hash is correctly verified
        assert!(memo.public_key_matches(&key));

        // Check that the note is extracted properly and terminated at first null
        assert_eq!(memo.funding_note().unwrap(), note);
    }

    #[test]
    fn test_gift_code_funding_memo_verified_with_wrong_public_key_doesnt_match() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let note = "Cash money MeowbleCoin for Kitty";
        let key = RistrettoPublic::from_random(&mut rng);
        let other_key = RistrettoPublic::from_random(&mut rng);
        let memo = GiftCodeFundingMemo::new(&key, note).unwrap();

        // Check that a non-matching public key cannot be correctly verified
        assert!(!memo.public_key_matches(&other_key));
    }

    #[test]
    fn test_gift_code_funding_memo_created_with_notes_near_max_byte_lengths() {
        // Create notes near max length
        let note_len_minus_one =
            str::from_utf8(&[b'6'; GiftCodeFundingMemo::NOTE_DATA_LEN - 1]).unwrap();
        let note_len_exact = str::from_utf8(&[b'6'; GiftCodeFundingMemo::NOTE_DATA_LEN]).unwrap();
        let note_len_plus_one =
            str::from_utf8(&[b'6'; GiftCodeFundingMemo::NOTE_DATA_LEN + 1]).unwrap();
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let key = RistrettoPublic::from_random(&mut rng);

        // Create memos from notes
        let memo_len_minus_one = GiftCodeFundingMemo::new(&key, note_len_minus_one).unwrap();
        let memo_len_exact = GiftCodeFundingMemo::new(&key, note_len_exact).unwrap();
        let memo_len_plus_one = GiftCodeFundingMemo::new(&key, note_len_plus_one);

        // Check note lengths match or error on creation if note is too large
        let _memo_err: Result<GiftCodeFundingMemo, MemoError> =
            Err(MemoError::BadLength(GiftCodeFundingMemo::NOTE_DATA_LEN + 1));
        assert_eq!(
            memo_len_minus_one.funding_note().unwrap(),
            note_len_minus_one
        );
        assert_eq!(memo_len_exact.funding_note().unwrap(), note_len_exact);
        assert!(matches!(memo_len_plus_one, _memo_err));

        // Check public keys match for successful memo lengths for memos that didn't
        // error
        assert!(memo_len_minus_one.public_key_matches(&key));
        assert!(memo_len_exact.public_key_matches(&key));
    }

    #[test]
    fn test_gift_code_funding_memo_created_with_overlapping_byte_allocations_fail() {
        // Create hash bytes and note
        let note = str::from_utf8(&[b'6'; GiftCodeFundingMemo::NOTE_DATA_LEN - 1]).unwrap();
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let key = RistrettoPublic::from_random(&mut rng);
        let hash_bytes = tx_out_public_key_short_hash(&key);

        // Purposely overlap memo and public key bytes
        let mut memo_bytes = [0u8; GiftCodeFundingMemo::MEMO_DATA_LEN];
        memo_bytes[0..GiftCodeFundingMemo::HASH_DATA_LEN].copy_from_slice(&hash_bytes);
        memo_bytes
            [(GiftCodeFundingMemo::HASH_DATA_LEN - 1)..(GiftCodeFundingMemo::MEMO_DATA_LEN - 2)]
            .copy_from_slice(&note.as_bytes());
        let memo = GiftCodeFundingMemo::from(&memo_bytes);

        // Check that the hash isn't correctly verified
        assert!(!memo.public_key_matches(&key));

        // Check that the note is erroneous
        assert_ne!(memo.funding_note().unwrap(), note);
    }

    #[test]
    fn test_gift_code_funding_memo_created_with_corrupted_bytes_fail() {
        // Initialize note and hash bytes
        let note = str::from_utf8(&[b'6'; GiftCodeFundingMemo::NOTE_DATA_LEN - 1]).unwrap();
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let key = RistrettoPublic::from_random(&mut rng);
        let hash_bytes = tx_out_public_key_short_hash(&key);

        // Populate memo with hash and note bytes
        let mut memo_bytes = [0u8; GiftCodeFundingMemo::MEMO_DATA_LEN];
        memo_bytes[0..GiftCodeFundingMemo::HASH_DATA_LEN].copy_from_slice(&hash_bytes);
        memo_bytes[GiftCodeFundingMemo::HASH_DATA_LEN..(GiftCodeFundingMemo::MEMO_DATA_LEN - 1)]
            .copy_from_slice(&note.as_bytes());

        // Corrupt bytes
        memo_bytes[2] = 42;
        memo_bytes[55] = 42;
        let memo = GiftCodeFundingMemo::from(&memo_bytes);

        // Check that the hash isn't correctly verified
        assert!(!memo.public_key_matches(&key));

        // Check that the note is erroneous
        assert_ne!(memo.funding_note().unwrap(), note);
    }

    #[test]
    fn test_gift_code_funding_memo_from_valid_bytes_is_okay() {
        // Initialize note and hash bytes
        let note = str::from_utf8(&[b'6'; GiftCodeFundingMemo::NOTE_DATA_LEN - 1]).unwrap();
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let key = RistrettoPublic::from_random(&mut rng);
        let hash_bytes = tx_out_public_key_short_hash(&key);

        // Populate memo with hash and note bytes
        let mut memo_bytes = [0u8; GiftCodeFundingMemo::MEMO_DATA_LEN];
        memo_bytes[0..GiftCodeFundingMemo::HASH_DATA_LEN].copy_from_slice(&hash_bytes);
        memo_bytes[GiftCodeFundingMemo::HASH_DATA_LEN..(GiftCodeFundingMemo::MEMO_DATA_LEN - 1)]
            .copy_from_slice(&note.as_bytes());
        let memo = GiftCodeFundingMemo::from(&memo_bytes);

        // Check that the hash is correctly verified
        assert!(memo.public_key_matches(&key));

        // Check that the note is correctly verified
        assert_eq!(memo.funding_note().unwrap(), note);
    }
}
