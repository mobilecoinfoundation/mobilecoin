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
    pub fn new(tx_out_public_key: RistrettoPublic, note: &str) -> Result<Self, MemoError> {
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
    /// TODO: Should this be constant time?
    pub fn public_key_matches(&self, tx_out_public_key: RistrettoPublic) -> bool {
        tx_out_public_key_short_hash(tx_out_public_key) == self.memo_data[0..4]
    }

    /// Get funding note from memo
    pub fn funding_note(&self) -> &str {
        let note_data = &self.memo_data[Self::HASH_DATA_LEN..];
        str::from_utf8(note_data)
            .unwrap()
            .trim_matches(char::from(0))
    }
}

// Compute first four bytes of TxOut hash
fn tx_out_public_key_short_hash(
    tx_out_public_key: RistrettoPublic,
) -> [u8; GiftCodeFundingMemo::HASH_DATA_LEN] {
    let mut hasher = Blake2b512::new();
    hasher.update("mc-memo-mac");
    hasher.update(tx_out_public_key.as_ref().compress().as_bytes());
    hasher.finalize().as_slice()[0..GiftCodeFundingMemo::HASH_DATA_LEN]
        .try_into()
        .unwrap()
}

impl From<&[u8; 64]> for GiftCodeFundingMemo {
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
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let note = "Cash money MeowbleCoin for Kitty";
        let txout_public_key = RistrettoPublic::from_random(&mut rng);
        let memo = GiftCodeFundingMemo::new(txout_public_key, note).unwrap();

        // Check that the note is extracted properly
        assert_eq!(memo.funding_note(), note);

        // Check that the public key can be verified
        assert!(memo.public_key_matches(txout_public_key));
    }
}
