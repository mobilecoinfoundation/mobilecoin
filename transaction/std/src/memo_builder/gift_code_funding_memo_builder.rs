// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Defines the Memo Builder for the gift code funding memo (0x0201)
//! specified in MCIP #32

use crate::{
    memo::{GiftCodeFundingMemo, UnusedMemo},
    MemoBuilder, ReservedDestination,
};
use mc_account_keys::PublicAddress;
use mc_crypto_keys::RistrettoPublic;
use mc_transaction_core::{Amount, MemoContext, MemoPayload, NewMemoError};

/// There are three possible gift code memo types specified in MCIP #32
/// | Memo type bytes | Name                        |
/// | -----------     | -----------                 |
/// |    0x0002       | Gift Code Sender Memo       |
/// | -->0x0201<--    | Gift Code Funding Memo      |
/// |    0x0202       | Gift Code Cancellation Memo |
/// This memo builder builds a gift code funding memo (0x0201). When a gift
/// code is funded, the amount of the gift code is sent to a TxOut at the
/// Sender's reserved gift code subaddress and a second zero valued TxOut
/// is sent to the sender's reserved change subaddress with the gift code
/// funding memo attached. The funding memo will include the first 4 bytes
/// of the hash of the gift code TxOut sent to the sender's reserved gift
/// code subaddress and 60 bytes for an optional utf-8 memo.
///
/// IMPORTANT NOTE: The public_key of the zero valued TxOut that the Gift Code
/// Funding Memo is written to is NOT the public_key that should be passed into
/// set_gift_code_tx_out_public_key(tx_out_public_key). Instead the public_key
/// of the TxOut sent to the gift code subaddress is what should be passed into
/// set_gift_code_tx_out_public_key(tx_out_public_key)
#[derive(Clone, Debug)]
pub struct GiftCodeFundingMemoBuilder {
    // Utf-8 note within the memo that can be up to 60 bytes long
    note: String,
    // TxOut Public Key of the gift code TxOut sent to the gift code subaddress
    gift_code_tx_out_public_key: Option<RistrettoPublic>,
    // Whether or not to enable change memo
    gift_code_change_memo_enabled: bool,
    // Whether we've already written the change memo
    wrote_change_memo: bool,
    // Whether our last note setting attempt was invalid and the note hasn't
    // been reset with a valid note or cleared
    attempted_invalid_note: bool,
}

// Create an empty GiftCodeFundingMemoBuilder
impl Default for GiftCodeFundingMemoBuilder {
    fn default() -> Self {
        Self {
            note: "".into(),
            gift_code_tx_out_public_key: None,
            gift_code_change_memo_enabled: true,
            wrote_change_memo: false,
            attempted_invalid_note: false,
        }
    }
}

impl GiftCodeFundingMemoBuilder {
    /// Set a utf-8 note (up to 60 bytes) onto the funding memo indicating
    /// what the gift code was for. This method will enforce the 60 byte
    /// limit with a NewMemoErr if the &str passed is longer than
    /// 60 bytes.
    pub fn set_funding_note(&mut self, note: &str) -> Result<(), NewMemoError> {
        if note.len() > GiftCodeFundingMemo::NOTE_DATA_LEN {
            self.attempted_invalid_note = true;
            return Err(NewMemoError::BadInputs(
                "Note memo cannot be greater than 60 bytes".into(),
            ));
        }
        self.attempted_invalid_note = false;
        self.note = note.into();
        Ok(())
    }
    /// Clear the gift code funding note
    pub fn clear_funding_note(&mut self) {
        self.attempted_invalid_note = false;
        self.note = "".into();
    }
    /// Set the TxOut public_key of the gift code TxOut sent to the
    /// reserved gift code subaddress.
    ///
    /// IMPORTANT NOTE: Do NOT pass the public_key of the zero valued change
    /// TxOut that the gift code memo is attached to as an argument. Doing
    /// so will result in an error when attempting to build the memo.
    pub fn set_gift_code_tx_out_public_key(
        &mut self,
        tx_out_public_key: &RistrettoPublic,
    ) -> Result<(), NewMemoError> {
        self.gift_code_tx_out_public_key = Some(*tx_out_public_key);
        Ok(())
    }
    /// Clear the gift code tx_out_public_key
    pub fn clear_gift_code_tx_out_public_key(&mut self) {
        self.gift_code_tx_out_public_key = None;
    }
    /// Enable change memos
    pub fn enable_gift_code_change_memo(&mut self) {
        self.gift_code_change_memo_enabled = true;
    }
    /// Disable change memos
    pub fn disable_gift_code_change_memo(&mut self) {
        self.gift_code_change_memo_enabled = false;
    }
}

impl MemoBuilder for GiftCodeFundingMemoBuilder {
    /// Set the fee
    fn set_fee(&mut self, _fee: Amount) -> Result<(), NewMemoError> {
        Ok(())
    }

    /// Gift code destination memos are not allowed - all gift code
    /// memos accompany TxOuts sent to the change address
    fn make_memo_for_output(
        &mut self,
        _amount: Amount,
        _recipient: &PublicAddress,
        _memo_context: MemoContext,
    ) -> Result<MemoPayload, NewMemoError> {
        Err(NewMemoError::DestinationMemoNotAllowed)
    }

    /// Build a memo for a gift code change output
    fn make_memo_for_change_output(
        &mut self,
        amount: Amount,
        _change_destination: &ReservedDestination,
        memo_context: MemoContext,
    ) -> Result<MemoPayload, NewMemoError> {
        if !self.gift_code_change_memo_enabled {
            return Ok(UnusedMemo {}.into());
        }
        if self.wrote_change_memo {
            return Err(NewMemoError::MultipleChangeOutputs);
        }
        if amount.value > 0 {
            return Err(NewMemoError::BadInputs(
                "Funding memo TxOut should be zero valued".into(),
            ));
        }
        // Prevent callers from writing memo if last note set attempt was a failure
        if self.attempted_invalid_note {
            return Err(NewMemoError::BadInputs(
                "Tried to set a note longer than 64 bytes".into(),
            ));
        }
        if self.gift_code_tx_out_public_key.as_ref() == Some(memo_context.tx_public_key) {
            return Err(NewMemoError::BadInputs("The public_key in the memo should be the TxOut at the gift code subaddress and not that of the memo TxOut".into()));
        }
        if let Some(tx_out_public_key) = self.gift_code_tx_out_public_key.take() {
            self.wrote_change_memo = true;
            Ok(GiftCodeFundingMemo::new(&tx_out_public_key, self.note.as_str())?.into())
        } else {
            Err(NewMemoError::MissingInput(
                "Missing gift code TxOut public key".into(),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{
        build_change_memo_with_amount, build_zero_value_change_memo, MemoDecoder,
    };
    use mc_account_keys::AccountKey;
    use mc_util_from_random::FromRandom;
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn test_gift_code_funding_memo_built_successfully_with_note() {
        // Create memo builder
        let mut builder = GiftCodeFundingMemoBuilder::default();

        // Set the gift code TxOut public key and note
        let mut rng: StdRng = SeedableRng::from_seed([0u8; 32]);
        let gift_code_public_key = RistrettoPublic::from_random(&mut rng);
        let note = "It's MEMO TIME!!";
        builder
            .set_gift_code_tx_out_public_key(&gift_code_public_key)
            .unwrap();
        builder.set_funding_note(note).unwrap();

        // Build the memo payload and get the data
        let memo_payload = build_zero_value_change_memo(&mut builder).unwrap();
        let memo_data = memo_payload.get_memo_data();

        // Verify memo data
        let derived_note = MemoDecoder::decode_funding_note(memo_data);
        let expected_hash = MemoDecoder::tx_out_public_key_short_hash(&gift_code_public_key);
        assert_eq!(note, derived_note);
        assert_eq!(
            expected_hash,
            memo_data[0..GiftCodeFundingMemo::HASH_DATA_LEN]
        );
    }

    #[test]
    fn test_gift_code_funding_memo_built_successfully_without_note() {
        // Create memo builder
        let mut builder = GiftCodeFundingMemoBuilder::default();

        // Set the gift code TxOut public key only
        let mut rng: StdRng = SeedableRng::from_seed([0u8; 32]);
        let gift_code_public_key = RistrettoPublic::from_random(&mut rng);
        builder
            .set_gift_code_tx_out_public_key(&gift_code_public_key)
            .unwrap();

        // Build the memo payload and get the data
        let memo_payload = build_zero_value_change_memo(&mut builder).unwrap();
        let memo_data = memo_payload.get_memo_data();

        // Verify memo data
        let derived_note = MemoDecoder::decode_funding_note(memo_data);
        let expected_hash = MemoDecoder::tx_out_public_key_short_hash(&gift_code_public_key);
        let blank_note = "";
        assert_eq!(blank_note, derived_note);
        assert_eq!(
            expected_hash,
            memo_data[0..GiftCodeFundingMemo::HASH_DATA_LEN]
        );
    }

    #[test]
    fn test_gift_code_funding_memo_fails_to_build_if_key_matches_empty_change_memo_public_key() {
        // Create memo builder
        let mut builder = GiftCodeFundingMemoBuilder::default();

        // Set the gift code note and the public_key as the empty gift code public_key
        let mut rng: StdRng = SeedableRng::from_seed([0u8; 32]);
        let change_tx_public_key = RistrettoPublic::from_random(&mut rng);
        let note = "It's MEMO TIME!!";
        builder
            .set_gift_code_tx_out_public_key(&change_tx_public_key)
            .unwrap();
        builder.set_funding_note(note).unwrap();

        // Build a memo
        let mut rng: StdRng = SeedableRng::from_seed([0u8; 32]);
        let alice = AccountKey::random_with_fog(&mut rng);
        let alice_address_book = ReservedDestination::from(&alice);
        let change_amount = Amount::new(666, 666.into());
        let memo_context = MemoContext {
            tx_public_key: &change_tx_public_key,
        };
        let memo_payload =
            builder.make_memo_for_change_output(change_amount, &alice_address_book, memo_context);

        // Assert memo creation fails
        assert!(matches!(memo_payload, Err(NewMemoError::BadInputs(_))));
    }

    #[test]
    fn test_gift_code_funding_memo_fails_for_nonzero_amount() {
        // Create memo builder
        let mut builder = GiftCodeFundingMemoBuilder::default();

        // Set the gift code TxOut public key and note
        let mut rng: StdRng = SeedableRng::from_seed([0u8; 32]);
        let gift_code_public_key = RistrettoPublic::from_random(&mut rng);
        let note = "It's MEMO TIME!!";
        builder
            .set_gift_code_tx_out_public_key(&gift_code_public_key)
            .unwrap();
        builder.set_funding_note(note).unwrap();

        // Build the memo payload and get the data
        let amount = Amount::new(666, 0.into());
        let memo_payload = build_change_memo_with_amount(&mut builder, amount);
        assert!(matches!(memo_payload, Err(NewMemoError::BadInputs(_))));
    }

    #[test]
    fn test_gift_code_funding_memo_fails_for_more_than_one_change_memo() {
        // Create memo builder
        let mut builder = GiftCodeFundingMemoBuilder::default();

        // Set the gift code TxOut public key and note
        let mut rng: StdRng = SeedableRng::from_seed([0u8; 32]);
        let gift_code_public_key = RistrettoPublic::from_random(&mut rng);
        let note = "It's MEMO TIME!!";
        builder
            .set_gift_code_tx_out_public_key(&gift_code_public_key)
            .unwrap();
        builder.set_funding_note(note).unwrap();

        // Build the memo payload and get the data
        let memo_payload = build_zero_value_change_memo(&mut builder).unwrap();
        let memo_data = memo_payload.get_memo_data();

        // Verify memo data
        let derived_note = MemoDecoder::decode_funding_note(memo_data);
        let expected_hash = MemoDecoder::tx_out_public_key_short_hash(&gift_code_public_key);
        assert_eq!(note, derived_note);
        assert_eq!(
            expected_hash,
            memo_data[0..GiftCodeFundingMemo::HASH_DATA_LEN]
        );

        // Try building another memo and assert failure
        let memo_payload = build_zero_value_change_memo(&mut builder);
        assert!(matches!(
            memo_payload,
            Err(NewMemoError::MultipleChangeOutputs)
        ))
    }

    #[test]
    fn test_gift_code_funding_memo_fields_are_cleared_properly_and_fails_if_no_public_key() {
        // Create memo builder
        let mut builder = GiftCodeFundingMemoBuilder::default();

        // Set the gift code TxOut public key and note
        let mut rng: StdRng = SeedableRng::from_seed([0u8; 32]);
        let gift_code_public_key = RistrettoPublic::from_random(&mut rng);
        let note = "It's MEMO TIME!!";
        builder
            .set_gift_code_tx_out_public_key(&gift_code_public_key)
            .unwrap();
        builder.set_funding_note(note).unwrap();

        // Clear the funding note
        builder.clear_funding_note();

        // Build the memo payload and get the data
        let memo_payload = build_zero_value_change_memo(&mut builder).unwrap();
        let memo_data = memo_payload.get_memo_data();

        // Verify note was cleared
        let blank_note = "";
        let derived_note = MemoDecoder::decode_funding_note(memo_data);
        let expected_hash = MemoDecoder::tx_out_public_key_short_hash(&gift_code_public_key);
        assert_eq!(blank_note, derived_note);
        assert_eq!(
            expected_hash,
            memo_data[0..GiftCodeFundingMemo::HASH_DATA_LEN]
        );

        // Create another memo builder
        let mut builder_2 = GiftCodeFundingMemoBuilder::default();

        // Set the gift code TxOut public key and note
        builder_2
            .set_gift_code_tx_out_public_key(&gift_code_public_key)
            .unwrap();
        builder_2.set_funding_note(note).unwrap();
        builder_2.clear_gift_code_tx_out_public_key();

        // Build the memo payload and ensure we can't build it without the tx public key
        let memo_payload_2 = build_zero_value_change_memo(&mut builder_2);
        assert!(matches!(memo_payload_2, Err(NewMemoError::MissingInput(_))));
    }

    #[test]
    fn test_gift_code_funding_memo_writes_unused_if_change_disabled() {
        // Create memo builder
        let mut builder = GiftCodeFundingMemoBuilder::default();

        // Set the gift code TxOut public key and note
        let mut rng: StdRng = SeedableRng::from_seed([0u8; 32]);
        let gift_code_public_key = RistrettoPublic::from_random(&mut rng);
        let note = "It's MEMO TIME!!";
        builder
            .set_gift_code_tx_out_public_key(&gift_code_public_key)
            .unwrap();
        builder.set_funding_note(note).unwrap();

        // Disable change memos
        builder.disable_gift_code_change_memo();

        // Build the memo payload and get the data
        let memo_payload = build_zero_value_change_memo(&mut builder).unwrap();
        let memo_data = memo_payload.get_memo_data();

        // Assert data is equal to zero byte array
        assert_eq!(memo_data, &[0u8; GiftCodeFundingMemo::MEMO_DATA_LEN]);
    }

    #[test]
    fn test_gift_code_funding_memo_fails_if_last_note_setting_attempt_failed() {
        // Create memo builder
        let mut builder = GiftCodeFundingMemoBuilder::default();

        // Set the gift code TxOut public key
        let mut rng: StdRng = SeedableRng::from_seed([0u8; 32]);
        let gift_code_public_key = RistrettoPublic::from_random(&mut rng);

        // Attempt to set an invalid note longer than allowed bytes
        let note_bytes = [b'6'; GiftCodeFundingMemo::NOTE_DATA_LEN + 1];
        let bad_note = std::str::from_utf8(&note_bytes).unwrap();
        builder
            .set_gift_code_tx_out_public_key(&gift_code_public_key)
            .unwrap();
        let result = builder.set_funding_note(bad_note);

        // Ensure set method errors correctly
        assert!(matches!(result, Err(NewMemoError::BadInputs(_))));

        // Attempt to set the memo anyways and assert our attempt is a failure
        let memo_payload = build_zero_value_change_memo(&mut builder);
        assert!(matches!(memo_payload, Err(NewMemoError::BadInputs(_))));
    }

    #[test]
    fn test_gift_code_funding_memo_succeeds_after_invalid_note_is_reset_with_valid_note() {
        // Create memo builder
        let mut builder = GiftCodeFundingMemoBuilder::default();

        // Set the gift code TxOut public key
        let mut rng: StdRng = SeedableRng::from_seed([0u8; 32]);
        let gift_code_public_key = RistrettoPublic::from_random(&mut rng);

        // Attempt to set an invalid note longer than allowed bytes
        let note_bytes = [b'6'; GiftCodeFundingMemo::NOTE_DATA_LEN + 1];
        let bad_note = std::str::from_utf8(&note_bytes).unwrap();
        builder
            .set_gift_code_tx_out_public_key(&gift_code_public_key)
            .unwrap();
        let result = builder.set_funding_note(bad_note);

        // Ensure set method errors correctly
        assert!(matches!(result, Err(NewMemoError::BadInputs(_))));

        // Set a correct memo and ensure we can build a valid memo
        let correct_note = "I'm also bad mwa-ha (but in a healthy, fun way)";
        builder.set_funding_note(correct_note).unwrap();
        let memo_payload = build_zero_value_change_memo(&mut builder).unwrap();
        let memo_data = memo_payload.get_memo_data();

        // Verify memo data
        let derived_note = MemoDecoder::decode_funding_note(memo_data);
        let expected_hash = MemoDecoder::tx_out_public_key_short_hash(&gift_code_public_key);
        assert_eq!(correct_note, derived_note);
        assert_eq!(
            expected_hash,
            memo_data[0..GiftCodeFundingMemo::HASH_DATA_LEN]
        );
    }
}
