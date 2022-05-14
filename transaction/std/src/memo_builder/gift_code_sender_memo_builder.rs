// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Defines the Memo Builder for the gift code sender memo (0x0002)
//! specified in MCIP #32

use crate::{
    memo::{GiftCodeSenderMemo, UnusedMemo},
    MemoBuilder, ReservedDestination,
};
use mc_account_keys::PublicAddress;
use mc_transaction_core::{Amount, MemoContext, MemoPayload, NewMemoError};

/// There are three possible gift code memo types specified in MCIP #32
/// | Memo type bytes | Name                                              |
/// | -----------     | -----------                                       |
/// | -->0x0002<--    | Gift Code Sender Memo                             |
/// |    0x0201       | Gift Code Funding Memo                            |
/// |    0x0202       | Gift Code Cancellation Memo                       |
/// This memo builder builds a gift code sender memo (0x0002). A gift code
/// considered redeemed when the Receiver uses the TxOut spend private key
/// of the gift code TxOut they received from the Sender to send the TxOut
/// from the sender's gift code subaddress to their own change subaddress.
/// The destination memo is written into that TxOut at the change address
/// and includes an optional Utf-8 note up to 64 bytes long the Receiver
/// can use to record any information they desire about the gift code.
#[derive(Clone, Debug)]
pub struct GiftCodeSenderMemoBuilder {
    // Utf-8 formatted note within the memo that can be up to 64 bytes long
    note: String,
    // Whether or not to enable change memos
    gift_code_change_memo_enabled: bool,
    // Whether we've already written the change memo
    wrote_change_memo: bool,
    // Whetever we've set a valid note
    wrote_valid_note: bool,
}

// Create an empty GiftCodeSenderMemoBuilder
impl Default for GiftCodeSenderMemoBuilder {
    fn default() -> Self {
        Self {
            note: "".into(),
            gift_code_change_memo_enabled: true,
            wrote_change_memo: false,
            wrote_valid_note: true,
        }
    }
}

impl GiftCodeSenderMemoBuilder {
    /// Set a utf-8 note (up to 64 bytes) onto the sender memo indicating
    /// any desired info about the gift code. This method will enforce the
    /// 64 byte limit with a NewMemoErr if the &str passed is longer than
    /// 64 bytes.
    pub fn set_gift_code_sender_note(&mut self, note: &str) -> Result<(), NewMemoError> {
        if note.len() > GiftCodeSenderMemo::MEMO_DATA_LEN {
            self.wrote_valid_note = false;
            return Err(NewMemoError::BadInputs(
                "Sender note cannot be longer than 64 bytes".into(),
            ));
        }
        self.note = note.into();
        Ok(())
    }
    /// Clear the gift code sender note
    pub fn clear_sender_note(&mut self) {
        self.note = "".into();
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

impl MemoBuilder for GiftCodeSenderMemoBuilder {
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
        _amount: Amount,
        _change_destination: &ReservedDestination,
        _memo_context: MemoContext,
    ) -> Result<MemoPayload, NewMemoError> {
        if !self.gift_code_change_memo_enabled {
            return Ok(UnusedMemo {}.into());
        };
        if self.wrote_change_memo {
            return Err(NewMemoError::MultipleChangeOutputs);
        };
        if !self.wrote_valid_note {
            return Err(NewMemoError::BadInputs(
                "Tried to set a note longer than 64 bytes".into(),
            ));
        }
        self.wrote_change_memo = true;
        Ok(GiftCodeSenderMemo::new(self.note.as_str())?.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::build_change_memo_with_amount;

    /// Get the sender note
    fn get_sender_note(memo_data: &[u8; GiftCodeSenderMemo::MEMO_DATA_LEN]) -> &str {
        let index = if let Some(terminator) = memo_data.iter().position(|b| b == &0u8) {
            terminator
        } else {
            GiftCodeSenderMemo::MEMO_DATA_LEN
        };

        std::str::from_utf8(&memo_data[0..index]).unwrap()
    }

    #[test]
    fn test_gift_code_sender_memo_built_successfully_with_note() {
        // Create memo builder
        let mut builder = GiftCodeSenderMemoBuilder::default();

        // Set the note
        let note = "It's MEMO TIME!!";
        builder.set_gift_code_sender_note(note).unwrap();

        // Build the memo payload and get the data
        let amount = Amount::new(42, 0.into());
        let memo_payload = build_change_memo_with_amount(&mut builder, amount).unwrap();

        // Verify memo data
        let derived_note = get_sender_note(memo_payload.get_memo_data());
        assert_eq!(note, derived_note);
    }

    #[test]
    fn test_gift_code_sender_memo_built_successfully_without_note() {
        // Create memo builder
        let mut builder = GiftCodeSenderMemoBuilder::default();

        // Build the memo payload and get the data
        let amount = Amount::new(42, 0.into());
        let memo_payload = build_change_memo_with_amount(&mut builder, amount).unwrap();

        // Verify memo data
        let blank_note = "";
        let derived_note = get_sender_note(memo_payload.get_memo_data());
        assert_eq!(blank_note, derived_note);
    }

    #[test]
    fn test_gift_code_sender_memo_fails_for_more_than_one_change_memo() {
        // Create memo builder
        let mut builder = GiftCodeSenderMemoBuilder::default();

        // Set the note
        let note = "It's MEMO TIME!!";
        builder.set_gift_code_sender_note(note).unwrap();

        // Build the memo payload and get the data
        let amount = Amount::new(42, 0.into());
        let memo_payload = build_change_memo_with_amount(&mut builder, amount).unwrap();

        // Verify memo data works once
        let derived_note = get_sender_note(memo_payload.get_memo_data());
        assert_eq!(note, derived_note);

        // Verify memo_data doesn't work more than once
        let amount_2 = Amount::new(42, 0.into());
        let memo_payload_2 = build_change_memo_with_amount(&mut builder, amount_2);

        let matches = matches!(memo_payload_2, Err(NewMemoError::MultipleChangeOutputs));
        assert!(matches);
    }

    #[test]
    fn test_gift_code_sender_memo_fields_are_cleared_properly() {
        // Create memo builder
        let mut builder = GiftCodeSenderMemoBuilder::default();

        // Set the note
        let note = "It's MEMO TIME!!";
        builder.set_gift_code_sender_note(note).unwrap();
        builder.clear_sender_note();

        // Build the memo payload
        let amount = Amount::new(42, 0.into());
        let memo_payload = build_change_memo_with_amount(&mut builder, amount).unwrap();

        // Verify memo data
        let blank_note = "";
        let derived_note = get_sender_note(memo_payload.get_memo_data());
        assert_eq!(blank_note, derived_note);

        // Create another memo builder
        let mut builder_2 = GiftCodeSenderMemoBuilder::default();

        // Set the cancellation index and then set another note on top of it
        let note_2 = "Is anything actually real?";
        builder_2.set_gift_code_sender_note(note).unwrap();
        builder_2.set_gift_code_sender_note(note_2).unwrap();

        // Build the memo payload and get the data
        let amount_2 = Amount::new(666, 0.into());
        let memo_payload_2 = build_change_memo_with_amount(&mut builder_2, amount_2).unwrap();
        let derived_note_2 = get_sender_note(memo_payload_2.get_memo_data());
        assert_eq!(note_2, derived_note_2);
    }

    #[test]
    fn test_gift_code_sender_memo_writes_unused_if_change_disabled() {
        // Create memo builder
        let mut builder = GiftCodeSenderMemoBuilder::default();

        // Set the note
        let note = "It's MEMO TIME!!";
        builder.set_gift_code_sender_note(note).unwrap();

        // Disable change memos
        builder.disable_gift_code_change_memo();

        // Build the memo payload
        let amount = Amount::new(42, 0.into());
        let memo_payload = build_change_memo_with_amount(&mut builder, amount).unwrap();
        assert_eq!(memo_payload.get_memo_data(), &[0u8; 64]);
    }

    #[test]
    fn test_gift_code_sender_builder_doesnt_allow_invalid_note_length() {
        // Create memo builder
        let mut builder = GiftCodeSenderMemoBuilder::default();

        // Set an invalid note
        let note_bytes = [b'6'; GiftCodeSenderMemo::MEMO_DATA_LEN + 1];
        let note = std::str::from_utf8(&note_bytes).unwrap();
        let result = builder.set_gift_code_sender_note(note);
        assert!(matches!(result, Err(NewMemoError::BadInputs(_))));

        // Try to build after failing to set note
        let amount = Amount::new(42, 0.into());
        let memo_payload = build_change_memo_with_amount(&mut builder, amount);
        assert!(matches!(memo_payload, Err(NewMemoError::BadInputs(_))));
    }
}
