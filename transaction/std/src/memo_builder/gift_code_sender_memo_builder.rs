// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Defines the Memo Builder for the gift code sender memo (0x0002)
//! specified in MCIP #32

use crate::{memo::GiftCodeSenderMemo, MemoBuilder, ReservedDestination};
use mc_account_keys::PublicAddress;
use mc_transaction_core::{Amount, MemoContext, MemoPayload, NewMemoError};

/// There are three possible gift code memo types specified in MCIP #32
/// | Memo type bytes | Name                        |
/// | -----------     | -----------                 |
/// | -->0x0002<--    | Gift Code Sender Memo       |
/// |    0x0201       | Gift Code Funding Memo      |
/// |    0x0202       | Gift Code Cancellation Memo |
/// This memo builder builds the gift code sender memo (0x0002). A gift code
/// considered redeemed when the Receiver uses the TxOut spend private key
/// of the gift code TxOut they received from the Sender to send the TxOut
/// from the sender's gift code subaddress to their own change subaddress.
/// The sender memo is written into the TxOut the receiver sends to the
/// change address and includes an optional Utf-8 note up to 64 bytes long
/// the Receiver can  use to record any information they desire about the
/// gift code.
#[derive(Clone, Debug)]
pub struct GiftCodeSenderMemoBuilder {
    // Utf-8 formatted note within the memo that can be up to 64 bytes long
    note: String,
    // Whether we've already written the change memo
    wrote_change_memo: bool,
}

impl GiftCodeSenderMemoBuilder {
    /// Initialize memo builder with a utf-8 note (up to 64 bytes), This
    /// method will enforce the 64 byte limit with a NewMemoErr if the
    /// note passed is longer than 64 bytes.
    pub fn new(note: &str) -> Result<Self, NewMemoError> {
        if note.len() > GiftCodeSenderMemo::MEMO_DATA_LEN {
            return Err(NewMemoError::BadInputs(
                "Sender note cannot be longer than 64 bytes".into(),
            ));
        }
        Ok(Self {
            note: note.into(),
            wrote_change_memo: false,
        })
    }
}

impl MemoBuilder for GiftCodeSenderMemoBuilder {
    /// Set the fee
    fn set_fee(&mut self, _fee: Amount) -> Result<(), NewMemoError> {
        Ok(())
    }

    /// Destination memos are not allowed for gift code sender memos
    fn make_memo_for_output(
        &mut self,
        _amount: Amount,
        _recipient: &PublicAddress,
        _memo_context: MemoContext,
    ) -> Result<MemoPayload, NewMemoError> {
        Err(NewMemoError::DestinationMemoNotAllowed)
    }

    /// Write the sender memo to the TxOut the receiver sends to their change
    /// address when the gift code is redeemed
    fn make_memo_for_change_output(
        &mut self,
        _amount: Amount,
        _change_destination: &ReservedDestination,
        _memo_context: MemoContext,
    ) -> Result<MemoPayload, NewMemoError> {
        if self.wrote_change_memo {
            return Err(NewMemoError::MultipleChangeOutputs);
        };
        self.wrote_change_memo = true;
        Ok(GiftCodeSenderMemo::new(self.note.as_str())?.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::build_change_memo_with_amount;

    #[test]
    fn test_gift_code_sender_memo_built_successfully_with_note() {
        // Create memo builder with note
        let note = "It's MEMO TIME!!";
        let mut builder = GiftCodeSenderMemoBuilder::new(note).unwrap();

        // Build the memo payload and get the data
        let amount = Amount::new(42, 0.into());
        let memo_payload = build_change_memo_with_amount(&mut builder, amount).unwrap();

        // Verify memo data
        let derived_note = GiftCodeSenderMemo::from(memo_payload.get_memo_data());
        assert_eq!(note, derived_note.sender_note().unwrap());
    }

    #[test]
    fn test_gift_code_sender_memo_built_successfully_with_blank_note_and_notes_close_to_max_length()
    {
        // Create edge case notes
        let amount = Amount::new(42, 0.into());
        let blank_note = "";
        let note_minus_one =
            std::str::from_utf8(&[b'6'; GiftCodeSenderMemo::MEMO_DATA_LEN - 1]).unwrap();
        let note_exact = std::str::from_utf8(&[b'6'; GiftCodeSenderMemo::MEMO_DATA_LEN]).unwrap();

        // Verify blank note is okay
        {
            let mut builder = GiftCodeSenderMemoBuilder::new(blank_note).unwrap();

            // Build the memo payload and get the data
            let memo_payload = build_change_memo_with_amount(&mut builder, amount).unwrap();

            // Verify memo data
            let derived_note = GiftCodeSenderMemo::from(memo_payload.get_memo_data());
            assert_eq!(blank_note, derived_note.sender_note().unwrap());
        }

        // Verify note with max length minus one is okay
        {
            let mut builder = GiftCodeSenderMemoBuilder::new(note_minus_one).unwrap();

            // Build the memo payload and get the data
            let memo_payload = build_change_memo_with_amount(&mut builder, amount).unwrap();

            // Verify memo data
            let derived_note = GiftCodeSenderMemo::from(memo_payload.get_memo_data());
            assert_eq!(note_minus_one, derived_note.sender_note().unwrap());
        }

        // Verify note with max length okay
        {
            let mut builder = GiftCodeSenderMemoBuilder::new(note_exact).unwrap();

            // Build the memo payload and get the data
            let memo_payload = build_change_memo_with_amount(&mut builder, amount).unwrap();

            // Verify memo data
            let derived_note = GiftCodeSenderMemo::from(memo_payload.get_memo_data());
            assert_eq!(note_exact, derived_note.sender_note().unwrap());
        }
    }

    #[test]
    fn test_gift_code_sender_memo_fails_for_more_than_one_change_memo() {
        // Create memo builder with note
        let note = "It's MEMO TIME!!";
        let mut builder = GiftCodeSenderMemoBuilder::new(note).unwrap();

        // Build the memo payload and get the data
        let amount = Amount::new(42, 0.into());
        let memo_payload = build_change_memo_with_amount(&mut builder, amount).unwrap();

        // Verify memo data can be verified after writing the first change memo
        let derived_note = GiftCodeSenderMemo::from(memo_payload.get_memo_data());
        assert_eq!(note, derived_note.sender_note().unwrap());

        // Verify attempting to write two change memos fail
        let memo_payload_2 = build_change_memo_with_amount(&mut builder, amount);
        assert!(matches!(
            memo_payload_2,
            Err(NewMemoError::MultipleChangeOutputs)
        ));
    }

    #[test]
    fn test_gift_code_sender_note_builder_creation_fails_with_invalid_note() {
        // Create Memo Builder with an input longer than allowed
        let note_bytes = [b'6'; GiftCodeSenderMemo::MEMO_DATA_LEN + 1];
        let note = std::str::from_utf8(&note_bytes).unwrap();
        let builder = GiftCodeSenderMemoBuilder::new(note);
        assert!(matches!(builder, Err(NewMemoError::BadInputs(_))));
    }
}
