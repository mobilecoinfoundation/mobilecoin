// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Defines the Memo Builder for the gift code sender memo (0x0002)
//! specified in MCIP #32

use crate::{memo::GiftCodeSenderMemo, MemoBuilder, ReservedSubaddresses};
use mc_account_keys::PublicAddress;
use mc_transaction_core::{tokens::Mob, Amount, MemoContext, MemoPayload, NewMemoError, Token};

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
/// the Receiver can use to record any information they desire about the
/// gift code.
#[derive(Clone, Debug)]
pub struct GiftCodeSenderMemoBuilder {
    // Utf-8 formatted note within the memo that can be up to 64 bytes long
    note: String,
    // Whether we've already written the change memo
    wrote_change_memo: bool,
    // Fee paid to redeem gift code
    fee: Amount,
}

impl GiftCodeSenderMemoBuilder {
    /// Initialize memo builder with a utf-8 note (up to 57 bytes). This
    /// method will enforce the 57 byte limit with a NewMemoErr if the
    /// note passed is longer than 57 bytes.
    pub fn new(note: &str) -> Result<Self, NewMemoError> {
        if note.len() > GiftCodeSenderMemo::NOTE_DATA_LEN {
            return Err(NewMemoError::BadInputs(format!(
                "Note memo cannot be greater than {} bytes",
                GiftCodeSenderMemo::NOTE_DATA_LEN
            )));
        }
        Ok(Self {
            note: note.into(),
            wrote_change_memo: false,
            fee: Amount::new(Mob::MINIMUM_FEE, Mob::ID),
        })
    }
}

impl MemoBuilder for GiftCodeSenderMemoBuilder {
    /// Set the fee
    fn set_fee(&mut self, fee: Amount) -> Result<(), NewMemoError> {
        if self.wrote_change_memo {
            return Err(NewMemoError::FeeAfterChange);
        }
        if fee.value > GiftCodeSenderMemo::MAX_FEE {
            return Err(NewMemoError::MaxFeeExceeded(
                GiftCodeSenderMemo::MAX_FEE,
                fee.value,
            ));
        }
        self.fee = fee;
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
        amount: Amount,
        _change_destination: &ReservedSubaddresses,
        _memo_context: MemoContext,
    ) -> Result<MemoPayload, NewMemoError> {
        if self.wrote_change_memo {
            return Err(NewMemoError::MultipleChangeOutputs);
        };
        // fee and change amount token id must match
        if self.fee.token_id != amount.token_id {
            return Err(NewMemoError::MixedTokenIds);
        }
        self.wrote_change_memo = true;
        Ok(GiftCodeSenderMemo::new(self.fee.value, self.note.as_str())?.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::build_change_memo_with_amount;
    use assert_matches::assert_matches;

    #[test]
    fn test_gift_code_sender_memo_built_successfully_with_note() {
        // Create memo builder with note
        let note = "It's MEMO TIME!!";
        let mut builder = GiftCodeSenderMemoBuilder::new(note).unwrap();

        // Build the memo payload and get the data
        let amount = Amount::new(42, 0.into());
        let fee = Amount::new(10, 0.into());
        builder.set_fee(fee).unwrap();

        let memo_payload = build_change_memo_with_amount(&mut builder, amount).unwrap();

        // Verify memo data
        let derived_memo = GiftCodeSenderMemo::from(memo_payload.get_memo_data());
        assert_eq!(note, derived_memo.sender_note().unwrap());
        assert_eq!(fee.value, derived_memo.get_fee());
    }

    #[test]
    fn test_gift_code_sender_memo_built_successfully_with_blank_note_and_notes_close_to_max_length()
    {
        // Create edge case notes
        let amount = Amount::new(42, 0.into());
        let fee = Amount::new(10, 0.into());
        let blank_note = "";
        let note_minus_one =
            std::str::from_utf8(&[b'6'; GiftCodeSenderMemo::NOTE_DATA_LEN - 1]).unwrap();
        let note_exact = std::str::from_utf8(&[b'6'; GiftCodeSenderMemo::NOTE_DATA_LEN]).unwrap();

        // Verify blank note is okay
        {
            let mut builder = GiftCodeSenderMemoBuilder::new(blank_note).unwrap();
            builder.set_fee(fee).unwrap();

            // Build the memo payload and get the data
            let memo_payload = build_change_memo_with_amount(&mut builder, amount).unwrap();

            // Verify memo data
            let derived_memo = GiftCodeSenderMemo::from(memo_payload.get_memo_data());
            assert_eq!(blank_note, derived_memo.sender_note().unwrap());
            assert_eq!(fee.value, derived_memo.get_fee());
        }

        // Verify note with max length minus one is okay
        {
            let mut builder = GiftCodeSenderMemoBuilder::new(note_minus_one).unwrap();
            builder.set_fee(fee).unwrap();

            // Build the memo payload and get the data
            let memo_payload = build_change_memo_with_amount(&mut builder, amount).unwrap();

            // Verify memo data
            let derived_memo = GiftCodeSenderMemo::from(memo_payload.get_memo_data());
            assert_eq!(note_minus_one, derived_memo.sender_note().unwrap());
            assert_eq!(fee.value, derived_memo.get_fee());
        }

        // Verify note with max length okay
        {
            let mut builder = GiftCodeSenderMemoBuilder::new(note_exact).unwrap();
            builder.set_fee(fee).unwrap();

            // Build the memo payload and get the data
            let memo_payload = build_change_memo_with_amount(&mut builder, amount).unwrap();

            // Verify memo data
            let derived_memo = GiftCodeSenderMemo::from(memo_payload.get_memo_data());
            assert_eq!(note_exact, derived_memo.sender_note().unwrap());
            assert_eq!(fee.value, derived_memo.get_fee());
        }
    }

    #[test]
    fn test_gift_code_sender_memo_fails_for_more_than_one_change_memo() {
        // Create memo builder with note
        let note = "It's MEMO TIME!!";
        let mut builder = GiftCodeSenderMemoBuilder::new(note).unwrap();

        // Build the memo payload and get the data
        let amount = Amount::new(42, 0.into());
        let fee = Amount::new(10, 0.into());
        builder.set_fee(fee).unwrap();

        let memo_payload = build_change_memo_with_amount(&mut builder, amount).unwrap();

        // Verify memo data can be verified after writing the first change memo
        let derived_memo = GiftCodeSenderMemo::from(memo_payload.get_memo_data());
        assert_eq!(note, derived_memo.sender_note().unwrap());
        assert_eq!(fee.value, derived_memo.get_fee());

        // Verify attempting to write two change memos fail
        let memo_payload_2 = build_change_memo_with_amount(&mut builder, amount);
        assert_eq!(memo_payload_2, Err(NewMemoError::MultipleChangeOutputs));
    }

    #[test]
    fn test_gift_code_sender_note_builder_creation_fails_with_invalid_note() {
        // Create Memo Builder with an input longer than allowed
        let note_bytes = [b'6'; GiftCodeSenderMemo::NOTE_DATA_LEN + 1];
        let note = std::str::from_utf8(&note_bytes).unwrap();
        let builder = GiftCodeSenderMemoBuilder::new(note);
        assert_matches!(builder, Err(NewMemoError::BadInputs(_)));
    }

    #[test]
    fn test_gift_code_sender_memo_builder_fee_token_cannot_be_different_from_change_token() {
        let note = "It's MEMO TIME!!";
        let mut builder = GiftCodeSenderMemoBuilder::new(note).unwrap();
        let amount = Amount::new(42, 0.into());
        let fee = Amount::new(1, 9001.into());

        // Set a fee with a different token id
        builder.set_fee(fee).unwrap();

        // Attempt to build the memo
        let memo_payload = build_change_memo_with_amount(&mut builder, amount);

        // Ensure memo creation fails
        assert_eq!(memo_payload, Err(NewMemoError::MixedTokenIds))
    }

    #[test]
    fn test_gift_code_sender_memo_builder_set_fee_fails_when_exceeding_max_fee() {
        let note = "It's MEMO TIME!!";
        let mut builder = GiftCodeSenderMemoBuilder::new(note).unwrap();
        let fee = Amount::new(u64::MAX, 0.into());

        // Try to set a fee above max allowed
        let result = builder.set_fee(fee);
        assert_eq!(
            result,
            Err(NewMemoError::MaxFeeExceeded(
                GiftCodeSenderMemo::MAX_FEE,
                fee.value
            ))
        );
    }
}
