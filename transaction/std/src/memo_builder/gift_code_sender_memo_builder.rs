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
}

// Create an empty GiftCodeSenderMemoBuilder
impl Default for GiftCodeSenderMemoBuilder {
    fn default() -> Self {
        Self {
            note: "".into(),
            gift_code_change_memo_enabled: true,
            wrote_change_memo: false,
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
        self.wrote_change_memo = true;
        Ok(GiftCodeSenderMemo::new(self.note.as_str())?.into())
    }
}

mod tests {

    #[test]
    fn test_gift_code() {
        // Tests forthcoming
    }
}
