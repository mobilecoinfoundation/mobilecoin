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
/// | Memo type bytes | Name                                              |
/// | -----------     | -----------                                       |
/// |    0x0002       | Gift Code Sender Memo                             |
/// | -->0x0201<--    | Gift Code Funding Memo                            |
/// |    0x0202       | Gift Code Cancellation Memo                       |
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
}

// Create an empty GiftCodeFundingMemoBuilder
impl Default for GiftCodeFundingMemoBuilder {
    fn default() -> Self {
        Self {
            note: "".into(),
            gift_code_tx_out_public_key: None,
            gift_code_change_memo_enabled: true,
            wrote_change_memo: false,
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
            return Err(NewMemoError::BadInputs(
                "Note memo cannot be greater than 60 bytes".into(),
            ));
        }
        self.note = note.into();
        Ok(())
    }
    /// Clear the gift code funding note
    pub fn clear_funding_note(&mut self) {
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
        tx_out_public_key: RistrettoPublic,
    ) -> Result<(), NewMemoError> {
        self.gift_code_tx_out_public_key = Some(tx_out_public_key);
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
        _amount: Amount,
        _change_destination: &ReservedDestination,
        memo_context: MemoContext,
    ) -> Result<MemoPayload, NewMemoError> {
        if !self.gift_code_change_memo_enabled {
            return Ok(UnusedMemo {}.into());
        }
        if self.wrote_change_memo {
            return Err(NewMemoError::MultipleChangeOutputs);
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

mod tests {

    #[test]
    fn test_gift_code() {
        // Tests forthcoming
    }
}
