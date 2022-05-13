// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Defines the Memo Builder for the gift code cancellation memo (0x0202)
//! specified in MCIP #32

use super::{memo::{UnusedMemo, GiftCodeCancellationMemo}, ReservedDestination, MemoBuilder};
use mc_account_keys::PublicAddress;
use mc_transaction_core::{Amount, MemoContext, MemoPayload, NewMemoError};

/// There are three possible gift code memo types specified in MCIP #32
/// | Memo type bytes | Name                                              |
/// | -----------     | -----------                                       |
/// |    0x0002       | Gift Code Sender Memo                             |
/// |    0x0201       | Gift Code Funding Memo                            |
/// | -->0x0202<--    | Gift Code Cancellation Memo                       |
/// This memo builder builds a gift code cancellation memo (0x0202). Gift code
/// cancellation is defined as the sender sending the gift code TxOut at the
/// gift code subaddress back to their default address prior to it being spent
/// by the receiver. When that happens a zero valued TxOut is sent to the gift
/// code sender's change subaddress with a gift code cancellation memo that
/// stores the index of the TxOut originally sent to the gift code subaddress
/// when the gift code was funded.
#[derive(Clone, Debug)]
pub struct GiftCodeCancellationMemoBuilder {
    // Index of the gift code TxOut that was originally funded
    gift_code_tx_out_global_index: Option<u64>,
    // Whether or not to enable change memos
    gift_code_change_memo_enabled: bool,
    // Whether we've already written the change memo
    wrote_change_memo: bool,
}

impl GiftCodeCancellationMemoBuilder {
    /// Create a new cancellation gift code memo builder
    pub fn new() -> Self {
        Self {
            gift_code_tx_out_global_index: None,
            gift_code_change_memo_enabled: true,
            wrote_change_memo: false,
        }
    }
    /// Set the index of the gift code TxOut that was cancelled
    pub fn set_gift_code_tx_out_index(&mut self, tx_out_global_index: u64) {
        self.gift_code_tx_out_global_index = Some(tx_out_global_index)
    }
    /// Clear the index
    pub fn clear_gift_code_tx_out_index(&mut self) {
        self.gift_code_tx_out_global_index = None;
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

impl MemoBuilder for GiftCodeCancellationMemoBuilder {
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
        }
        if self.wrote_change_memo {
            return Err(NewMemoError::MultipleChangeOutputs);
        }
        self.wrote_change_memo = true;
        if let Some(tx_out_global_index) = self.gift_code_tx_out_global_index.take() {
            return Ok(GiftCodeCancellationMemo::from(tx_out_global_index).into());
        } else {
            return Err(NewMemoError::MissingInput(
                "Missing global index of TxOut to be cancelled".into(),
            ));
        }
    }
}
