// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Defines the Memo Builder for the gift code cancellation memo (0x0202)
//! specified in MCIP #32

use super::{
    memo::{GiftCodeCancellationMemo, UnusedMemo},
    MemoBuilder, ReservedDestination,
};
use mc_account_keys::PublicAddress;
use mc_transaction_core::{Amount, MemoContext, MemoPayload, NewMemoError};

/// There are three possible gift code memo types specified in MCIP #32
/// | Memo type bytes | Name                        |
/// | -----------     | -----------                 |
/// |    0x0002       | Gift Code Sender Memo       |
/// |    0x0201       | Gift Code Funding Memo      |
/// | -->0x0202<--    | Gift Code Cancellation Memo |
/// This memo builder builds a gift code cancellation memo (0x0202). Gift code
/// cancellation is defined as the sender sending the gift code TxOut at the
/// gift code subaddress back to their default address prior to it being spent
/// by the receiver. When that happens a change TxOut is sent to the gift
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

// Create an empty GiftCodeCancellationMemoBuilder
impl Default for GiftCodeCancellationMemoBuilder {
    fn default() -> Self {
        Self {
            gift_code_tx_out_global_index: None,
            gift_code_change_memo_enabled: true,
            wrote_change_memo: false,
        }
    }
}

impl GiftCodeCancellationMemoBuilder {
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

    /// Gift code cancellation memos write blank memos to destination TxOut(s)
    fn make_memo_for_output(
        &mut self,
        _amount: Amount,
        _recipient: &PublicAddress,
        _memo_context: MemoContext,
    ) -> Result<MemoPayload, NewMemoError> {
        Ok(UnusedMemo {}.into())
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
        if self.gift_code_tx_out_global_index.is_none() {
            return Err(NewMemoError::MissingInput(
                "Must specify gift code TxOut global index".into(),
            ));
        }
        self.wrote_change_memo = true;
        if let Some(tx_out_global_index) = self.gift_code_tx_out_global_index.take() {
            Ok(GiftCodeCancellationMemo::from(tx_out_global_index).into())
        } else {
            Err(NewMemoError::MissingInput(
                "Missing global index of TxOut to be cancelled".into(),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::build_zero_value_change_memo;
    use std::convert::TryInto;

    #[test]
    fn test_gift_code_cancellation_memo_built_successfully_with_index() {
        // Create memo builder
        let mut builder = GiftCodeCancellationMemoBuilder::default();

        // Set the cancellation index
        let index = 666;
        builder.set_gift_code_tx_out_index(index);

        // Build the memo payload and get the data
        let memo_payload = build_zero_value_change_memo(&mut builder).unwrap();
        let memo_data = memo_payload.get_memo_data();

        // Verify memo data
        let derived_index = u64::from_le_bytes(memo_data[0..8].try_into().unwrap());
        assert_eq!(index, derived_index);
    }

    #[test]
    fn test_gift_code_cancellation_memo_fails_without_index() {
        // Instantiate memo builder
        let mut builder = GiftCodeCancellationMemoBuilder::default();

        // Build the memo payload
        let memo_payload = build_zero_value_change_memo(&mut builder);

        // Assert we've created the correct error
        assert!(matches!(memo_payload, Err(NewMemoError::MissingInput(_))));
    }

    #[test]
    fn test_gift_code_cancellation_memo_fails_for_more_than_one_change_memo() {
        // Create memo builder
        let mut builder = GiftCodeCancellationMemoBuilder::default();

        // Set the cancellation index
        let index = 666;
        builder.set_gift_code_tx_out_index(index);

        // Build the memo payload
        build_zero_value_change_memo(&mut builder).unwrap();
        let memo_payload = build_zero_value_change_memo(&mut builder);
        assert!(matches!(
            memo_payload,
            Err(NewMemoError::MultipleChangeOutputs)
        ));
    }

    #[test]
    fn test_gift_code_cancellation_memo_fields_are_set_and_cleared_properly() {
        // Create memo builder
        let mut builder = GiftCodeCancellationMemoBuilder::default();

        // Set the cancellation index, and then replace it
        let index = 666;
        builder.set_gift_code_tx_out_index(index);
        let replacement_index = 420;
        builder.set_gift_code_tx_out_index(replacement_index);

        // Build the memo payload and get the data
        let memo_payload = build_zero_value_change_memo(&mut builder).unwrap();
        let memo_data = memo_payload.get_memo_data();

        // Verify memo data
        let derived_index = u64::from_le_bytes(memo_data[0..8].try_into().unwrap());
        assert_eq!(replacement_index, derived_index);

        // Create another memo builder
        let mut builder_2 = GiftCodeCancellationMemoBuilder::default();

        // Set the cancellation index and then clear it
        let index_2 = 666;
        builder_2.set_gift_code_tx_out_index(index_2);
        builder_2.clear_gift_code_tx_out_index();

        // Build the memo payload and get the data
        let memo_payload_2 = build_zero_value_change_memo(&mut builder_2);
        assert!(matches!(memo_payload_2, Err(NewMemoError::MissingInput(_))));
    }

    #[test]
    fn test_gift_code_cancellation_memo_writes_unused_if_change_disabled() {
        // Create memo builder
        let mut builder = GiftCodeCancellationMemoBuilder::default();

        // Set the cancellation index
        let index = 666;
        builder.set_gift_code_tx_out_index(index);

        // Disable change outputs
        builder.disable_gift_code_change_memo();

        // Build the memo payload and get the data
        let memo_payload = build_zero_value_change_memo(&mut builder).unwrap();

        // Verify memo data is blank
        assert_eq!(memo_payload.get_memo_data(), &[0u8; 64]);
    }
}
