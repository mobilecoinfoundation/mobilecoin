// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Defines the Memo Builder for the gift code cancellation memo (0x0202)
//! specified in MCIP #32

use super::{memo::GiftCodeCancellationMemo, MemoBuilder, ReservedSubaddresses};
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
/// gift code subaddress to their change address prior to it being spent by
/// the receiver. When that happens a gift code cancellation memo is
/// written to the change TxOut that stores the index of the TxOut originally
/// sent to the gift code subaddress when the gift code was funded.
#[derive(Clone, Debug)]
pub struct GiftCodeCancellationMemoBuilder {
    // Index of the gift code TxOut that was originally funded
    gift_code_tx_out_global_index: u64,
    // Whether we've already written the change memo
    wrote_change_memo: bool,
}

impl GiftCodeCancellationMemoBuilder {
    /// Initialize memo builder with the index of the originally
    /// funded gift code TxOut
    pub fn new(gift_code_tx_out_global_index: u64) -> Self {
        Self {
            gift_code_tx_out_global_index,
            wrote_change_memo: false,
        }
    }
}

impl MemoBuilder for GiftCodeCancellationMemoBuilder {
    /// Set the fee
    fn set_fee(&mut self, _fee: Amount) -> Result<(), NewMemoError> {
        Ok(())
    }

    /// Destination memos for gift code cancellation memos are not allowed
    fn make_memo_for_output(
        &mut self,
        _amount: Amount,
        _recipient: &PublicAddress,
        _memo_context: MemoContext,
    ) -> Result<MemoPayload, NewMemoError> {
        Err(NewMemoError::DestinationMemoNotAllowed)
    }

    /// Write the cancellation memo to the change output
    fn make_memo_for_change_output(
        &mut self,
        _amount: Amount,
        _change_destination: &ReservedSubaddresses,
        _memo_context: MemoContext,
    ) -> Result<MemoPayload, NewMemoError> {
        if self.wrote_change_memo {
            return Err(NewMemoError::MultipleChangeOutputs);
        }
        self.wrote_change_memo = true;
        Ok(GiftCodeCancellationMemo::from(self.gift_code_tx_out_global_index).into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::build_zero_value_change_memo;
    use std::convert::TryInto;

    #[test]
    fn test_gift_code_cancellation_memo_built_successfully_with_index() {
        // Set the cancellation index and create memo builder
        let index = 666;
        let mut builder = GiftCodeCancellationMemoBuilder::new(index);

        // Build the memo payload and get the data
        let memo_payload = build_zero_value_change_memo(&mut builder).unwrap();
        let memo_data = memo_payload.get_memo_data();

        // Verify memo data
        let derived_index = u64::from_le_bytes(memo_data[0..8].try_into().unwrap());
        assert_eq!(index, derived_index);
    }

    #[test]
    fn test_gift_code_cancellation_memo_fails_for_more_than_one_change_memo() {
        // Set the cancellation index and create memo builder
        let index = 666;
        let mut builder = GiftCodeCancellationMemoBuilder::new(index);

        // Attempt to build two change outputs
        build_zero_value_change_memo(&mut builder).unwrap();
        let memo_payload = build_zero_value_change_memo(&mut builder);

        // Assert failure for the second output
        assert!(matches!(
            memo_payload,
            Err(NewMemoError::MultipleChangeOutputs)
        ));
    }
}
