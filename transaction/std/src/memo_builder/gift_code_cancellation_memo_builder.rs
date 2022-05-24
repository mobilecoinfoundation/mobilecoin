// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Defines the Memo Builder for the gift code cancellation memo (0x0202)
//! specified in MCIP #32

use super::{memo::GiftCodeCancellationMemo, MemoBuilder, ReservedSubaddresses};
use mc_account_keys::PublicAddress;
use mc_transaction_core::{tokens::Mob, Amount, MemoContext, MemoPayload, NewMemoError, Token};

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
/// sent to the gift code subaddress when the gift code was funded as well
/// as the fee paid to cancel the gift code. The gift code memo uses 8 bytes
/// to represent the cancellation index as a 64 bit number and the next 7 bytes
/// to represent the fee as a 56 bit number.
#[derive(Clone, Debug)]
pub struct GiftCodeCancellationMemoBuilder {
    // Index of the gift code TxOut that was originally funded
    gift_code_tx_out_global_index: u64,
    // Whether we've already written the change memo
    wrote_change_memo: bool,
    // Fee paid for gift code cancellation
    fee: Amount,
}

impl GiftCodeCancellationMemoBuilder {
    /// Initialize memo builder with the index of the originally
    /// funded gift code TxOut
    pub fn new(gift_code_tx_out_global_index: u64) -> Self {
        Self {
            gift_code_tx_out_global_index,
            wrote_change_memo: false,
            fee: Amount::new(Mob::MINIMUM_FEE, Mob::ID),
        }
    }
}

impl MemoBuilder for GiftCodeCancellationMemoBuilder {
    /// Set the fee
    fn set_fee(&mut self, fee: Amount) -> Result<(), NewMemoError> {
        if self.wrote_change_memo {
            return Err(NewMemoError::FeeAfterChange);
        }
        if fee.value > GiftCodeCancellationMemo::MAX_FEE {
            return Err(NewMemoError::MaxFeeExceeded(
                GiftCodeCancellationMemo::MAX_FEE,
                fee.value,
            ));
        }
        self.fee = fee;
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
        amount: Amount,
        _change_destination: &ReservedSubaddresses,
        _memo_context: MemoContext,
    ) -> Result<MemoPayload, NewMemoError> {
        if self.wrote_change_memo {
            return Err(NewMemoError::MultipleChangeOutputs);
        }
        // fee and change amount token id must match
        if self.fee.token_id != amount.token_id {
            return Err(NewMemoError::MixedTokenIds);
        }
        self.wrote_change_memo = true;
        Ok(
            GiftCodeCancellationMemo::new(self.gift_code_tx_out_global_index, self.fee.value)?
                .into(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::build_change_memo_with_amount;

    #[test]
    fn test_gift_code_cancellation_memo_built_successfully_with_index() {
        // Set the cancellation index and fee and create the memo builder
        let index = 666;
        let amount = Amount::new(42, 0.into());
        let fee = Amount::new(1, 0.into());
        let mut builder = GiftCodeCancellationMemoBuilder::new(index);
        builder.set_fee(fee).unwrap();

        // Build the memo payload and get the data
        let memo_payload = build_change_memo_with_amount(&mut builder, amount).unwrap();
        let memo_data = memo_payload.get_memo_data();

        // Recover memo
        let memo = GiftCodeCancellationMemo::from(memo_data);

        // Check recovered index is correct
        assert_eq!(index, memo.cancelled_gift_code_index());

        // Check recovered fee is correct
        assert_eq!(fee.value, memo.get_fee());
    }

    #[test]
    fn test_gift_code_cancellation_memo_fails_for_more_than_one_change_memo() {
        // Set the cancellation index and fee and create the memo builder
        let index = 666;
        let amount = Amount::new(42, 0.into());
        let fee = Amount::new(20, 0.into());
        let mut builder = GiftCodeCancellationMemoBuilder::new(index);
        builder.set_fee(fee).unwrap();

        // Attempt to build two change outputs
        let memo_payload = build_change_memo_with_amount(&mut builder, amount).unwrap();
        let memo_payload_2 = build_change_memo_with_amount(&mut builder, amount);

        // Ensure we can recover the index and fee for the first change output
        let memo = GiftCodeCancellationMemo::from(memo_payload.get_memo_data());
        assert_eq!(index, memo.cancelled_gift_code_index());
        assert_eq!(fee.value, memo.get_fee());

        // Assert failure for the second attempted change output
        assert!(matches!(
            memo_payload_2,
            Err(NewMemoError::MultipleChangeOutputs)
        ));
    }

    #[test]
    fn test_gift_code_cancellation_memo_builder_fee_token_cannot_be_different_from_change_token() {
        let index = 666;
        let mut builder = GiftCodeCancellationMemoBuilder::new(index);
        let amount = Amount::new(42, 0.into());
        let fee = Amount::new(1, 9001.into());

        // Set a fee with a different token id
        builder.set_fee(fee).unwrap();

        // Attempt to build the memo
        let memo_payload = build_change_memo_with_amount(&mut builder, amount);

        // Ensure memo creation fails
        assert!(matches!(memo_payload, Err(NewMemoError::MixedTokenIds)))
    }

    #[test]
    fn test_gift_code_cancellation_memo_builder_set_fee_fails_when_exceeding_max_fee() {
        let index = 666;
        let mut builder = GiftCodeCancellationMemoBuilder::new(index);
        let fee = Amount::new(u64::MAX, 0.into());

        // Try to set a fee above max allowed
        let result = builder.set_fee(fee);
        assert_eq!(
            result,
            Err(NewMemoError::MaxFeeExceeded(
                GiftCodeCancellationMemo::MAX_FEE,
                fee.value
            ))
        );
    }
}
