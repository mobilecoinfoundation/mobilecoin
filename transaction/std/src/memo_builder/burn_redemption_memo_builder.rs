// Copyright (c) 2022 The MobileCoin Foundation

//! Defines the BurnRedemptionMemoBuilder.
//! This MemoBuilder policy implements Burn Redemption tracking using memos, as
//! envisioned in MCIP #TODO.

use super::{
    memo::{BurnRedemptionMemo, DestinationMemo, DestinationMemoError, UnusedMemo},
    MemoBuilder,
};
use crate::ChangeDestination;
use mc_account_keys::{burn_address, PublicAddress, ShortAddressHash};
use mc_transaction_core::{tokens::Mob, Amount, MemoContext, MemoPayload, NewMemoError, Token};

/// This memo builder attaches 0x0001 Burn Redemption Memos to an output going
/// to the designated burn address, and 0x0200 Destination Memos to change
/// outputs. Only a single non-change output is allowed, and it must go to the
/// designated burn address.
///
/// Usage:
/// You should usually use this like:
///
///   let memo_data = [1; BurnRedemptionMemo::MEMO_DATA_LEN];
///   let mut mb = BurnRedemptionMemoBuilder::new(memo_data);
///   mb.enable_destination_memo();
///
/// Then use it to construct a transaction builder.
///
/// A memo builder configured this way will use 0x0001 Burn Redemption Memo
/// on the burn output and 0x0200 Destination Memo on the change output.
///
/// If mb.enable_destination_memo() is not called 0x0000 Unused will appear on
/// change output, instead of 0x0200 Destination Memo.
///
/// When invoking the transaction builder, the change output must be created
/// last. If the burn output is created after the change output, an error will
/// occur.
///
/// If more than one burn output is created, an error will be returned.
#[derive(Clone, Debug)]
pub struct BurnRedemptionMemoBuilder {
    // The memo data we will attach to the burn output.
    memo_data: [u8; BurnRedemptionMemo::MEMO_DATA_LEN],
    // Whether destination memos are enabled.
    destination_memo_enabled: bool,
    // Tracks if we already wrote a destination memo, for error reporting
    wrote_destination_memo: bool,
    // Tracks the amount being burned
    burn_amount: Option<Amount>,
    // Tracks the fee
    fee: Amount,
}

impl BurnRedemptionMemoBuilder {
    /// Construct a new BurnRedemptionMemoBuilder.
    pub fn new(memo_data: [u8; BurnRedemptionMemo::MEMO_DATA_LEN]) -> Self {
        Self {
            memo_data,
            destination_memo_enabled: false,
            wrote_destination_memo: false,
            burn_amount: None,
            fee: Amount::new(Mob::MINIMUM_FEE, Mob::ID),
        }
    }
    /// Enable destination memos
    pub fn enable_destination_memo(&mut self) {
        self.destination_memo_enabled = true;
    }

    /// Disable destination memos
    pub fn disable_destination_memo(&mut self) {
        self.destination_memo_enabled = false;
    }
}

impl MemoBuilder for BurnRedemptionMemoBuilder {
    /// Set the fee
    fn set_fee(&mut self, fee: Amount) -> Result<(), NewMemoError> {
        if self.wrote_destination_memo {
            return Err(NewMemoError::FeeAfterChange);
        }
        self.fee = fee;
        Ok(())
    }

    /// Build a memo for the burn output.
    fn make_memo_for_output(
        &mut self,
        amount: Amount,
        recipient: &PublicAddress,
        _memo_context: MemoContext,
    ) -> Result<MemoPayload, NewMemoError> {
        if *recipient != burn_address() {
            return Err(NewMemoError::InvalidRecipient);
        }
        if self.burn_amount.is_some() {
            return Err(NewMemoError::MultipleOutputs);
        }
        if self.wrote_destination_memo {
            return Err(NewMemoError::OutputsAfterChange);
        }
        self.burn_amount = Some(amount);
        Ok(BurnRedemptionMemo::new(self.memo_data).into())
    }

    /// Build a memo for a change output (to ourselves).
    fn make_memo_for_change_output(
        &mut self,
        change_amount: Amount,
        _change_destination: &ChangeDestination,
        _memo_context: MemoContext,
    ) -> Result<MemoPayload, NewMemoError> {
        if !self.destination_memo_enabled {
            return Ok(UnusedMemo {}.into());
        }
        if self.wrote_destination_memo {
            return Err(NewMemoError::MultipleChangeOutputs);
        }
        let burn_amount = self.burn_amount.ok_or(NewMemoError::MissingOutput)?;
        if burn_amount.token_id != self.fee.token_id
            || burn_amount.token_id != change_amount.token_id
        {
            return Err(NewMemoError::MixedTokenIds);
        }

        let total_outlay = burn_amount
            .value
            .checked_add(self.fee.value)
            .ok_or(NewMemoError::LimitsExceeded("total_outlay"))?;
        match DestinationMemo::new(
            ShortAddressHash::from(&burn_address()),
            total_outlay,
            self.fee.value,
        ) {
            Ok(mut d_memo) => {
                self.wrote_destination_memo = true;
                d_memo.set_num_recipients(1);
                Ok(d_memo.into())
            }
            Err(err) => match err {
                DestinationMemoError::FeeTooLarge => Err(NewMemoError::LimitsExceeded("fee")),
            },
        }
    }
}
