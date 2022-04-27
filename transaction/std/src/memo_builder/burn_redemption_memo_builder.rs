// Copyright (c) 2022 The MobileCoin Foundation

//! Defines the BurnRedemptionMemoBuilder.
//! This MemoBuilder policy implements Burn Redemption tracking usin memos, as
//! envisioned in MCIP #TODO.

use super::{
    memo::{BurnRedemptionMemo, DestinationMemo, DestinationMemoError, UnusedMemo},
    MemoBuilder,
};
use crate::ChangeDestination;
use mc_account_keys::{burn_address, PublicAddress, ShortAddressHash};
use mc_transaction_core::{tokens::Mob, MemoContext, MemoPayload, NewMemoError, Token};

/// This memo builder attaches 0x0001 Burn Redemption Memos to an output going
/// to the designated burn address, and 0x0200 Destination Memos to change
/// outputs. Only a single non-change output is allowed, and it must go to the
/// designated burn address.
///
/// Usage:
/// You should usually use this like:
///
///   let memo_data = [1; 64]; // TODO: contents of this are still not designed.
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
    memo_data: [u8; 64],
    // Whether destination memos are enabled.
    destination_memo_enabled: bool,
    // Tracks if we already wrote a burn memo, for error reporting
    wrote_burn_memo: bool,
    // Tracks if we already wrote a destination memo, for error reporting
    wrote_destination_memo: bool,
    // Tracks the amount being burned
    burn_amount: u64,
    // Tracks the fee
    fee: u64,
}

impl BurnRedemptionMemoBuilder {
    /// Construct a new BurnRedemptionMemoBuilder.
    pub fn new(memo_data: [u8; 64]) -> Self {
        Self {
            memo_data,
            destination_memo_enabled: false,
            wrote_burn_memo: false,
            wrote_destination_memo: false,
            burn_amount: 0,
            fee: Mob::MINIMUM_FEE,
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
    fn set_fee(&mut self, fee: u64) -> Result<(), NewMemoError> {
        if self.wrote_destination_memo {
            return Err(NewMemoError::FeeAfterChange);
        }
        self.fee = fee;
        Ok(())
    }

    /// Build a memo for the burn output.
    fn make_memo_for_output(
        &mut self,
        value: u64,
        recipient: &PublicAddress,
        _memo_context: MemoContext,
    ) -> Result<MemoPayload, NewMemoError> {
        if *recipient != burn_address() {
            return Err(NewMemoError::InvalidRecipient(recipient.clone()));
        }
        if self.wrote_burn_memo {
            return Err(NewMemoError::MultipleOutputs);
        }
        if self.wrote_destination_memo {
            return Err(NewMemoError::OutputsAfterChange);
        }
        self.burn_amount = value;
        self.wrote_burn_memo = true;
        Ok(BurnRedemptionMemo::new(self.memo_data).into())
    }

    /// Build a memo for a change output (to ourselves).
    fn make_memo_for_change_output(
        &mut self,
        _value: u64,
        _change_destination: &ChangeDestination,
        _memo_context: MemoContext,
    ) -> Result<MemoPayload, NewMemoError> {
        if !self.destination_memo_enabled {
            return Ok(UnusedMemo {}.into());
        }
        if self.wrote_destination_memo {
            return Err(NewMemoError::MultipleChangeOutputs);
        }
        if !self.wrote_burn_memo {
            return Err(NewMemoError::MissingOutput);
        }
        let total_outlay = self
            .burn_amount
            .checked_add(self.fee)
            .ok_or(NewMemoError::LimitsExceeded("total_outlay"))?;
        match DestinationMemo::new(
            ShortAddressHash::from(&burn_address()),
            total_outlay,
            self.fee,
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
