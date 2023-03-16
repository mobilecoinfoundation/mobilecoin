// Copyright (c) 2018-2023 The MobileCoin Foundation

//! Defines the DefragmentationMemoBuilder
//! This memo builder implements DefragmentationMemos defined in MCIP #61

use super::MemoBuilder;
use crate::ReservedSubaddresses;
use mc_account_keys::PublicAddress;
use mc_transaction_core::{tokens::Mob, Amount, MemoContext, MemoPayload, NewMemoError, Token};
use mc_transaction_extra::{DefragmentationMemo, DefragmentationMemoError};

/// This memo builder builds the [`DefragmentationMemo`] (0x0003).
///
/// The DefragmentationMemo denotes defragmentation transactions. It contains
/// three pieces of information: the fee, the total outlay, and an optional
/// defragmentation ID number. If no defragmentation ID is specified, 0 is used.
/// The fee and defragmentation ID can be set using this builder. The total
/// outlay is set when the memo for the main output is written.
///
/// This builder will write a memo for both the main and change outputs of a
/// defragmentation transaction. The main output will get the fee and outlay of
/// the transaction. The change output (if present) will get a defragmentation
/// memo with the same defragmentation ID number, but 0 fee and outlay.
#[derive(Clone, Debug)]
pub struct DefragmentationMemoBuilder {
    // Defragmentation transaction fee
    fee: Amount,
    // Defragmentation ID
    defrag_id: Option<u64>,
    // Tracks whether or not the main defrag memo was already written
    wrote_main_memo: bool,
    // Tracks whether or not the change (0 value) defrag memo was already written
    wrote_decoy_memo: bool,
}

impl Default for DefragmentationMemoBuilder {
    fn default() -> Self {
        Self {
            fee: Amount::new(Mob::MINIMUM_FEE, Mob::ID),
            defrag_id: None,
            wrote_main_memo: false,
            wrote_decoy_memo: false,
        }
    }
}

impl DefragmentationMemoBuilder {
    /// Creates a new DefragmentationMemoBuilder with the specified
    /// defragmentation ID
    pub fn new(defrag_id: u64) -> Self {
        let mut result = DefragmentationMemoBuilder::default();
        result.set_defrag_id(defrag_id);
        result
    }

    /// Sets the defragmentation ID
    pub fn set_defrag_id(&mut self, value: u64) -> &mut Self {
        self.defrag_id = Some(value);
        self
    }

    /// Clears the defragmentation ID
    /// If the memo is built without a specified defragmentation ID, it　will
    /// default　to 0.
    pub fn clear_defrag_id(&mut self) -> &mut Self {
        self.defrag_id = None;
        self
    }
}

impl MemoBuilder for DefragmentationMemoBuilder {
    /// Set the fee
    /// Throws an error if the specified value cannot be represented in 56 bits
    fn set_fee(&mut self, fee: Amount) -> Result<(), NewMemoError> {
        // Since the main memo includes the fee, check for main, not change
        if self.wrote_main_memo {
            return Err(NewMemoError::FeeAfterChange);
        }
        self.fee = fee;
        Ok(())
    }

    /// Build the memo for the main defrag output (non-zero amount)
    fn make_memo_for_output(
        &mut self,
        amount: Amount,
        _recipient: &PublicAddress,
        _memo_context: MemoContext,
    ) -> Result<MemoPayload, NewMemoError> {
        if self.wrote_main_memo {
            return Err(NewMemoError::MultipleOutputs);
        }
        if self.wrote_decoy_memo {
            return Err(NewMemoError::OutputsAfterChange);
        }
        if amount.token_id != self.fee.token_id {
            return Err(NewMemoError::MixedTokenIds);
        }

        let memo = DefragmentationMemo::new(
            self.fee.value,
            self.fee
                .value
                .checked_add(amount.value)
                .ok_or(NewMemoError::LimitsExceeded("total_outlay"))?,
            self.defrag_id.unwrap_or(0),
        )?;
        self.wrote_main_memo = true;
        Ok(memo.into())
    }

    /// Build the memo for the change output (zero amount)
    fn make_memo_for_change_output(
        &mut self,
        amount: Amount,
        _change_destination: &ReservedSubaddresses,
        _memo_context: MemoContext,
    ) -> Result<MemoPayload, NewMemoError> {
        if !self.wrote_main_memo {
            return Err(NewMemoError::MissingOutput);
        }
        if self.wrote_decoy_memo {
            return Err(NewMemoError::MultipleChangeOutputs);
        }
        if amount.token_id != self.fee.token_id {
            return Err(NewMemoError::MixedTokenIds);
        }
        if amount.value != 0 {
            return Err(NewMemoError::DefragWithChange);
        }

        let memo = DefragmentationMemo::new(0, 0, self.defrag_id.unwrap_or(0))?;
        self.wrote_main_memo = true;
        Ok(memo.into())
    }
}
