// Copyright (c) 2018-2023 The MobileCoin Foundation

//! Defines the DefragmentationMemoBuilder
//! This memo builder implements DefragmentationMemos defined in MCIP #61

use super::MemoBuilder;
use crate::ReservedSubaddresses;
use mc_account_keys::PublicAddress;
use mc_transaction_core::{
    tokens::Mob, Amount, MemoContext, MemoPayload, NewMemoError, Token,
};
use mc_transaction_extra::{DefragmentationMemo, DefragmentationMemoError};

///TODO: doc
#[derive(Clone, Debug)]
pub struct DefragmentationMemoBuilder {
    // Defragmentation transaction fee
    fee: Amount,
    // Fee + defragmentation transaction amount
    total_outlay: u64,
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
            total_outlay: Mob::MINIMUM_FEE,
            defrag_id: None,
            wrote_main_memo: false,
            wrote_decoy_memo: false,
        }
    }
}

impl DefragmentationMemoBuilder {

    /// TODO: doc
    pub fn set_total_outlay(&mut self, value: u64) {
        self.total_outlay = value;
    }

    /// TODO: doc
    pub fn set_defrag_id(&mut self, value: u64) {
        self.defrag_id = Some(value);
    }

    /// TODO: doc
    pub fn clear_defrag_id(&mut self) {
        self.defrag_id = None;
    }

}

impl MemoBuilder for DefragmentationMemoBuilder {

    /// Set the fee
    fn set_fee(&mut self, fee: Amount) -> Result<(), NewMemoError> {
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
            return Err(NewMemoError::MultipleDefragOutputs);
        }
        if self.wrote_decoy_memo {
            return Err(NewMemoError::OutputsAfterChange);
        }
        if amount.token_id != self.fee.token_id {
            return Err(NewMemoError::MixedTokenIds);
        }

        match DefragmentationMemo::new(
            self.fee.value,
            self.total_outlay,
            self.defrag_id.unwrap_or(0),
        ) {
            Ok(memo) => {
                self.wrote_main_memo = true;
                Ok(memo.into())
            }
            Err(err) => match err {
                DefragmentationMemoError::FeeTooLarge => Err(NewMemoError::LimitsExceeded("fee")),
            },
        }

    }

    /// Build the memo for the change output (zero amount)
    fn make_memo_for_change_output(
        &mut self,
        amount: Amount,
        _change_destination: &ReservedSubaddresses,
        _memo_context: MemoContext,
    ) -> Result<MemoPayload, NewMemoError> {

        if self.wrote_decoy_memo {
            return Err(NewMemoError::MultipleChangeOutputs);
        }
        if amount.token_id != self.fee.token_id {
            return Err(NewMemoError::MixedTokenIds);
        }

        match DefragmentationMemo::new(
            0,
            0,
            self.defrag_id.unwrap_or(0),
        ) {
            Ok(memo) => {
                self.wrote_main_memo = true;
                Ok(memo.into())
            }
            Err(err) => match err {
                DefragmentationMemoError::FeeTooLarge => Err(NewMemoError::LimitsExceeded("fee")),
            },
        }

    }

}
