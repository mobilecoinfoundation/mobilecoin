// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Defines the MemoBuilder trait, and the Default implementation
//! The memo builder for recoverable transaction history is defined in a
//! submodule.

use super::{memo, ChangeDestination};
use core::fmt::Debug;
use mc_account_keys::PublicAddress;
use mc_transaction_core::{Amount, MemoContext, MemoPayload, NewMemoError};

mod rth_memo_builder;
pub use rth_memo_builder::RTHMemoBuilder;

/// The MemoBuilder trait defines the API that the transaction builder uses
/// to ask the memo builder to build a memo for a particular TxOut.
///
/// The intention is that the memo builder represents a policy for the entire
/// transaction, and it is constructed and configured first. Then, it is
/// installed in the transaction builder when that is constructed.
/// This way low-level handing of memo payloads with TxOuts is not needed,
/// and just invoking the TransactionBuilder as before will do the right thing.
///
/// Note: Even if the memo builder creates memo paylaods, they will be filtered
/// out by the transaction builder if the block version is too low for memos
/// to be supported.
pub trait MemoBuilder: Debug {
    /// Set the fee.
    /// The memo builder is in the loop when the fee is set and changed,
    /// and gets a chance to report an error, if the fee is too large, or if it
    /// is being changed too late
    /// in the process, and memos that are already written would be invalid.
    fn set_fee(&mut self, amount: Amount) -> Result<(), NewMemoError>;

    /// Build a memo for a normal output (to another party).
    fn make_memo_for_output(
        &mut self,
        amount: Amount,
        recipient: &PublicAddress,
        memo_context: MemoContext,
    ) -> Result<MemoPayload, NewMemoError>;

    /// Build a memo for a change output (to ourselves).
    fn make_memo_for_change_output(
        &mut self,
        amount: Amount,
        change_destination: &ChangeDestination,
        memo_context: MemoContext,
    ) -> Result<MemoPayload, NewMemoError>;
}

/// The empty memo builder always builds UnusedMemo.
/// This is the safe and maximally private default.
#[derive(Default, Clone, Debug)]
pub struct EmptyMemoBuilder;

impl MemoBuilder for EmptyMemoBuilder {
    fn set_fee(&mut self, _fee: Amount) -> Result<(), NewMemoError> {
        Ok(())
    }

    fn make_memo_for_output(
        &mut self,
        _value: Amount,
        _recipient: &PublicAddress,
        _memo_context: MemoContext,
    ) -> Result<MemoPayload, NewMemoError> {
        Ok(memo::UnusedMemo {}.into())
    }

    fn make_memo_for_change_output(
        &mut self,
        _value: Amount,
        _change_destination: &ChangeDestination,
        _memo_context: MemoContext,
    ) -> Result<MemoPayload, NewMemoError> {
        Ok(memo::UnusedMemo {}.into())
    }
}
