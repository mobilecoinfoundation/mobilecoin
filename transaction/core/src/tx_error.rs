// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Errors that can occur when creating a new TxOut

use crate::AmountError;
use alloc::string::String;
use displaydoc::Display;

/// An error that occurs when creating a new TxOut
#[derive(Debug, Display)]
pub enum NewTxError {
    /// Amount: {0}
    Amount(AmountError),
    /// Memo: {0}
    Memo(NewMemoError),
}

impl From<AmountError> for NewTxError {
    fn from(src: AmountError) -> NewTxError {
        NewTxError::Amount(src)
    }
}

impl From<NewMemoError> for NewTxError {
    fn from(src: NewMemoError) -> NewTxError {
        NewTxError::Memo(src)
    }
}

/// An error that occurs when creating a new Memo for a TxOut
///
/// These errors are usually created by a MemoBuilder.
/// We have included error codes for some known useful error conditions.
/// For a custom MemoBuilder, you can try to reuse those, or use the Other
/// error code.
#[derive(Debug, Display, PartialEq, Eq)]
pub enum NewMemoError {
    /// Limits for '{0}' value exceeded
    LimitsExceeded(&'static str),
    /// Multiple change outputs not supported
    MultipleChangeOutputs,
    /// Creating more outputs after the change output is not supported
    OutputsAfterChange,
    /// Changing the fee after the change output is not supported
    FeeAfterChange,
    /// Other: {0}
    Other(String),
}
