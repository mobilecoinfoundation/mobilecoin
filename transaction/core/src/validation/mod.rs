// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Validation routines for a MobileCoin transaction

mod error;
mod validate;

pub use self::{
    error::{TransactionValidationError, TransactionValidationResult},
    validate::{validate, validate_signature, validate_tombstone, validate_tx_out},
};
