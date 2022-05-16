// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Utilities for creating MobileCoin transactions, intended for client-side
//! use and not intended to be used inside of enclaves.

#![deny(missing_docs)]

extern crate core;

mod change_destination;
mod error;
mod input_credentials;
mod memo;
mod memo_builder;
mod transaction_builder;

pub use change_destination::ChangeDestination;
pub use error::TxBuilderError;
pub use input_credentials::InputCredentials;
pub use memo::{
    AuthenticatedSenderMemo, AuthenticatedSenderWithPaymentRequestIdMemo, BurnRedemptionMemo,
    DestinationMemo, DestinationMemoError, MemoDecodingError, MemoType, RegisteredMemoType,
    SenderMemoCredential, UnusedMemo,
};
pub use memo_builder::{BurnRedemptionMemoBuilder, EmptyMemoBuilder, MemoBuilder, RTHMemoBuilder};
pub use transaction_builder::{
    DefaultTxOutputsOrdering, TransactionBuilder, TxOutContext, TxOutputsOrdering,
};

// Re-export this to help the exported macros work
pub use mc_transaction_core::MemoPayload;
