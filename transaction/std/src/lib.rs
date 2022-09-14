// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Utilities for creating MobileCoin transactions, intended for client-side
//! use and not intended to be used inside of enclaves.

#![deny(missing_docs)]

extern crate core;

mod error;
mod input_credentials;
mod input_materials;
mod memo;
mod memo_builder;
mod reserved_subaddresses;
mod signed_contingent_input_builder;
mod transaction_builder;

#[cfg(any(test, feature = "test-only"))]
pub mod test_utils;

pub use error::{SignedContingentInputBuilderError, TxBuilderError};
pub use input_credentials::InputCredentials;
pub use memo::{
    AuthenticatedSenderMemo, AuthenticatedSenderWithPaymentRequestIdMemo, BurnRedemptionMemo,
    DestinationMemo, DestinationMemoError, GiftCodeCancellationMemo, GiftCodeFundingMemo,
    GiftCodeSenderMemo, MemoDecodingError, MemoType, RegisteredMemoType, SenderMemoCredential,
    UnusedMemo,
};
pub use memo_builder::{
    BurnRedemptionMemoBuilder, EmptyMemoBuilder, GiftCodeCancellationMemoBuilder,
    GiftCodeFundingMemoBuilder, GiftCodeSenderMemoBuilder, MemoBuilder, RTHMemoBuilder,
};
pub use reserved_subaddresses::ReservedSubaddresses;
pub use signed_contingent_input_builder::SignedContingentInputBuilder;
pub use transaction_builder::{
    DefaultTxOutputsOrdering, TransactionBuilder, TransactionViewOnlySigningData, TxOutContext,
    TxOutputsOrdering,
};

// Re-export this to help the exported macros work
pub use mc_transaction_core::MemoPayload;
