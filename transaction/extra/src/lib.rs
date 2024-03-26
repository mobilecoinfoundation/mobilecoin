// Copyright (c) 2018-2023 The MobileCoin Foundation

//! Ancillary structures and schema on top of the core Mobilecoin transaction
//! logic.
//!
//! These structures may be important or even essential to some client
//! workflows, but if they aren't needed for transaction validation to work,
//! then they probably should be in here and not in transaction-core.

#![no_std]
#![deny(missing_docs)]

extern crate alloc;

mod memo;
mod signed_contingent_input;
mod tx_out_confirmation_number;
mod tx_out_gift_code;
mod unsigned_tx;

pub use memo::{
    compute_authenticated_sender_memo, compute_destination_memo,
    get_data_from_authenticated_sender_memo, get_data_from_destination_memo,
    validate_authenticated_sender, AuthenticatedSenderMemo,
    AuthenticatedSenderWithPaymentIntentIdMemo, AuthenticatedSenderWithPaymentRequestIdMemo,
    BurnRedemptionMemo, DefragmentationMemo, DefragmentationMemoError, DestinationMemo,
    DestinationMemoError, DestinationWithPaymentIntentIdMemo, DestinationWithPaymentRequestIdMemo,
    GiftCodeCancellationMemo, GiftCodeFundingMemo, GiftCodeSenderMemo, MemoDecodingError, MemoType,
    RegisteredMemoType, SenderMemoCredential, UnusedMemo,
};
pub use signed_contingent_input::{
    SignedContingentInput, SignedContingentInputAmounts, SignedContingentInputError,
};
pub use tx_out_confirmation_number::TxOutConfirmationNumber;
pub use tx_out_gift_code::TxOutGiftCode;
pub use unsigned_tx::UnsignedTx;

// Re-export this to help the exported macros work
pub use mc_transaction_core::MemoPayload;
