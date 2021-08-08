// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Defines an object for each known high-level memo type,
//! and an enum to allow matching recovered memos to one of these types.
//!
//! The intended use is like:
//! - Call `TxOut::decrypt_memo`, obtaining `MemoPayload`
//! - Call `MemoType::try_from`, obtaining the enum `MemoType`
//! - Match on the enum, which tells you what memo type this is, then you can
//!   read that data and validate it. See individual memo types for their
//!   semantics.
//!
//! To add a new memo type, you can add it to this crate in a new module,
//! make it implement `RegisteredMemoType`, and add it to the `impl_memo_enum`
//! macro call below.
//!
//! You can also make your own custom version of `MemoType` using different
//! structs, in your own crate, if you prefer. The `impl_memo_enum` macro is
//! exported, and will work as long as your memo types all implement
//! RegisteredMemoType, and all have different MEMO_TYPE_BYTES.
//!
//! If you want to put new memo types into transactions, you will need to
//! implement a new `MemoBuilder`. See the `memo_builder` module for examples.
//! Or, if you don't want to use the `TransactionBuilder`, you can call
//! `TxOut::new_with_memo` directly.

use core::{convert::TryFrom, fmt::Debug};
use displaydoc::Display;

mod authenticated_common;
mod authenticated_sender;
mod authenticated_sender_with_payment_request_id;
mod credential;
mod destination;
#[macro_use]
mod macros;
mod unused;

use crate::impl_memo_enum;
pub use authenticated_common::compute_category1_hmac;
pub use authenticated_sender::AuthenticatedSenderMemo;
pub use authenticated_sender_with_payment_request_id::AuthenticatedSenderWithPaymentRequestIdMemo;
pub use credential::SenderMemoCredential;
pub use destination::{DestinationMemo, DestinationMemoError};
pub use unused::UnusedMemo;

/// A trait that all registered memo types should implement.
/// This creates a single source of truth for the memo type bytes.
pub trait RegisteredMemoType:
    Sized + Clone + Debug + Into<[u8; 44]> + for<'a> From<&'a [u8; 44]>
{
    /// The type bytes assigned to this memo type. Refer to MCIP for these.
    ///
    /// The first byte is conceptually a "type category"
    /// The second byte is a type within the category
    const MEMO_TYPE_BYTES: [u8; 2];
}

/// An error that can occur when trying to interpret a raw MemoPayload as
/// a MemoType
#[derive(Clone, Display, Debug)]
pub enum MemoDecodingError {
    /// Unknown memo type: type bytes were {0:02X?}
    UnknownMemoType([u8; 2]),
}

impl_memo_enum! { MemoType,
    Unused(UnusedMemo),
    AuthenticatedSender(AuthenticatedSenderMemo),
    AuthenticatedSenderWithPaymentRequestId(AuthenticatedSenderWithPaymentRequestIdMemo),
    Destination(DestinationMemo),
}
