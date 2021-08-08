// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Defines an object for each known high-level memo type,
//! and an enum to allow matching recovered memos to one of these types.
//!
//! To add a new memo type, add a new module for it, add a structure,
//! and make it convertible to MemoPayload.
//! Then also add it to the MemoType enum and extend the TryFrom logic.

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
