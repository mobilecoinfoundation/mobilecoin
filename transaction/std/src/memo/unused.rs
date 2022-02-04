// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Object for 0x0000 Unused memo type
//!
//! This was proposed for standardization in mobilecoinfoundation/mcips/pull/3

use super::RegisteredMemoType;
use crate::impl_memo_type_conversions;

/// A memo that the sender declined to use to convey any information.
#[derive(Default, Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct UnusedMemo;

impl RegisteredMemoType for UnusedMemo {
    const MEMO_TYPE_BYTES: [u8; 2] = [0x00, 0x00];
}

impl From<&[u8; 64]> for UnusedMemo {
    fn from(_: &[u8; 64]) -> Self {
        Self
    }
}

impl From<UnusedMemo> for [u8; 64] {
    fn from(_: UnusedMemo) -> [u8; 64] {
        [0u8; 64]
    }
}

impl_memo_type_conversions! { UnusedMemo }
