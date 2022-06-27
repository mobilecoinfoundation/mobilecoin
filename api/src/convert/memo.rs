// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Convert between Rust and proto representations of EncryptedMemo.

use crate::{external, ConversionError};
use mc_transaction_core::EncryptedMemo;

impl From<&EncryptedMemo> for external::EncryptedMemo {
    fn from(src: &EncryptedMemo) -> Self {
        let bytes: &[u8] = src.as_ref();
        Self {
            data: bytes.to_vec(),
        }
    }
}

impl TryFrom<&external::EncryptedMemo> for EncryptedMemo {
    type Error = ConversionError;

    fn try_from(src: &external::EncryptedMemo) -> Result<Self, Self::Error> {
        Self::try_from(&src.data[..]).map_err(|_| ConversionError::ArrayCastError)
    }
}
