// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Convert between Rust and proto representations of EncryptedMemo.

use crate::{external, ConversionError};
use mc_transaction_core::encrypted_fog_hint::EncryptedFogHint;

impl From<&EncryptedFogHint> for external::EncryptedFogHint {
    fn from(src: &EncryptedFogHint) -> Self {
        Self {
            data: src.to_bytes().to_vec(),
        }
    }
}

impl TryFrom<&external::EncryptedFogHint> for EncryptedFogHint {
    type Error = ConversionError;

    fn try_from(src: &external::EncryptedFogHint) -> Result<Self, Self::Error> {
        Self::try_from(&src.data[..]).map_err(|_| ConversionError::ArrayCastError)
    }
}
