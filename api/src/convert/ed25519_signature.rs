// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Convert to/from external::Ed25519Signature

use crate::{external, ConversionError};
use mc_crypto_keys::{Ed25519Public, Ed25519Signature};

/// Convert Ed25519Signature --> external::Ed25519Signature.
impl From<&Ed25519Signature> for external::Ed25519Signature {
    fn from(src: &Ed25519Signature) -> Self {
        Self {
            data: src.to_bytes().to_vec(),
        }
    }
}

/// Convert external::Ed25519Signature --> Ed25519Signature.
impl TryFrom<&external::Ed25519Signature> for Ed25519Signature {
    type Error = ConversionError;

    fn try_from(source: &external::Ed25519Signature) -> Result<Self, Self::Error> {
        let bytes: &[u8] = source.data.as_slice();
        Ed25519Signature::try_from(bytes).map_err(|_| ConversionError::ArrayCastError)
    }
}

/// Convert Ed25519Public --> external::Ed25519Public.
impl From<&Ed25519Public> for external::Ed25519Public {
    fn from(src: &Ed25519Public) -> Self {
        let bytes: &[u8] = src.as_ref();
        Self {
            data: bytes.to_vec(),
        }
    }
}

/// Convert external::Ed25519Public --> Ed25519Public.
impl TryFrom<&external::Ed25519Public> for Ed25519Public {
    type Error = ConversionError;

    fn try_from(source: &external::Ed25519Public) -> Result<Self, Self::Error> {
        let bytes: &[u8] = source.data.as_slice();
        Ed25519Public::try_from(bytes).map_err(|_| ConversionError::ArrayCastError)
    }
}
