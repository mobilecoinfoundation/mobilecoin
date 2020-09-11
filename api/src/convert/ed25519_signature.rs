//! Convert to/from external::Ed25519Signature

use crate::{convert::ConversionError, external};
use mc_crypto_keys::{Ed25519Public, Ed25519Signature};
use std::convert::TryFrom;

/// Convert Ed25519Signature --> external::Ed25519Signature.
impl From<&Ed25519Signature> for external::Ed25519Signature {
    fn from(src: &Ed25519Signature) -> Self {
        let mut dst = external::Ed25519Signature::new();
        dst.set_data(src.to_bytes().to_vec());
        dst
    }
}

/// Convert external::Ed25519Signature --> Ed25519Signature.
impl TryFrom<&external::Ed25519Signature> for Ed25519Signature {
    type Error = ConversionError;

    fn try_from(source: &external::Ed25519Signature) -> Result<Self, Self::Error> {
        let bytes: &[u8] = source.get_data();
        Ed25519Signature::try_from(bytes).map_err(|_| ConversionError::ArrayCastError)
    }
}

/// Convert Ed25519Public --> external::Ed25519Public.
impl From<&Ed25519Public> for external::Ed25519Public {
    fn from(src: &Ed25519Public) -> Self {
        let mut dst = external::Ed25519Public::new();
        let bytes: &[u8] = src.as_ref();
        dst.set_data(bytes.to_vec());
        dst
    }
}

/// Convert external::Ed25519Public --> Ed25519Public.
impl TryFrom<&external::Ed25519Public> for Ed25519Public {
    type Error = ConversionError;

    fn try_from(source: &external::Ed25519Public) -> Result<Self, Self::Error> {
        let bytes: &[u8] = source.get_data();
        Ed25519Public::try_from(bytes).map_err(|_| ConversionError::ArrayCastError)
    }
}
