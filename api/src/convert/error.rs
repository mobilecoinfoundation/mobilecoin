// Copyright (c) 2018-2022 The MobileCoin Foundation

use core::{array::TryFromSliceError, convert::Infallible};
use displaydoc::Display;
use mc_blockchain_types::ConvertError;
use mc_crypto_keys::{KeyError, SignatureError};
use mc_transaction_core::ring_signature::Error as RingSigError;

#[derive(Debug, Display, Eq, PartialEq, Copy, Clone)]
pub enum ConversionError {
    /// Failed to cast array
    ArrayCastError,
    /// Failed to cast key
    KeyCastError,
    /// Key: {0}
    Key(KeyError),
    /// Fee mismatch
    FeeMismatch,
    /// Index out of bounds
    IndexOutOfBounds,
    /// Missing object
    ObjectMissing,
    /// Invalid signature
    InvalidSignature,
    /// Invalid contents
    InvalidContents,
    /// Other conversion error
    Other,
}

// This is needed for some code to compile, due to TryFrom being derived from
// From
impl From<Infallible> for ConversionError {
    fn from(_src: Infallible) -> Self {
        unreachable!();
    }
}

impl From<TryFromSliceError> for ConversionError {
    fn from(_: TryFromSliceError) -> Self {
        Self::ArrayCastError
    }
}

impl From<RingSigError> for ConversionError {
    fn from(src: RingSigError) -> Self {
        match src {
            RingSigError::LengthMismatch(_, _) => Self::ArrayCastError,
            _ => Self::KeyCastError,
        }
    }
}

impl From<ConvertError> for ConversionError {
    fn from(_src: ConvertError) -> Self {
        Self::ArrayCastError
    }
}

impl From<KeyError> for ConversionError {
    fn from(src: KeyError) -> Self {
        Self::Key(src)
    }
}

impl From<SignatureError> for ConversionError {
    fn from(_: SignatureError) -> Self {
        Self::InvalidSignature
    }
}

impl std::error::Error for ConversionError {}
