// Copyright (c) 2018-2022 The MobileCoin Foundation

use mc_blockchain_types::ConvertError;
use mc_crypto_keys::{KeyError, SignatureError};
use mc_transaction_core::ring_signature::Error as RingSigError;
use std::{
    array::TryFromSliceError,
    convert::Infallible,
    error::Error,
    fmt::{self, Formatter},
};

#[derive(Debug, Eq, PartialEq, Clone)]
pub enum ConversionError {
    ArrayCastError,
    FeeMismatch,
    IndexOutOfBounds,
    InvalidContents,
    InvalidSignature,
    Key(KeyError),
    KeyCastError,
    MissingField(String),
    NarrowingCastError,
    ObjectMissing,
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

impl Error for ConversionError {}

impl fmt::Display for ConversionError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "ConversionError")
    }
}
