// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Error types converting to/from encodings.

use alloc::string::FromUtf8Error;
use base64::DecodeError;
use binascii::ConvertError;
use core::{array::TryFromSliceError, fmt::Error as FmtError, str::Utf8Error};
use displaydoc::Display;
use hex::FromHexError;
use mc_util_repr_bytes::LengthMismatch;
use serde::{Deserialize, Serialize};

/// Type used to add traits to ConvertError
#[derive(
    Clone, Copy, Debug, Deserialize, Display, Hash, Eq, Ord, PartialEq, PartialOrd, Serialize,
)]
pub enum Error {
    /// The output string was not proper UTF-8
    InvalidUtf8,
    /// The input length was too short or not right (padding)
    InvalidInputLength,
    /// The output buffer was too short for the data
    InvalidOutputLength,
    /// The input data contained invalid characters
    InvalidInput,
}

impl From<ConvertError> for Error {
    fn from(src: ConvertError) -> Self {
        match src {
            ConvertError::InvalidInputLength => Error::InvalidInputLength,
            ConvertError::InvalidOutputLength => Error::InvalidOutputLength,
            ConvertError::InvalidInput => Error::InvalidInput,
        }
    }
}

impl From<DecodeError> for Error {
    fn from(src: DecodeError) -> Self {
        match src {
            DecodeError::InvalidByte(_offset, _byte) => Error::InvalidInput,
            DecodeError::InvalidLength => Error::InvalidInputLength,
            DecodeError::InvalidLastSymbol(_offset, _byte) => Error::InvalidInput,
        }
    }
}

impl From<FromHexError> for Error {
    fn from(src: FromHexError) -> Self {
        match src {
            FromHexError::InvalidHexCharacter { .. } => Error::InvalidInput,
            FromHexError::OddLength => Error::InvalidInputLength,
            FromHexError::InvalidStringLength => Error::InvalidInputLength,
        }
    }
}

impl From<FromUtf8Error> for Error {
    fn from(_src: FromUtf8Error) -> Self {
        Error::InvalidUtf8
    }
}

impl From<TryFromSliceError> for Error {
    fn from(_src: TryFromSliceError) -> Self {
        Error::InvalidInputLength
    }
}

impl From<Utf8Error> for Error {
    fn from(_src: Utf8Error) -> Self {
        Error::InvalidUtf8
    }
}

impl From<LengthMismatch> for Error {
    fn from(_src: LengthMismatch) -> Self {
        Error::InvalidInputLength
    }
}

impl From<Error> for FmtError {
    fn from(_src: Error) -> FmtError {
        FmtError
    }
}
