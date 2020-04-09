// Copyright (c) 2018-2020 MobileCoin Inc.

//! Error types converting to/from encodings.

use alloc::string::FromUtf8Error;
use binascii::ConvertError;
use core::str::Utf8Error;
use failure::Fail;
use serde::{Deserialize, Serialize};

/// Type used to add traits to ConvertError
#[derive(Clone, Copy, Debug, Deserialize, Fail, Hash, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum Error {
    #[fail(display = "The output string was not proper UTF-8")]
    InvalidUtf8,
    #[fail(display = "The input length was too short or not right (padding)")]
    InvalidInputLength,
    #[fail(display = "The output buffer was too short for the data")]
    InvalidOutputLength,
    #[fail(display = "The input data contained invalid characters")]
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

impl From<Utf8Error> for Error {
    fn from(_src: Utf8Error) -> Self {
        Error::InvalidUtf8
    }
}

impl From<FromUtf8Error> for Error {
    fn from(_src: FromUtf8Error) -> Self {
        Error::InvalidUtf8
    }
}
