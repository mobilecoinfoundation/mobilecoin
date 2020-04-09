// Copyright (c) 2018-2020 MobileCoin Inc.

use crate::range;
use failure::Fail;

/// Reasons why a creating or validating a proof of membership might fail.
#[derive(Debug, Fail, PartialEq)]
pub enum Error {
    /// Contains incorrect leaf hash.
    #[fail(display = "Incorrect hash for leaf: {}", 0)]
    IncorrectLeafHash(u64),

    /// Missing hash for leaf.
    #[fail(display = "Missing hash for leaf: {}", 0)]
    MissingLeafHash(u64),

    /// Invalid Range.
    #[fail(display = "Invalid range")]
    RangeError(range::RangeError),

    /// Failed to serialize a TxOut.
    #[fail(display = "TxOutSerializationError")]
    TxOutSerializationError,

    #[fail(display = "CapacityExceeded")]
    CapacityExceeded,
}

impl From<mcserial::encode::Error> for Error {
    fn from(_e: mcserial::encode::Error) -> Self {
        Error::TxOutSerializationError
    }
}

impl From<range::RangeError> for Error {
    fn from(e: range::RangeError) -> Self {
        Error::RangeError(e)
    }
}
