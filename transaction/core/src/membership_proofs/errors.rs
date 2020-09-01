// Copyright (c) 2018-2020 MobileCoin Inc.

use crate::range;
use displaydoc::Display;

/// Reasons why a creating or validating a proof of membership might fail.
#[derive(Debug, Display, PartialEq)]
pub enum Error {
    /// Contains incorrect leaf hash: {0}
    IncorrectLeafHash(u64),

    /// Missing hash for leaf: {0}
    MissingLeafHash(u64),

    /// Invalid Range: {0}
    RangeError(range::RangeError),

    /// An unexpected tx out membership element was provided, which was not adjacent to the preceding elements, at index {0}
    UnexpectedMembershipElement(usize),

    /// The value provided for proof.highest_index doesn't match the other data
    HighestIndexMismatch,

    /// The implied merkle root's range doesn't cover 0
    RootNotCoveringZero,

    /// Failed to serialize a TxOut.
    TxOutSerializationError,

    /// Numeric limits exceeded
    NumericLimitsExceeded,
}

impl From<mc_util_serial::encode::Error> for Error {
    fn from(_e: mc_util_serial::encode::Error) -> Self {
        Error::TxOutSerializationError
    }
}

impl From<range::RangeError> for Error {
    fn from(e: range::RangeError) -> Self {
        Error::RangeError(e)
    }
}
