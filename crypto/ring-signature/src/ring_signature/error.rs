// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Errors which can occur in connection to RingMLSAG signatures

use displaydoc::Display;
use serde::{Deserialize, Serialize};

/// An error which can occur when signing or verifying an MLSAG
#[derive(Clone, Debug, Deserialize, Display, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum Error {
    /// Incorrect length for array copy, provided `{0}`, required `{1}`.
    LengthMismatch(usize, usize),

    /// Index out of bounds
    IndexOutOfBounds,

    /// Invalid curve point
    InvalidCurvePoint,

    /// Invalid curve scalar
    InvalidCurveScalar,

    /// The signature was not able to be validated
    InvalidSignature,

    /// Failed to compress/decompress a KeyImage
    InvalidKeyImage,

    /// Value not conserved
    ValueNotConserved,
}

impl From<mc_util_repr_bytes::LengthMismatch> for Error {
    fn from(src: mc_util_repr_bytes::LengthMismatch) -> Self {
        Self::LengthMismatch(src.found, src.expected)
    }
}
