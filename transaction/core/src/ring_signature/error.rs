// Copyright (c) 2018-2021 The MobileCoin Foundation

use displaydoc::Display;
use serde::{Deserialize, Serialize};

#[derive(
    Clone, Copy, Debug, Display, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
pub enum Error {
    /// Incorrect length for array copy, provided `{0}`, required `{1}`.
    LengthMismatch(usize, usize),

    /// Real index out of bounds
    IndexOutOfBounds,

    /// No inputs
    NoInputs,

    /// Invalid ring size: `{0}`
    InvalidRingSize(usize),

    /// Invalid input_secrets size: `{0}`
    InvalidInputSecretsSize(usize),

    /// Invalid curve point
    InvalidCurvePoint,

    /// Invalid curve scalar
    InvalidCurveScalar,

    /// The signature was not able to be validated
    InvalidSignature,

    /// Failed to compress/decompress a KeyImage
    InvalidKeyImage,

    /// Duplicate key image
    DuplicateKeyImage,

    /// There was an opaque error returned by another crate or library
    InternalError,

    /**
     * Signing failed because the value of inputs did not equal the value of
     * outputs.
     */
    ValueNotConserved,

    /// Invalid RangeProof
    RangeProofError,
}

impl From<mc_util_repr_bytes::LengthMismatch> for Error {
    fn from(src: mc_util_repr_bytes::LengthMismatch) -> Self {
        Error::LengthMismatch(src.found, src.expected)
    }
}
