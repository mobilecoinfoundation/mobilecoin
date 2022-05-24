// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Errors which can occur in connection to ring signatures

use crate::{
    range_proofs::error::Error as RangeProofError, ring_signature::MLSAGError,
    signer::Error as SignerError, TokenId,
};
use alloc::string::{String, ToString};
use displaydoc::Display;
use mc_util_zip_exact::ZipExactError;
use serde::{Deserialize, Serialize};

/// An error which can occur in connection to a ring signature
#[derive(Clone, Debug, Deserialize, Display, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
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

    /// Duplicate key image
    DuplicateKeyImage,

    /**
     * Signing failed because the value of inputs did not equal the value of
     * outputs.
     */
    ValueNotConserved,

    /// Invalid RangeProof: {0}
    RangeProof(String),

    /// RangeProof Deserialization failed
    RangeProofDeserialization,

    /// TokenId is not allowed at this block version
    TokenIdNotAllowed,

    /// Missing pseudo-output token ids
    MissingPseudoOutputTokenIds,

    /// Missing output token ids
    MissingOutputTokenIds,

    /// Pseudo-output token ids not allowed at this block version
    PseudoOutputTokenIdsNotAllowed,

    /// Output token ids not allowed at this block version
    OutputTokenIdsNotAllowed,

    /// Mixed token ids in transactions not allowed at this block version
    MixedTransactionsNotAllowed,

    /// Too many range proofs for the block version
    TooManyRangeProofs,

    /// Unexpected range proof for the block version
    UnexpectedRangeProof,

    /// Missing expected range proofs (expected: {0}, found: {1})
    MissingRangeProofs(usize, usize),

    /// No commitments were found for {0}, this is a logic error
    NoCommitmentsForTokenId(TokenId),

    /// All rings were presigned, but this is not allowed
    AllRingsPresigned,

    /// Signed input rules not allowed at this revision
    SignedInputRulesNotAllowed,

    /// Zip Exact: {0}
    ZipExact(ZipExactError),

    /// MLSAG: {0}
    MLSAG(MLSAGError),

    /// Signer: {0}
    Signer(SignerError),
}

impl From<mc_util_repr_bytes::LengthMismatch> for Error {
    fn from(src: mc_util_repr_bytes::LengthMismatch) -> Self {
        Error::LengthMismatch(src.found, src.expected)
    }
}

impl From<RangeProofError> for Error {
    fn from(src: RangeProofError) -> Self {
        Error::RangeProof(src.to_string())
    }
}

impl From<ZipExactError> for Error {
    fn from(src: ZipExactError) -> Self {
        Error::ZipExact(src)
    }
}

impl From<MLSAGError> for Error {
    fn from(src: MLSAGError) -> Self {
        Self::MLSAG(src)
    }
}
impl From<SignerError> for Error {
    fn from(src: SignerError) -> Self {
        Self::Signer(src)
    }
}
