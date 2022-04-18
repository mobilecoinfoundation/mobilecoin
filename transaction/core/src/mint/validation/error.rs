// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Error type for mint transactions validation.

use crate::{BlockVersion, TokenId};
use displaydoc::Display;
use serde::{Deserialize, Serialize};

/// Error type for mint transactions validation.
#[derive(Clone, Debug, Display, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum Error {
    /// Invalid block version: {0}
    InvalidBlockVersion(BlockVersion),

    /// Invalid token id: {0}
    InvalidTokenId(TokenId),

    /// Invalid nonce length: {0}
    InvalidNonceLength(usize),

    /// Invalid signer set
    InvalidSignerSet,

    /// Invalid signature
    InvalidSignature,

    /// Number of blocks in ledger exceeds the tombstone block number
    TombstoneBlockExceeded,

    /// Tombstone block is too far in the future
    TombstoneBlockTooFar,

    /// Unknown error (should never happen)
    Unknown,

    /// Amount exceeds mint limit
    AmountExceedsMintLimit,

    /// No master minters configured for token id {0}
    NoMasterMinters(TokenId),

    /// Nonce already seen in ledger
    NonceAlreadyUsed,

    /// No matching mint configuration
    NoMatchingMintConfig,
}
