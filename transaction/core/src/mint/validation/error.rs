// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Error type for mint transactions validation.

use crate::BlockVersion;
use displaydoc::Display;
use serde::{Deserialize, Serialize};

/// Error type for mint transactions validation.
#[derive(Clone, Debug, Display, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum Error {
    /// Invalid block version: {0}
    BlockVersion(BlockVersion),

    /// Invalid token id: {0}
    TokenId(u32),

    /// Invalid nonce length: {0}
    NonceLength(usize),

    /// Invalid signer set
    SignerSet,

    /// Invalid signature
    Signature,

    /// Number of blocks in ledger exceeds the tombstone block number
    TombstoneBlockExceeded,

    /// Tombstone block is too far in the future
    TombstoneBlockTooFar,

    /// Unknown error (should never happen)
    Unknown,

    /// Amount exceeds mint limit
    AmountExceedsMintLimit,
}
