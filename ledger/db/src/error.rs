// Copyright (c) 2018-2022 The MobileCoin Foundation

use displaydoc::Display;
use mc_blockchain_types::{BlockID, BlockIndex};
use mc_transaction_core::membership_proofs::RangeError;
use mc_util_lmdb::MetadataStoreError;

/// A Ledger error kind.
#[derive(Clone, Display, Eq, PartialEq)]
pub enum Error {
    /// Record not found
    NotFound,

    /// Failed to serialize
    Serialization,

    /// Failed to deserialize
    Deserialization,

    /// No transactions
    NoTransactions,

    /// Invalid block version: {0}
    InvalidBlockVersion(u32),

    /// No key images were found
    NoKeyImages,

    /// Invalid block index: {0}
    InvalidBlockIndex(BlockIndex),

    /// Key image has already been spent
    KeyImageAlreadySpent,

    /// Duplicate output public key
    DuplicateOutputPublicKey,

    /// Invalid block contents
    InvalidBlockContents,

    /// Invalid block ID: {0}
    InvalidBlockID(BlockID),

    /// Invalid parent block ID: {0}
    InvalidParentBlockID(BlockID),

    /// No outputs
    NoOutputs,

    /// Too few outputs
    TooFewOutputs,

    /// BadRslot, may mean database is opened multiple times in a process.
    BadRslot,

    /// Capacity exceeded
    CapacityExceeded,

    /// TxOut Index out of bounds: {0}
    TxOutIndexOutOfBounds(u64),

    /// LMDB: {0}
    Lmdb(lmdb::Error),

    /// Invalid Range
    Range,

    /// Metadata store: {0}
    MetadataStore(MetadataStoreError),

    /// Invalid mint configuration: {0}
    InvalidMintConfig(String),

    /** Mint limit exceeded: Attempted to mint {0}, currently minted {1} out
     * of {2}
     */
    MintLimitExceeded(u64, u64, u64),

    /// Total minted amount cannot decrease: {0} < {1}
    TotalMintedAmountCannotDecrease(u64, u64),

    /// Duplicate MintTx
    DuplicateMintTx,

    /// Duplicate MintConfigTx
    DuplicateMintConfigTx,

    /// Block metadata is required at this block version
    BlockMetadataRequired,

    /// Missing masked amonut
    MissingMaskedAmount,
}

// Implement Debug by forwarding to Display
//
// This is somewhat unusual, but the main reason is, lmdb::error::Other(c_int)
// is very opaque in the Debug output, and displays a nice human readable string
// in the Display output. The debug output often occurs when we call
// LedgerDb::open and it fails because of an OS issue, and this error is
// unwrapped, which is very typical. This change will make it show e.g "file not
// found" or "permission denied" instead of obscure errno codes.
impl core::fmt::Debug for Error {
    fn fmt(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
        <Self as core::fmt::Display>::fmt(self, formatter)
    }
}

impl From<lmdb::Error> for Error {
    fn from(lmdb_error: lmdb::Error) -> Self {
        match lmdb_error {
            lmdb::Error::NotFound => Error::NotFound,
            lmdb::Error::BadRslot => Error::BadRslot,
            err => Error::Lmdb(err),
        }
    }
}

impl From<mc_util_serial::decode::Error> for Error {
    fn from(_: mc_util_serial::decode::Error) -> Self {
        Error::Deserialization
    }
}

impl From<mc_util_serial::encode::Error> for Error {
    fn from(_: mc_util_serial::encode::Error) -> Self {
        Error::Serialization
    }
}

impl From<mc_util_serial::DecodeError> for Error {
    fn from(_: mc_util_serial::DecodeError) -> Self {
        Error::Deserialization
    }
}

impl From<mc_util_serial::EncodeError> for Error {
    fn from(_: mc_util_serial::EncodeError) -> Self {
        Error::Serialization
    }
}

impl From<RangeError> for Error {
    fn from(_: RangeError) -> Self {
        Error::Range
    }
}

impl From<MetadataStoreError> for Error {
    fn from(src: MetadataStoreError) -> Self {
        Self::MetadataStore(src)
    }
}
