// Copyright (c) 2018-2021 The MobileCoin Foundation

use displaydoc::Display;
use mc_transaction_core::{membership_proofs::RangeError, BlockID, BlockIndex};
use mc_util_lmdb::MetadataStoreError;

/// A Ledger error kind.
#[derive(Debug, Eq, PartialEq, Clone, Display)]
pub enum Error {
    /// NotFound
    NotFound,

    /// Serialization
    Serialization,

    /// Deserialization
    Deserialization,

    /// NoTransactions
    NoTransactions,

    /// InvalidBlockVersion: {0}
    InvalidBlockVersion(u32),

    /// NoKeyImages
    NoKeyImages,

    /// InvalidBlockIndex: {0}
    InvalidBlockIndex(BlockIndex),

    /// KeyImageAlreadySpent
    KeyImageAlreadySpent,

    /// DuplicateOutputPublicKey
    DuplicateOutputPublicKey,

    /// InvalidBlockContents
    InvalidBlockContents,

    /// InvalidBlockID: {0}
    InvalidBlockID(BlockID),

    /// InvalidParentBlockID: {0}
    InvalidParentBlockID(BlockID),

    /// NoOutputs
    NoOutputs,

    /// LMDB error, may mean database is opened multiple times in a process.
    BadRslot,

    /// CapacityExceeded
    CapacityExceeded,

    /// IndexOutOfBounds: {0}
    IndexOutOfBounds(u64),

    /// Lmdb: {0}
    Lmdb(lmdb::Error),

    /// Range
    Range,

    /// Metadata store: {0}
    MetadataStore(MetadataStoreError),
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
