// Copyright (c) 2018-2020 MobileCoin Inc.

use failure::Fail;
use mc_util_lmdb::MetadataStoreError;

/// A Ledger error kind.
#[derive(Debug, Eq, PartialEq, Copy, Clone, Fail)]
pub enum Error {
    #[fail(display = "NotFound")]
    NotFound,

    #[fail(display = "Serialization")]
    Serialization,

    #[fail(display = "Deserialization")]
    Deserialization,

    #[fail(display = "NoTransactions")]
    NoTransactions,

    #[fail(display = "InvalidBlock")]
    InvalidBlock,

    #[fail(display = "KeyImageAlreadySpent")]
    KeyImageAlreadySpent,

    #[fail(display = "DuplicateOutputPublicKey")]
    DuplicateOutputPublicKey,

    #[fail(display = "InvalidBlockContents")]
    InvalidBlockContents,

    #[fail(display = "InvalidBlockID")]
    InvalidBlockID,

    #[fail(display = "NoOutputs")]
    NoOutputs,

    /// LMDB error, may mean database is opened multiple times in a process.
    #[fail(display = "BadRslot")]
    BadRslot,

    #[fail(display = "CapacityExceeded")]
    CapacityExceeded,

    #[fail(display = "IndexOutOfBounds: {}", _0)]
    IndexOutOfBounds(u64),

    #[fail(display = "LmdbError")]
    LmdbError(lmdb::Error),

    #[fail(display = "RangeError")]
    RangeError,

    #[fail(display = "Metadata store error: {}", _0)]
    MetadataStore(MetadataStoreError),
}

impl From<lmdb::Error> for Error {
    fn from(lmdb_error: lmdb::Error) -> Self {
        match lmdb_error {
            lmdb::Error::NotFound => Error::NotFound,
            lmdb::Error::BadRslot => Error::BadRslot,
            err => Error::LmdbError(err),
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

impl From<mc_transaction_core::range::RangeError> for Error {
    fn from(_: mc_transaction_core::range::RangeError) -> Self {
        Error::RangeError
    }
}

impl From<MetadataStoreError> for Error {
    fn from(src: MetadataStoreError) -> Self {
        Self::MetadataStore(src)
    }
}
