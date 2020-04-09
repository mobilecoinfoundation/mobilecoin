// Copyright (c) 2018-2020 MobileCoin Inc.

use common::logger::global_log;
use failure::Fail;

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

    #[fail(display = "InvalidBlockContents")]
    InvalidBlockContents,

    #[fail(display = "InvalidBlockID")]
    InvalidBlockID,

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
}

impl From<lmdb::Error> for Error {
    fn from(lmdb_error: lmdb::Error) -> Self {
        match lmdb_error {
            lmdb::Error::NotFound => Error::NotFound,
            lmdb::Error::BadRslot => Error::BadRslot,
            err => {
                global_log::error!("lmdb error: {:?} ", err);
                Error::LmdbError(err)
            }
        }
    }
}

impl From<mcserial::decode::Error> for Error {
    fn from(_: mcserial::decode::Error) -> Self {
        Error::Deserialization
    }
}

impl From<mcserial::encode::Error> for Error {
    fn from(_: mcserial::encode::Error) -> Self {
        Error::Serialization
    }
}

impl From<transaction::range::RangeError> for Error {
    fn from(_: transaction::range::RangeError) -> Self {
        Error::RangeError
    }
}
