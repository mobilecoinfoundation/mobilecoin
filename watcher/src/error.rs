// Copyright (c) 2018-2020 MobileCoin Inc.

use failure::Fail;

/// Watcher Errors
#[derive(Debug, Eq, PartialEq, Copy, Clone, Fail)]
pub enum WatcherError {
    #[fail(display = "URL Parse Error: {}", _0)]
    URLParse(url::ParseError),

    #[fail(display = "WatcherDBError: {}", _0)]
    DB(WatcherDBError),

    #[fail(display = "SyncFailed")]
    SyncFailed,
}

impl From<url::ParseError> for WatcherError {
    fn from(src: url::ParseError) -> Self {
        WatcherError::URLParse(src)
    }
}

impl From<WatcherDBError> for WatcherError {
    fn from(src: WatcherDBError) -> Self {
        WatcherError::DB(src)
    }
}

/// WatcherDB Errors
#[derive(Debug, Eq, PartialEq, Copy, Clone, Fail)]
pub enum WatcherDBError {
    #[fail(display = "NotFound")]
    NotFound,

    #[fail(display = "Serialization")]
    Serialization,

    #[fail(display = "Deserialization")]
    Deserialization,

    #[fail(display = "Loading blocks out of order.")]
    BlockOrder,

    #[fail(display = "LmdbError: {}", _0)]
    LmdbError(lmdb::Error),

    #[fail(display = "Error managing IO")]
    IO,
}

impl From<lmdb::Error> for WatcherDBError {
    fn from(src: lmdb::Error) -> Self {
        WatcherDBError::LmdbError(src)
    }
}

impl From<prost::DecodeError> for WatcherDBError {
    fn from(_src: prost::DecodeError) -> Self {
        WatcherDBError::Deserialization
    }
}

impl From<prost::EncodeError> for WatcherDBError {
    fn from(_src: prost::EncodeError) -> Self {
        WatcherDBError::Serialization
    }
}

impl From<std::io::Error> for WatcherDBError {
    fn from(_src: std::io::Error) -> Self {
        WatcherDBError::IO
    }
}
