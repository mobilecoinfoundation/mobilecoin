// Copyright (c) 2018-2021 The MobileCoin Foundation

use failure::Fail;
use mc_connection::Error as ConnectionError;
use mc_crypto_keys::KeyError;
use mc_util_lmdb::MetadataStoreError;
use std::string::FromUtf8Error;

/// Watcher Errors
#[derive(Debug, Fail)]
pub enum WatcherError {
    #[fail(display = "URL Parse Error: {}", _0)]
    URLParse(url::ParseError),

    #[fail(display = "WatcherDBError: {}", _0)]
    DB(WatcherDBError),

    #[fail(display = "SyncFailed")]
    SyncFailed,

    #[fail(display = "Node connection error: {}", _0)]
    Connection(ConnectionError),
}

impl From<url::ParseError> for WatcherError {
    fn from(src: url::ParseError) -> Self {
        Self::URLParse(src)
    }
}

impl From<WatcherDBError> for WatcherError {
    fn from(src: WatcherDBError) -> Self {
        Self::DB(src)
    }
}

impl From<ConnectionError> for WatcherError {
    fn from(src: ConnectionError) -> Self {
        Self::Connection(src)
    }
}

/// WatcherDB Errors
#[derive(Debug, Eq, PartialEq, Copy, Clone, Fail)]
pub enum WatcherDBError {
    #[fail(display = "NotFound")]
    NotFound,

    #[fail(display = "AlreadyExists")]
    AlreadyExists,

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

    #[fail(display = "Database was opened in read-only mode")]
    ReadOnly,

    #[fail(display = "Metadata store error: {}", _0)]
    MetadataStore(MetadataStoreError),

    #[fail(display = "Utf8 error")]
    Utf8,

    #[fail(display = "URL Parse Error: {}", _0)]
    URLParse(url::ParseError),

    #[fail(display = "Crypto key error: {}", _0)]
    CryptoKey(KeyError),
}

impl From<lmdb::Error> for WatcherDBError {
    fn from(src: lmdb::Error) -> Self {
        Self::LmdbError(src)
    }
}

impl From<prost::DecodeError> for WatcherDBError {
    fn from(_src: prost::DecodeError) -> Self {
        Self::Deserialization
    }
}

impl From<prost::EncodeError> for WatcherDBError {
    fn from(_src: prost::EncodeError) -> Self {
        Self::Serialization
    }
}

impl From<std::io::Error> for WatcherDBError {
    fn from(_src: std::io::Error) -> Self {
        Self::IO
    }
}

impl From<MetadataStoreError> for WatcherDBError {
    fn from(e: MetadataStoreError) -> Self {
        Self::MetadataStore(e)
    }
}

impl From<FromUtf8Error> for WatcherDBError {
    fn from(_src: FromUtf8Error) -> Self {
        Self::Utf8
    }
}

impl From<url::ParseError> for WatcherDBError {
    fn from(src: url::ParseError) -> Self {
        Self::URLParse(src)
    }
}

impl From<KeyError> for WatcherDBError {
    fn from(src: KeyError) -> Self {
        Self::CryptoKey(src)
    }
}
