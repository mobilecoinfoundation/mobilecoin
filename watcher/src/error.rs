// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Error data types

use failure::Fail;
use mc_connection::Error as ConnectionError;
use mc_crypto_keys::KeyError;
use mc_util_lmdb::MetadataStoreError;
use std::string::FromUtf8Error;

/// Watcher Errors
#[derive(Debug, Fail)]
pub enum WatcherError {
    /// URL parse error: {}
    #[fail(display = "URL Parse Error: {}", _0)]
    URLParse(url::ParseError),

    /// DB error: {}
    #[fail(display = "WatcherDBError: {}", _0)]
    DB(WatcherDBError),

    /// Sync failed
    #[fail(display = "SyncFailed")]
    SyncFailed,

    /// Connection error: {}
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
    /// Not found
    #[fail(display = "NotFound")]
    NotFound,

    /// Already exists
    #[fail(display = "AlreadyExists")]
    AlreadyExists,

    /// Serialization
    #[fail(display = "Serialization")]
    Serialization,

    /// Deserialization
    #[fail(display = "Deserialization")]
    Deserialization,

    /// Loading blocks out of order
    #[fail(display = "Loading blocks out of order.")]
    BlockOrder,

    /// LMDB error: {}
    #[fail(display = "LmdbError: {}", _0)]
    LmdbError(lmdb::Error),

    /// IO Error
    #[fail(display = "Error managing IO")]
    IO,

    /// Database was opened in read-only mode
    #[fail(display = "Database was opened in read-only mode")]
    ReadOnly,

    /// Metadata store error: {}
    #[fail(display = "Metadata store error: {}", _0)]
    MetadataStore(MetadataStoreError),

    /// UTF8 error
    #[fail(display = "Utf8 error")]
    Utf8,

    /// URL Parse error: {}
    #[fail(display = "URL Parse Error: {}", _0)]
    URLParse(url::ParseError),

    /// Cryptographic key error: {}
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
