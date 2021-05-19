// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Error data types

use displaydoc::Display;
use mc_connection::Error as ConnectionError;
use mc_crypto_keys::KeyError;
use mc_ledger_sync::ReqwestTransactionsFetcherError;
use mc_util_lmdb::MetadataStoreError;
use std::string::FromUtf8Error;

/// Watcher Errors
#[derive(Debug, Display)]
pub enum WatcherError {
    /// URL parse: {0}
    URLParse(url::ParseError),

    /// DB: {0}
    DB(WatcherDBError),

    /// Block fetching failed
    BlockFetch(ReqwestTransactionsFetcherError),

    /// Connection: {0}
    Connection(ConnectionError),

    /// Unknown tx source url: {0}
    UnknownTxSourceUrl(String),
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

impl From<ReqwestTransactionsFetcherError> for WatcherError {
    fn from(src: ReqwestTransactionsFetcherError) -> Self {
        Self::BlockFetch(src)
    }
}

impl From<ConnectionError> for WatcherError {
    fn from(src: ConnectionError) -> Self {
        Self::Connection(src)
    }
}

/// WatcherDB Errors
#[derive(Debug, Eq, PartialEq, Copy, Clone, Display)]
pub enum WatcherDBError {
    /// Not found
    NotFound,

    /// Already exists
    AlreadyExists,

    /// Serialization
    Serialization,

    /// Deserialization
    Deserialization,

    /// Loading blocks out of order
    BlockOrder,

    /// LMDB: {0}
    LmdbError(lmdb::Error),

    /// IO
    IO,

    /// Database was opened in read-only mode
    ReadOnly,

    /// Metadata store: {0}
    MetadataStore(MetadataStoreError),

    /// UTF8
    Utf8,

    /// URL Parse: {0}
    URLParse(url::ParseError),

    /// Cryptographic key: {0}
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
