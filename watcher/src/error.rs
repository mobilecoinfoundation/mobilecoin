// Copyright (c) 2018-2020 MobileCoin Inc.

use failure::Fail;

/// SignatureStore Errors
#[derive(Debug, Eq, PartialEq, Copy, Clone, Fail)]
pub enum SignatureStoreError {
    #[fail(display = "NotFound")]
    NotFound,

    #[fail(display = "Serialization")]
    Serialization,

    #[fail(display = "Deserialization")]
    Deserialization,

    #[fail(display = "LmdbError")]
    LmdbError(lmdb::Error),
}

impl From<prost::DecodeError> for SignatureStoreError {
    fn from(_src: prost::DecodeError) -> Self {
        SignatureStoreError::Deserialization
    }
}

impl From<prost::EncodeError> for SignatureStoreError {
    fn from(_src: prost::EncodeError) -> Self {
        SignatureStoreError::Serialization
    }
}

impl From<lmdb::Error> for SignatureStoreError {
    fn from(src: lmdb::Error) -> Self {
        SignatureStoreError::LmdbError(src)
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

    #[fail(display = "LmdbError")]
    LmdbError(lmdb::Error),

    #[fail(display = "SignatureStore")]
    SignatureStore(SignatureStoreError),
}

impl From<lmdb::Error> for WatcherDBError {
    fn from(src: lmdb::Error) -> Self {
        WatcherDBError::LmdbError(src)
    }
}

impl From<SignatureStoreError> for WatcherDBError {
    fn from(src: SignatureStoreError) -> Self {
        WatcherDBError::SignatureStore(src)
    }
}
