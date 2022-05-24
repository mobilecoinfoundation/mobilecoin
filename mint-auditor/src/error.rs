// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Mint auditor error data type.

use crate::gnosis::Error as GnosisError;
use displaydoc::Display;
use mc_ledger_db::Error as LedgerDbError;
use mc_transaction_core::BlockIndex;
use mc_util_lmdb::MetadataStoreError;
use mc_util_serial::{DecodeError, EncodeError};
use std::io::Error as IoError;

/// Mint auditor error data type.
#[derive(Debug, Display)]
pub enum Error {
    /// LMDB: {0}
    Lmdb(lmdb::Error),

    /// Not found
    NotFound,

    /// Metadata store: {0}
    MetadataStore(MetadataStoreError),

    /// IO: {0}
    Io(IoError),

    /// Ledger DB: {0}
    LedgerDb(LedgerDbError),

    /// Decode: {0}
    Decode(DecodeError),

    /// Encode: {0}
    Encode(EncodeError),

    /// Unexpected block index {0} (was expecting {1})
    UnexpectedBlockIndex(BlockIndex, BlockIndex),

    /// Gnosis: {0}
    Gnosis(GnosisError),

    /// Gnosis tx hash already in database and data differs
    TxHashConflict(String),
}

impl From<lmdb::Error> for Error {
    fn from(err: lmdb::Error) -> Self {
        match err {
            lmdb::Error::NotFound => Self::NotFound,
            err => Self::Lmdb(err),
        }
    }
}

impl From<MetadataStoreError> for Error {
    fn from(err: MetadataStoreError) -> Self {
        Self::MetadataStore(err)
    }
}

impl From<IoError> for Error {
    fn from(err: IoError) -> Self {
        Self::Io(err)
    }
}

impl From<LedgerDbError> for Error {
    fn from(err: LedgerDbError) -> Self {
        Self::LedgerDb(err)
    }
}

impl From<DecodeError> for Error {
    fn from(err: DecodeError) -> Self {
        Self::Decode(err)
    }
}

impl From<EncodeError> for Error {
    fn from(err: EncodeError) -> Self {
        Self::Encode(err)
    }
}

impl From<GnosisError> for Error {
    fn from(err: GnosisError) -> Self {
        Self::Gnosis(err)
    }
}
