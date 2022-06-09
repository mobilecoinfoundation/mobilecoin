// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Mint auditor error data type.

use crate::{db::TransactionRetriableError, gnosis::Error as GnosisError};
use diesel::result::Error as DieselError;
use diesel_migrations::RunMigrationsError;
use displaydoc::Display;
use mc_ledger_db::Error as LedgerDbError;
use mc_transaction_core::BlockIndex;
use mc_util_serial::DecodeError;
use std::io::Error as IoError;

/// Mint auditor error data type.
#[derive(Debug, Display)]
pub enum Error {
    /// Not found
    NotFound,

    /// IO: {0}
    Io(IoError),

    /// Ledger DB: {0}
    LedgerDb(LedgerDbError),

    /// Decode: {0}
    Decode(DecodeError),

    /// Unexpected block index {0} (was expecting {1})
    UnexpectedBlockIndex(BlockIndex, BlockIndex),

    /// Diesel: {0}
    Diesel(DieselError),

    /// Diesel migrations: {0}
    DieselMigrations(RunMigrationsError),

    /// R2d2 pool: {0}
    R2d2Pool(diesel::r2d2::PoolError),

    /// Gnosis: {0}
    Gnosis(GnosisError),

    /// Other: {0}
    Other(String),
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

impl From<DieselError> for Error {
    fn from(err: DieselError) -> Self {
        match err {
            DieselError::NotFound => Self::NotFound,
            err => Self::Diesel(err),
        }
    }
}

impl From<RunMigrationsError> for Error {
    fn from(err: RunMigrationsError) -> Self {
        Self::DieselMigrations(err)
    }
}

impl From<diesel::r2d2::PoolError> for Error {
    fn from(err: diesel::r2d2::PoolError) -> Self {
        Self::R2d2Pool(err)
    }
}

impl From<GnosisError> for Error {
    fn from(err: GnosisError) -> Self {
        Self::Gnosis(err)
    }
}

impl TransactionRetriableError for Error {
    fn should_retry(&self) -> bool {
        matches!(
            self,
            Self::Diesel(DieselError::DatabaseError(_, _)) | Self::R2d2Pool(_)
        )
    }
}

// Make clap happy.
impl std::error::Error for Error {}
