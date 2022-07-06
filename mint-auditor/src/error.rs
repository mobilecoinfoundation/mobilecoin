// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Mint auditor error data type.

use crate::{
    db::TransactionRetriableError,
    gnosis::{Error as GnosisError, EthAddr, EthTxHash},
};
use diesel::result::{DatabaseErrorKind, Error as DieselError};
use diesel_migrations::RunMigrationsError;
use displaydoc::Display;
use hex::FromHexError;
use mc_api::display::Error as ApiDisplayError;
use mc_blockchain_types::BlockIndex;
use mc_crypto_keys::KeyError;
use mc_ledger_db::Error as LedgerDbError;
use mc_transaction_core::ViewKeyMatchError;
use mc_transaction_std::MemoDecodingError;
use mc_util_serial::DecodeError;
use std::io::Error as IoError;

/// Mint auditor error data type.
#[derive(Debug, Display)]
pub enum Error {
    /// Not found
    NotFound,

    /// Already exists: {0}
    AlreadyExists(String),

    /// Object not saved to database
    ObjectNotSaved,

    /// Deposit and mint mismatch: {0}
    DepositAndMintMismatch(String),

    /// Ethereum token {0} not audited in safe {1} (tx hash: {2})
    EthereumTokenNotAudited(EthAddr, EthAddr, EthTxHash),

    /// Gnosis safe {0} not audited
    GnosisSafeNotAudited(EthAddr),

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

    /// Api display: {0}
    ApiDisplay(ApiDisplayError),

    /// Hex parse: {0}
    HexParse(FromHexError),

    /// Crypto key: {0}
    Key(KeyError),

    /// Invalid length: expected {0}, got {1}
    InvalidLength(usize, usize),

    /// Invalid nonce identifier: {0:?}
    InvalidNonceIdentifier(Vec<u8>),

    /// View key match: {0}
    ViewKeyMatch(ViewKeyMatchError),

    /// Memo decoding: {0}
    MemoDecoding(MemoDecodingError),

    /// Invalid memo type
    InvalidMemoType,

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
            DieselError::DatabaseError(DatabaseErrorKind::UniqueViolation, info) => {
                Self::AlreadyExists(info.message().to_string())
            }
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

impl From<ApiDisplayError> for Error {
    fn from(err: ApiDisplayError) -> Self {
        Self::ApiDisplay(err)
    }
}

impl From<FromHexError> for Error {
    fn from(err: FromHexError) -> Self {
        Self::HexParse(err)
    }
}

impl From<KeyError> for Error {
    fn from(err: KeyError) -> Self {
        Self::Key(err)
    }
}

impl From<ViewKeyMatchError> for Error {
    fn from(err: ViewKeyMatchError) -> Self {
        Self::ViewKeyMatch(err)
    }
}

impl From<MemoDecodingError> for Error {
    fn from(err: MemoDecodingError) -> Self {
        Self::MemoDecoding(err)
    }
}

impl TransactionRetriableError for Error {
    fn should_retry(&self) -> bool {
        match self {
            Self::Diesel(DieselError::NotFound) => false,
            Self::Diesel(DieselError::DatabaseError(DatabaseErrorKind::ForeignKeyViolation, _)) => {
                false
            }
            Self::R2d2Pool(_) => true,
            _ => false,
        }
    }
}

// Make clap happy.
impl std::error::Error for Error {}
