// Copyright (c) 2018-2022 The MobileCoin Foundation

use crate::timestamp_validator::Error as TimestampError;
use displaydoc::Display;
use mc_ledger_db::Error as LedgerDbError;
use mc_transaction_core::mint::MintValidationError;

#[derive(Clone, Debug, Display, Eq, PartialEq)]
pub enum MintTxManagerError {
    /// Mint validation error: {0}
    MintValidation(MintValidationError),

    /// Ledger error: {0}
    LedgerDb(LedgerDbError),

    /// Timestamp error: {0}
    Timestamp(TimestampError),
}

impl From<MintValidationError> for MintTxManagerError {
    fn from(err: MintValidationError) -> Self {
        Self::MintValidation(err)
    }
}

impl From<LedgerDbError> for MintTxManagerError {
    fn from(err: LedgerDbError) -> Self {
        Self::LedgerDb(err)
    }
}

impl From<TimestampError> for MintTxManagerError {
    fn from(err: TimestampError) -> Self {
        Self::Timestamp(err)
    }
}

pub type MintTxManagerResult<T> = Result<T, MintTxManagerError>;
