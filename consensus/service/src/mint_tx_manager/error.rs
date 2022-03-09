// Copyright (c) 2018-2022 The MobileCoin Foundation

use displaydoc::Display;
use mc_ledger_db::Error as LedgerDbError;
use mc_transaction_core::{mint::MintValidationError, TokenId};

#[derive(Clone, Debug, Display)]
pub enum MintTxManagerError {
    /// Mint validation error: {0}
    MintValidation(MintValidationError),

    /// Ledger error: {0}
    LedgerDb(LedgerDbError),

    /// No master minters configured for token id {0}
    NoMasterMinters(TokenId),
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

pub type MintTxManagerResult<T> = Result<T, MintTxManagerError>;
