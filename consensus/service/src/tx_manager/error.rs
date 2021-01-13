// Copyright (c) 2018-2021 The MobileCoin Foundation

use displaydoc::Display;
use mc_consensus_enclave::Error as ConsensusEnclaveError;
use mc_ledger_db::Error as LedgerDbError;
use mc_transaction_core::{tx::TxHash, validation::TransactionValidationError};

#[derive(Clone, Debug, Display)]
pub enum TxManagerError {
    /// Enclave error: {0}
    Enclave(ConsensusEnclaveError),

    /// Transaction validation error: {0}
    TransactionValidation(TransactionValidationError),

    /// Tx(s) not in cache {0:?}
    NotInCache(Vec<TxHash>),

    /// Ledger error: {0}
    LedgerDb(LedgerDbError),
}

impl From<ConsensusEnclaveError> for TxManagerError {
    fn from(err: ConsensusEnclaveError) -> Self {
        if let ConsensusEnclaveError::MalformedTx(transaction_validation_error) = err {
            Self::TransactionValidation(transaction_validation_error)
        } else {
            Self::Enclave(err)
        }
    }
}

impl From<TransactionValidationError> for TxManagerError {
    fn from(err: TransactionValidationError) -> Self {
        Self::TransactionValidation(err)
    }
}

impl From<LedgerDbError> for TxManagerError {
    fn from(err: LedgerDbError) -> Self {
        Self::LedgerDb(err)
    }
}

pub type TxManagerResult<T> = Result<T, TxManagerError>;
