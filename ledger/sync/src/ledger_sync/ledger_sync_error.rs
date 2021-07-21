// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Errors related to ledger synchronization

use crate::transactions_fetcher_trait::TransactionFetcherError;
use displaydoc::Display;
use mc_connection::Error as ConnectionError;
use mc_ledger_db::Error as LedgerDbError;
use retry::Error as RetryError;

#[derive(Debug, Display)]
pub enum LedgerSyncError {
    /// Ledger db: {0}
    DBError(LedgerDbError),

    /// No potentially safe blocks
    NoSafeBlocks,

    /// Empty vec of potentially safe blocks
    EmptyBlockVec,

    /// Transactions and block do not match
    TransactionsAndBlockMismatch,

    /// Consensus connection failure: {0:?}
    Consensus(RetryError<ConnectionError>),

    // Super not a fan of this, but the error story here is really complex
    /// Transaction fetch failure: {0:?}
    TransactionFetcher(Box<dyn TransactionFetcherError>),

    /// Api conversion error: {0:?}
    ApiConversionError(mc_api::ConversionError),

    /// Invalid block ID
    InvalidBlockId,

    /// No transaction data
    NoTransactionData,
}

impl<TFE: TransactionFetcherError + 'static> From<TFE> for LedgerSyncError {
    fn from(src: TFE) -> Self {
        LedgerSyncError::TransactionFetcher(Box::new(src))
    }
}

impl From<LedgerDbError> for LedgerSyncError {
    fn from(src: LedgerDbError) -> Self {
        LedgerSyncError::DBError(src)
    }
}
