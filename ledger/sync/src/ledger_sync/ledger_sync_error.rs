// Copyright (c) 2018-2020 MobileCoin Inc.

//! Errors related to ledger synchronization

use crate::transactions_fetcher_trait::TransactionFetcherError;
use failure::Fail;
use mc_connection::Error as ConnectionError;
use mc_ledger_db::Error as LedgerDbError;
use retry::Error as RetryError;

#[derive(Debug, Fail)]
pub enum LedgerSyncError {
    #[fail(display = "Error occurred with ledger_db.")]
    DBError,

    #[fail(display = "No potentially safe blocks.")]
    NoSafeBlocks,

    #[fail(display = "Empty vec of potentially safe blocks.")]
    EmptyBlockVec,

    #[fail(display = "Transactions and block do not match.")]
    TransactionsAndBlockMismatch,

    #[fail(display = "Consensus connection failure: {:?}", _0)]
    Consensus(RetryError<ConnectionError>),

    // Super not a fan of this, but the error story here is really complex
    #[fail(display = "Transaction fetch failure: {:?}", _0)]
    TransactionFetcher(Box<dyn TransactionFetcherError>),

    #[fail(display = "Api conversion error: {:?}", _0)]
    ApiConversionError(mc_api::ConversionError),

    #[fail(display = "Invalid block ID.")]
    InvalidBlockId,

    #[fail(display = "No transaction data.")]
    NoTransactionData,
}

impl<TFE: TransactionFetcherError + 'static> From<TFE> for LedgerSyncError {
    fn from(src: TFE) -> Self {
        LedgerSyncError::TransactionFetcher(Box::new(src))
    }
}

impl From<LedgerDbError> for LedgerSyncError {
    fn from(_x: LedgerDbError) -> Self {
        LedgerSyncError::DBError
    }
}
