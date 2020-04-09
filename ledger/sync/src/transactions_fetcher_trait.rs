// Copyright (c) 2018-2020 MobileCoin Inc.

//! The `TransactionsFetcher` trait describes the interface used by `LedgerSyncService` for
//! fetching transaction data.

use common::ResponderId;
use std::fmt::Debug;
use transaction::{Block, RedactedTx};

pub trait TransactionFetcherError: Debug + Send + Sync {}

pub trait TransactionsFetcher: Sized + Sync + Send {
    type Error: TransactionFetcherError;

    /// Fetches the list of transactions for a given block.
    /// The implementer of this method is responsible for ensuring a sane timeout behavior.
    ///
    /// # Arguments
    /// * `safe_responder_ids` - List of responder IDs that have been identified as being able to provide a
    /// consistent copy of the blockchain.
    /// * `block` - The block we want to fetch transaction data for.
    fn get_transactions_by_block(
        &self,
        safe_responder_ids: &[ResponderId],
        block: &Block,
    ) -> Result<Vec<RedactedTx>, Self::Error>;
}
