// Copyright (c) 2018-2020 MobileCoin Inc.

//! The `TransactionsFetcher` trait describes the interface used by `LedgerSyncService` for
//! fetching transaction data.

use common::ResponderId;
use std::fmt::Debug;
use transaction::{Block, BlockContents};

pub trait TransactionFetcherError: Debug + Send + Sync {}

pub trait TransactionsFetcher: Sized + Sync + Send {
    type Error: TransactionFetcherError;

    /// Fetches the contents of a given block.
    /// The implementer of this method is responsible for ensuring a sane timeout behavior.
    ///
    /// # Arguments
    /// * `safe_responder_ids` - List of responder IDs that have been identified as being able to provide a
    /// consistent copy of the blockchain.
    /// * `block` - The block we want to fetch contents for.
    fn get_block_contents(
        &self,
        safe_responder_ids: &[ResponderId],
        block: &Block,
    ) -> Result<BlockContents, Self::Error>;
}
