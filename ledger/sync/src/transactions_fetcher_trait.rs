// Copyright (c) 2018-2022 The MobileCoin Foundation

//! The `TransactionsFetcher` trait describes the interface used by
//! `LedgerSyncService` for fetching transaction data.

use mc_common::NodeID;
use mc_transaction_core::{Block, BlockData};
use std::fmt::Debug;

pub trait TransactionFetcherError: Debug + Send + Sync {}

pub trait TransactionsFetcher: Sized + Sync + Send {
    type Error: TransactionFetcherError;

    /// Fetches the contents of a given block.
    /// The implementer of this method is responsible for ensuring a sane
    /// timeout behavior.
    ///
    /// # Arguments
    /// * `safe_node_ids` - List of NodeIDs that have been identified
    ///   as being able to provide a consistent copy of the blockchain.
    /// * `block` - The block we want to fetch contents for.
    fn get_block_data(
        &self,
        safe_node_ids: &[NodeID],
        block: &Block,
    ) -> Result<BlockData, Self::Error>;
}
