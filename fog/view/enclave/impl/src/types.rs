// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Helper structs for client `QueryResponse` collation.

use mc_fog_types::{common::BlockRange, view::QueryResponse};

/// Helper struct that contains the decrypted `QueryResponse` and the
/// `BlockRange` the shard is responsible for.
#[derive(Clone)]
pub(crate) struct DecryptedMultiViewStoreQueryResponse {
    /// Decrypted `QueryResponse`
    pub(crate) query_response: QueryResponse,
    /// The `BlockRange` that the shard is meant to process.
    pub(crate) block_range: BlockRange,
}

/// Helper struct that contains block data for the client `QueryResponse`
#[derive(Clone)]
pub(crate) struct BlockData {
    /// The highest processed block count that will be returned to the client.
    pub(crate) highest_processed_block_count: u64,
    /// The timestamp for the highest processed block count
    pub(crate) highest_processed_block_signature_timestamp: u64,
}

/// Helper struct that contains data associated with the "last known" fields in
/// the `QueryResponse`.
#[derive(Default)]
pub(crate) struct LastKnownData {
    /// The globally maximum block count that any store has seen but not
    /// necessarily processed.
    pub(crate) last_known_block_count: u64,
    /// The cumulative TxOut count associated with the last known block count.
    pub(crate) last_known_block_cumulative_txo_count: u64,
}

impl BlockData {
    pub(crate) fn new(
        highest_processed_block_count: u64,
        highest_processed_block_signature_timestamp: u64,
    ) -> Self {
        Self {
            highest_processed_block_count,
            highest_processed_block_signature_timestamp,
        }
    }
}
impl Default for BlockData {
    fn default() -> Self {
        Self {
            highest_processed_block_count: u64::MIN,
            highest_processed_block_signature_timestamp: u64::MIN,
        }
    }
}

impl LastKnownData {
    pub(crate) fn new(
        last_known_block_count: u64,
        last_known_block_cumulative_txo_count: u64,
    ) -> Self {
        Self {
            last_known_block_count,
            last_known_block_cumulative_txo_count,
        }
    }
}
