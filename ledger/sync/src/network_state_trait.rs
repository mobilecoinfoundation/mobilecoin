// Copyright (c) 2018-2020 MobileCoin Inc.

//! Tracks the state of peers' ledgers.

use mc_common::{HashSet, ResponderId};
use mc_transaction_core::BlockIndex;

/// An interface for an object that keeps track of the network's status, allowing SyncService to
/// check if the local node has fallen behind a certain block index.
pub trait NetworkState: Send {
    /// Returns true if `peers` forms a blocking set for this node and, if the local node is included, a quorum.
    ///
    /// # Arguments
    /// * `conn_ids` - IDs of other nodes.
    fn is_blocking_and_quorum(&self, conn_ids: &HashSet<ResponderId>) -> bool;

    /// Returns true if the local node has "fallen behind its peers" and should attempt to sync.
    ///
    /// # Arguments
    /// * `local_block_index` - The highest block externalized by this node.
    fn is_behind(&self, local_block_index: BlockIndex) -> bool;
}
