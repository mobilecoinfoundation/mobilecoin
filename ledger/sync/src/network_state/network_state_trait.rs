// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Tracks the state of peers' ledgers.

use mc_common::ResponderId;
use mc_transaction_core::BlockIndex;
use std::collections::HashSet;

/// An interface for an object that keeps track of the network's status,
/// allowing SyncService to check if the local node has fallen behind a certain
/// block index.
pub trait NetworkState: Send {
    /// Returns true if `peers` forms a blocking set for this node and, if the
    /// local node is included, a quorum.
    ///
    /// # Arguments
    /// * `conn_ids` - IDs of other nodes.
    fn is_blocking_and_quorum(&self, conn_ids: &HashSet<ResponderId>) -> bool;

    /// Returns true if the local node has "fallen behind its peers" and should
    /// attempt to sync.
    ///
    /// # Arguments
    /// * `local_block_index` - The highest block externalized by this node.
    fn is_behind(&self, local_block_index: BlockIndex) -> bool;

    /// Returns the highest block index the network agrees on (the highest block
    /// index from a set of peers that passes the "is blocking and quorum"
    /// test).
    fn highest_block_index_on_network(&self) -> Option<BlockIndex>;
}
