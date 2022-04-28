// Copyright (c) 2018-2022 The MobileCoin Foundation

//! NetworkState implementation that polls nodes for their current state and is
//! not part of consensus. This is currently implemented by faking SCP messages
//! and utilizing SCPNetworkState.

use crate::{NetworkState, SCPNetworkState};
use mc_common::{
    logger::{log, Logger},
    NodeID,
};
use mc_connection::{
    BlockchainConnection, Connection, ConnectionManager, RetryableBlockchainConnection, }; use mc_consensus_scp::{
    core_types::Ballot, msg::ExternalizePayload, test_utils, Msg, QuorumSet, SlotIndex, Topic,
};
use mc_transaction_core::BlockIndex;
use mc_util_uri::ConnectionUri;
use retry::delay::{jitter, Fibonacci};
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Condvar, Mutex},
    thread,
    time::Duration,
};

pub struct PollingNetworkState<BC: BlockchainConnection> {
    /// Connection manager (for consensus nodes we are going to poll).
    manager: ConnectionManager<BC>,

    /// SCPNetworkState instance that provides the actual blocking/quorum set
    /// check logic.
    scp_network_state: SCPNetworkState<NodeID>,

    /// Logger.
    logger: Logger,
}

impl<BC: BlockchainConnection + 'static> PollingNetworkState<BC> {
    pub fn new(
        quorum_set: QuorumSet<NodeID>,
        manager: ConnectionManager<BC>,
        logger: Logger,
    ) -> Self {
        // Since we want to re-use the findQuorum method on our QuorumSet object,
        // fabricate a message map based on the current block indexes we're
        // aware of.

        // Since PollingNetworkState is not a full-fledged consensus node, it does not
        // have a local node id. However, quorum tests inside the scp crate require a
        // local node id, so we provide one. Ideally this should not be a node id that
        // can be used on a real network.
        let local_node_id = test_utils::test_node_id(0);

        Self {
            manager,
            scp_network_state: SCPNetworkState::new(local_node_id, quorum_set),
            logger,
        }
    }

    /// Polls peers to find out the current state of the network.
    pub fn poll(&mut self) {
        type ResultsMap = HashMap<NodeID, Option<BlockIndex>>;
        let results_and_condvar = Arc::new((Mutex::new(ResultsMap::default()), Condvar::new()));

        for conn in self.manager.conns() {
            let node_id = conn
                .uri()
                .node_id()
                .expect("Could not get node_id from URI");

            let thread_logger = self.logger.clone();
            let thread_results_and_condvar = results_and_condvar.clone();
            thread::Builder::new()
                .name(format!("Poll:{}", node_id))
                .spawn(move || {
                    log::debug!(thread_logger, "Getting last block from {}", conn);

                    let &(ref lock, ref condvar) = &*thread_results_and_condvar;

                    let block_height_result = conn.fetch_block_height(Self::get_retry_iterator());

                    let mut results = lock.lock().expect("mutex poisoned");

                    match &block_height_result {
                        Ok(index) => {
                            log::debug!(
                                thread_logger,
                                "Last block reported by {}: {}",
                                conn,
                                index
                            );
                            results.insert(node_id.clone(), Some(*index));
                        }
                        Err(err) => {
                            log::error!(
                                thread_logger,
                                "Failed getting last block from {}: {:?}",
                                conn,
                                err
                            );
                            results.insert(node_id.clone(), None);
                        }
                    }
                    condvar.notify_one();
                })
                .expect("Failed spawning polling thread!");
        }

        // Wait until we get all results.
        let &(ref lock, ref condvar) = &*results_and_condvar;
        let num_peers = self.manager.len();
        let results = condvar //.wait(lock.lock().unwrap()).unwrap();
            .wait_while(lock.lock().unwrap(), |ref mut results| {
                results.len() < num_peers
            })
            .expect("waiting on condvar failed");

        log::debug!(
            self.logger,
            "Polling finished, current results: {:?}",
            results
        );

        // Hackishly feed into SCPNetworkState
        for (node_id, block_index) in results.iter() {
            if let Some(block_index) = block_index {
                self.scp_network_state.push(Msg::<&str, NodeID>::new(
                    node_id.clone(),
                    QuorumSet::empty(),
                    *block_index as SlotIndex,
                    Topic::Externalize(ExternalizePayload {
                        C: Ballot::new(1, &["fake"]),
                        HN: 1,
                    }),
                ));
            }
        }
    }

    pub fn peer_to_current_block_index(&self) -> &HashMap<NodeID, BlockIndex> {
        self.scp_network_state.peer_to_current_slot()
    }

    fn get_retry_iterator() -> Box<dyn Iterator<Item = Duration>> {
        // Start at 50ms, make 10 attempts (total would be 7150ms)
        Box::new(Fibonacci::from_millis(50).take(10).map(jitter))
    }
}

impl<BC: BlockchainConnection> NetworkState for PollingNetworkState<BC> {
    /// Returns true if `connections` forms a blocking set for this node and, if
    /// the local node is included, a quorum.
    ///
    /// # Arguments
    /// * `node_ids` - connection IDs of other nodes.
    fn is_blocking_and_quorum(&self, node_ids: &HashSet<NodeID>) -> bool {
        self.scp_network_state.is_blocking_and_quorum(node_ids)
    }

    /// Returns true if the local node has "fallen behind its peers" and should
    /// attempt to sync.
    ///
    /// # Arguments
    /// * `local_block_index` - The highest block externalized by this node.
    fn is_behind(&self, local_block_index: BlockIndex) -> bool {
        self.scp_network_state.is_behind(local_block_index)
    }

    /// Returns the highest block index the network agrees on (the highest block
    /// index from a set of peers that passes the "is blocking nad quorum"
    /// test).
    fn highest_block_index_on_network(&self) -> Option<BlockIndex> {
        self.scp_network_state.highest_block_index_on_network()
    }
}
