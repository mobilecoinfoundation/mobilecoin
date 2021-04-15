// Copyright (c) 2018-2021 The MobileCoin Foundation

//! NetworkState implementation for the `scp` module.

use crate::NetworkState;
use mc_common::{NodeID, ResponderId};
use mc_consensus_scp::{
    core_types::Ballot, msg::ExternalizePayload, predicates::FuncPredicate, GenericNodeId, Msg,
    QuorumSet, SlotIndex, Topic, Value,
};
use mc_transaction_core::BlockIndex;
use serde::{de::DeserializeOwned, Serialize};
use std::{
    collections::{HashMap, HashSet},
    hash::Hash,
};

pub struct SCPNetworkState<ID: GenericNodeId + Send = NodeID> {
    // The local node ID.
    local_node_id: ID,

    // The quorum set of the node we are tracking state for.
    local_quorum_set: QuorumSet<ID>,

    // Highest slot that a given node has externalized.
    id_to_current_slot: HashMap<ID, SlotIndex>,
}

impl<ID: GenericNodeId + Clone + Eq + PartialEq + Hash + Send> SCPNetworkState<ID> {
    pub fn new(local_node_id: ID, local_quorum_set: QuorumSet<ID>) -> Self {
        Self {
            local_node_id,
            local_quorum_set,
            id_to_current_slot: HashMap::default(),
        }
    }

    pub fn push<V: Value>(&mut self, msg: Msg<V, ID>) {
        let sender_id = msg.sender_id.clone();

        // Highest externalized slot index implied by this SCPStatement.
        let new_slot_index: SlotIndex = match msg.topic {
            Topic::Externalize(_) => msg.slot_index,
            // All other messages for a given SlotIndex imply that the previous SlotIndex
            // is the highest externalized slot.
            _ => msg.slot_index - 1,
        };

        // "Upsert"
        let entry_exists = self.id_to_current_slot.contains_key(&sender_id);
        let entry_is_older = entry_exists && self.id_to_current_slot[&sender_id] < new_slot_index;
        if !entry_exists || entry_is_older {
            self.id_to_current_slot.insert(sender_id, new_slot_index);
        }
    }

    pub fn peer_to_current_slot(&self) -> &HashMap<ID, SlotIndex> {
        &self.id_to_current_slot
    }
}

impl<ID: GenericNodeId + Send + AsRef<ResponderId> + DeserializeOwned + Serialize> NetworkState
    for SCPNetworkState<ID>
{
    /// Returns true if `peers` forms a blocking set for this node and, if the
    /// local node is included, a quorum.
    ///
    /// # Arguments
    /// * `responder_ids` - IDs of other nodes.
    fn is_blocking_and_quorum(&self, responder_ids: &HashSet<ResponderId>) -> bool {
        // Construct a map of responder id -> dummy message so that we could leverage
        // the existing quorum findBlockingSet/findQuorum code.
        let msg_map = responder_ids
            .iter()
            .map(|responder_id| {
                (
                    responder_id.clone(),
                    Msg::<&str, ResponderId>::new(
                        responder_id.clone(),
                        QuorumSet::empty(),
                        1,
                        Topic::Externalize(ExternalizePayload {
                            C: Ballot::new(1, &["fake"]),
                            HN: 1,
                        }),
                    ),
                )
            })
            .collect();

        let quorum_set: QuorumSet<ResponderId> = (&self.local_quorum_set).into();

        // Check if responder_ids form a blocking set
        let fp = FuncPredicate {
            test_fn: &|msg: &Msg<&str, ResponderId>| responder_ids.contains(&msg.sender_id),
        };
        let (node_ids, _pred) = quorum_set.findBlockingSet(&msg_map, fp);
        if node_ids.is_empty() {
            return false;
        }

        // Check if responder_ids form a quorum
        let fp = FuncPredicate {
            test_fn: &|msg: &Msg<&str, ResponderId>| responder_ids.contains(&msg.sender_id),
        };
        let (node_ids, _pred) = quorum_set.findQuorum(self.local_node_id.as_ref(), &msg_map, fp);
        if node_ids.is_empty() {
            return false;
        }

        // responder_ids are a blocking set and a quorum.
        true
    }

    /// Returns true if the local node has "fallen behind its peers" and should
    /// attempt to sync.
    ///
    /// # Arguments
    /// * `local_block_index` - The highest block externalized by this node.
    fn is_behind(&self, local_block_index: BlockIndex) -> bool {
        let peers_on_higher_block: Vec<ID> = self
            .peer_to_current_slot()
            .iter()
            .filter(|&(_id, block_index)| *block_index > local_block_index)
            .map(|(id, _block_index)| id.clone())
            .collect();

        self.is_blocking_and_quorum(
            &peers_on_higher_block
                .iter()
                .map(|node_id| node_id.as_ref().clone())
                .collect(),
        )
    }

    /// Returns the highest block index the network agrees on (the highest block
    /// index from a set of peers that passes the "is blocking and quorum"
    /// test).
    fn highest_block_index_on_network(&self) -> Option<BlockIndex> {
        // Create a sorted list of unique slot indexes. These are potential candidates
        // for the highest slot index the network agrees on.
        let mut seen_block_indexes: Vec<BlockIndex> =
            self.peer_to_current_slot().values().cloned().collect();
        seen_block_indexes.sort_unstable();
        seen_block_indexes.dedup();

        // For each potential block index we saw (from the highest to the lowest), see
        // if we can pass the is_blocking_and_quorum test.
        for highest_block_index in seen_block_indexes.iter().rev() {
            let peers_on_higher_block: Vec<ID> = self
                .peer_to_current_slot()
                .iter()
                .filter(|&(_id, block_index)| block_index >= highest_block_index)
                .map(|(id, _block_index)| id.clone())
                .collect();

            if self.is_blocking_and_quorum(
                &peers_on_higher_block
                    .iter()
                    .map(|node_id| node_id.as_ref().clone())
                    .collect(),
            ) {
                // Found a block index the network agrees on.
                return Some(*highest_block_index);
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mc_consensus_scp::{core_types::Ballot, msg::*};
    use mc_peers_test_utils::test_node_id;
    use std::{collections::BTreeSet, iter::FromIterator};

    #[test]
    fn test_new() {
        let local_node_id = test_node_id(1);
        let local_node_quorum_set = QuorumSet::<ResponderId>::empty();
        let network_state =
            SCPNetworkState::<ResponderId>::new(local_node_id.responder_id, local_node_quorum_set);
        assert_eq!(network_state.peer_to_current_slot().len(), 0);
    }

    #[test]
    // Nominate/Prepare/Commit(slot_index = 5) implies that slot_index 4 was
    // externalized.
    fn test_push_nominate_prepare_commit() {
        let sender_id = test_node_id(11).responder_id;
        let quorum_set = QuorumSet::<ResponderId>::empty();

        let local_node_id = test_node_id(1);
        let local_node_quorum_set = QuorumSet::<ResponderId>::empty();
        let mut network_state =
            SCPNetworkState::<ResponderId>::new(local_node_id.responder_id, local_node_quorum_set);

        let slot_index: SlotIndex = 5;

        // Nominate
        {
            let voted: BTreeSet<&str> = vec!["foo"].into_iter().collect();
            let accepted: BTreeSet<&str> = vec!["bar"].into_iter().collect();
            network_state.push(Msg::new(
                sender_id.clone(),
                quorum_set.clone(),
                slot_index,
                Topic::Nominate(NominatePayload {
                    X: voted,
                    Y: accepted,
                }),
            ));
            assert_eq!(network_state.peer_to_current_slot().len(), 1);
            assert_eq!(
                *network_state.id_to_current_slot.get(&sender_id).unwrap(),
                4 as SlotIndex
            );
        }

        // Prepare
        {
            network_state.push(Msg::new(
                sender_id.clone(),
                quorum_set.clone(),
                slot_index,
                Topic::Prepare(PreparePayload {
                    B: Ballot::new(1, &["bleh"]),
                    P: None,
                    PP: None,
                    HN: 0,
                    CN: 0,
                }),
            ));
            assert_eq!(network_state.peer_to_current_slot().len(), 1);
            assert_eq!(
                *network_state.id_to_current_slot.get(&sender_id).unwrap(),
                4 as SlotIndex
            );
        }

        // Commit
        {
            network_state.push(Msg::new(
                sender_id.clone(),
                quorum_set,
                slot_index,
                Topic::Commit(CommitPayload {
                    B: Ballot::new(1, &["bleh"]),
                    PN: 0,
                    HN: 0,
                    CN: 0,
                }),
            ));
            assert_eq!(network_state.peer_to_current_slot().len(), 1);
            assert_eq!(
                *network_state.id_to_current_slot.get(&sender_id).unwrap(),
                4 as SlotIndex
            );
        }
    }

    #[test]
    // Externalize(slot_index = 5) implies that slot_index 5 was externalized.
    fn test_push_externalize() {
        let sender_id = test_node_id(11).responder_id;
        let quorum_set = QuorumSet::<ResponderId>::empty();

        let local_node_id = test_node_id(1);
        let local_node_quorum_set = QuorumSet::<ResponderId>::empty();
        let mut network_state =
            SCPNetworkState::<ResponderId>::new(local_node_id.responder_id, local_node_quorum_set);

        let slot_index: SlotIndex = 5;
        // ExternalizeStatement
        {
            network_state.push(Msg::new(
                sender_id.clone(),
                quorum_set,
                slot_index,
                Topic::Externalize(ExternalizePayload {
                    C: Ballot::new(1, &["bleh"]),
                    HN: 0,
                }),
            ));
            assert_eq!(network_state.peer_to_current_slot().len(), 1);
            assert_eq!(
                *network_state.id_to_current_slot.get(&sender_id).unwrap(),
                5 as SlotIndex
            );
        }
    }

    #[test]
    // Out-of-order (stale) messages should not change the NetworkState.
    fn test_push_out_of_order_statement() {
        // Initially, the NetworkState knows that node 11 has externalized slot 8.
        let local_node_id = test_node_id(1);
        let local_node_quorum_set = QuorumSet::<ResponderId>::empty();
        let mut network_state =
            SCPNetworkState::<ResponderId>::new(local_node_id.responder_id, local_node_quorum_set);

        let sender_id = test_node_id(11).responder_id;
        network_state
            .id_to_current_slot
            .insert(sender_id.clone(), 8);

        // Push a "stale" Externalize message for slot 5.
        {
            let quorum_set = QuorumSet::<ResponderId>::empty();
            let slot_index: SlotIndex = 5;

            network_state.push(Msg::new(
                sender_id.clone(),
                quorum_set,
                slot_index,
                Topic::Externalize(ExternalizePayload {
                    C: Ballot::new(1, &["bleh"]),
                    HN: 0,
                }),
            ));
        }

        // NetworkState should still think that node 11 has externalized slot 8.
        assert_eq!(network_state.peer_to_current_slot().len(), 1);
        assert_eq!(
            *network_state.id_to_current_slot.get(&sender_id).unwrap(),
            8 as SlotIndex
        );
    }

    #[test]
    // NetworkState should correctly track the state of multiple senders.
    fn test_multiple_senders() {
        let local_node_id = test_node_id(1);
        let local_node_quorum_set = QuorumSet::<ResponderId>::empty();
        let mut network_state =
            SCPNetworkState::<ResponderId>::new(local_node_id.responder_id, local_node_quorum_set);

        let sender_a_id = test_node_id(11).responder_id;
        let sender_b_id = test_node_id(22).responder_id;

        let quorum_set = QuorumSet::<ResponderId>::empty();

        // A Prepare message from sender A.
        let slot_index: SlotIndex = 5;
        network_state.push(Msg::new(
            sender_a_id.clone(),
            quorum_set.clone(),
            slot_index,
            Topic::Prepare(PreparePayload {
                B: Ballot::new(1, &["bleh"]),
                P: None,
                PP: None,
                HN: 0,
                CN: 0,
            }),
        ));
        assert_eq!(network_state.peer_to_current_slot().len(), 1);
        assert_eq!(
            *network_state.id_to_current_slot.get(&sender_a_id).unwrap(),
            4 as SlotIndex
        );

        // A Commit from sender B.
        let slot_index: SlotIndex = 6;
        network_state.push(Msg::new(
            sender_b_id.clone(),
            quorum_set,
            slot_index,
            Topic::Commit(CommitPayload {
                B: Ballot::new(1, &["bleh"]),
                PN: 0,
                HN: 0,
                CN: 0,
            }),
        ));

        // There should now be values for both nodes.
        assert_eq!(network_state.peer_to_current_slot().len(), 2);

        assert_eq!(
            *network_state.id_to_current_slot.get(&sender_b_id).unwrap(),
            5 as SlotIndex
        );
    }

    #[test]
    // NetworkState is_behind should only return true when `responder_ids` form
    // both a blocking set and a quorum.
    fn test_is_behind() {
        let local_node_quorum_set: QuorumSet = {
            let inner_quorum_set_one: QuorumSet = QuorumSet::new_with_node_ids(
                2,
                vec![test_node_id(2), test_node_id(3), test_node_id(4)],
            );
            let inner_quorum_set_two: QuorumSet = QuorumSet::new_with_node_ids(
                2,
                vec![test_node_id(5), test_node_id(6), test_node_id(7)],
            );
            QuorumSet::new_with_inner_sets(2, vec![inner_quorum_set_one, inner_quorum_set_two])
        };
        let local_node_id = test_node_id(1);
        let mut network_state = SCPNetworkState::new(local_node_id, local_node_quorum_set);
        let local_block = 5;

        // Nodes 2 and 3 are a blocking set.
        let node_2_id = test_node_id(2);
        let node_2_quorum_set =
            QuorumSet::new_with_node_ids(1, vec![test_node_id(3), test_node_id(4)]);

        let node_3_id = test_node_id(3);
        let node_3_quorum_set =
            QuorumSet::new_with_node_ids(1, vec![test_node_id(2), test_node_id(4)]);

        let node_5_id = test_node_id(5);
        let node_5_quorum_set =
            QuorumSet::new_with_node_ids(1, vec![test_node_id(6), test_node_id(7)]);

        let node_6_id = test_node_id(6);
        let node_6_quorum_set =
            QuorumSet::new_with_node_ids(1, vec![test_node_id(5), test_node_id(7)]);

        // Initially, we are not behind.
        assert_eq!(network_state.is_behind(local_block), false);

        // Send a message from node 2. Nothing should change.
        network_state.push(Msg::<&str>::new(
            node_2_id,
            node_2_quorum_set,
            local_block + 1,
            Topic::Externalize(ExternalizePayload {
                C: Ballot::new(1, &["bleh"]),
                HN: 0,
            }),
        ));
        assert_eq!(network_state.is_behind(local_block), false);

        // Send a message from node 3, so we have a blocking set but no quorum.
        network_state.push(Msg::<&str>::new(
            node_3_id,
            node_3_quorum_set,
            local_block + 1,
            Topic::Externalize(ExternalizePayload {
                C: Ballot::new(1, &["bleh"]),
                HN: 0,
            }),
        ));
        assert_eq!(network_state.is_behind(local_block), false);

        // Send a message from node 5, not forming quorum.
        network_state.push(Msg::<&str>::new(
            node_5_id,
            node_5_quorum_set,
            local_block + 1,
            Topic::Externalize(ExternalizePayload {
                C: Ballot::new(1, &["bleh"]),
                HN: 0,
            }),
        ));
        assert_eq!(network_state.is_behind(local_block), false);

        // Send a message from node 6, we now have a blocking set and quorum.
        network_state.push(Msg::<&str>::new(
            node_6_id,
            node_6_quorum_set,
            local_block + 1,
            Topic::Externalize(ExternalizePayload {
                C: Ballot::new(1, &["bleh"]),
                HN: 0,
            }),
        ));
        assert_eq!(network_state.is_behind(local_block), true);
    }

    // A quorum set with a single node is blocking and quorum when that node has
    // issued a message.
    #[test]
    fn test_single_node_quorum_set_is_blocking_and_quorum() {
        let local_node_id = test_node_id(1);
        let local_node_quorum_set: QuorumSet =
            QuorumSet::new_with_node_ids(1, vec![test_node_id(2)]);
        let network_state = SCPNetworkState::new(local_node_id, local_node_quorum_set);

        assert_eq!(
            network_state
                .is_blocking_and_quorum(&HashSet::from_iter(vec![test_node_id(0).responder_id])),
            false,
        );

        assert_eq!(
            network_state
                .is_blocking_and_quorum(&HashSet::from_iter(vec![test_node_id(1).responder_id])),
            false,
        );

        assert_eq!(
            network_state
                .is_blocking_and_quorum(&HashSet::from_iter(vec![test_node_id(2).responder_id])),
            true
        );

        assert_eq!(
            network_state.is_blocking_and_quorum(&HashSet::from_iter(vec![
                test_node_id(0).responder_id,
                test_node_id(2).responder_id
            ])),
            true
        );
    }

    #[test]
    // NetworkState highest_block_index_on_network should only return the highest
    // block index a blocking set and quorum agrees on.
    fn test_highest_block_index_on_network() {
        let local_node_quorum_set: QuorumSet = {
            let inner_quorum_set_one: QuorumSet = QuorumSet::new_with_node_ids(
                2,
                vec![test_node_id(2), test_node_id(3), test_node_id(4)],
            );
            let inner_quorum_set_two: QuorumSet = QuorumSet::new_with_node_ids(
                2,
                vec![test_node_id(5), test_node_id(6), test_node_id(7)],
            );
            QuorumSet::new_with_inner_sets(2, vec![inner_quorum_set_one, inner_quorum_set_two])
        };
        let local_node_id = test_node_id(1);
        let mut network_state = SCPNetworkState::new(local_node_id, local_node_quorum_set);
        let local_block = 5;

        // Nodes 2 and 3 are a blocking set.
        let node_2_id = test_node_id(2);
        let node_2_quorum_set =
            QuorumSet::new_with_node_ids(1, vec![test_node_id(3), test_node_id(4)]);

        let node_3_id = test_node_id(3);
        let node_3_quorum_set =
            QuorumSet::new_with_node_ids(1, vec![test_node_id(2), test_node_id(4)]);

        let node_5_id = test_node_id(5);
        let node_5_quorum_set =
            QuorumSet::new_with_node_ids(1, vec![test_node_id(6), test_node_id(7)]);

        let node_6_id = test_node_id(6);
        let node_6_quorum_set =
            QuorumSet::new_with_node_ids(1, vec![test_node_id(5), test_node_id(7)]);

        // No messages issued so far, so we don't know where the network is.
        assert_eq!(network_state.highest_block_index_on_network(), None);

        // Send a message from node 2. Nothing should change.
        network_state.push(Msg::<&str>::new(
            node_2_id.clone(),
            node_2_quorum_set.clone(),
            local_block + 5,
            Topic::Externalize(ExternalizePayload {
                C: Ballot::new(1, &["bleh"]),
                HN: 0,
            }),
        ));
        assert_eq!(network_state.highest_block_index_on_network(), None);

        // Send a message from node 3, so we have a blocking set but no quorum.
        network_state.push(Msg::<&str>::new(
            node_3_id.clone(),
            node_3_quorum_set.clone(),
            local_block + 5,
            Topic::Externalize(ExternalizePayload {
                C: Ballot::new(1, &["bleh"]),
                HN: 0,
            }),
        ));
        assert_eq!(network_state.highest_block_index_on_network(), None);

        // Send a message from node 5, not forming quorum.
        network_state.push(Msg::<&str>::new(
            node_5_id.clone(),
            node_5_quorum_set.clone(),
            local_block + 5,
            Topic::Externalize(ExternalizePayload {
                C: Ballot::new(1, &["bleh"]),
                HN: 0,
            }),
        ));
        assert_eq!(network_state.highest_block_index_on_network(), None);

        // Send a message from node 6, we now have a blocking set and quorum agreeing on
        // block `local_block + 5` (even though node 6 is on block +10, the rest of the
        // network is on block +5).
        network_state.push(Msg::<&str>::new(
            node_6_id.clone(),
            node_6_quorum_set.clone(),
            local_block + 10,
            Topic::Externalize(ExternalizePayload {
                C: Ballot::new(1, &["bleh"]),
                HN: 0,
            }),
        ));
        assert_eq!(
            network_state.highest_block_index_on_network(),
            Some(local_block + 5)
        );

        // Node 2 and 3 advance to local_block+12 - the network continues to agree on
        // local_block + 5.
        network_state.push(Msg::<&str>::new(
            node_2_id,
            node_2_quorum_set,
            local_block + 12,
            Topic::Externalize(ExternalizePayload {
                C: Ballot::new(1, &["bleh"]),
                HN: 0,
            }),
        ));

        network_state.push(Msg::<&str>::new(
            node_3_id,
            node_3_quorum_set,
            local_block + 12,
            Topic::Externalize(ExternalizePayload {
                C: Ballot::new(1, &["bleh"]),
                HN: 0,
            }),
        ));
        assert_eq!(
            network_state.highest_block_index_on_network(),
            Some(local_block + 5)
        );

        // Node 5 moves to block local_block + 10, the network agrees on block
        // local_block+10 (since node 6 is on local_block + 10).
        network_state.push(Msg::<&str>::new(
            node_5_id,
            node_5_quorum_set,
            local_block + 12,
            Topic::Externalize(ExternalizePayload {
                C: Ballot::new(1, &["bleh"]),
                HN: 0,
            }),
        ));
        assert_eq!(
            network_state.highest_block_index_on_network(),
            Some(local_block + 10)
        );

        // Node 6 moves to block local_block + 12, the network agrees on local_block +
        // 12 as all nodes have reported that.
        network_state.push(Msg::<&str>::new(
            node_6_id,
            node_6_quorum_set,
            local_block + 12,
            Topic::Externalize(ExternalizePayload {
                C: Ballot::new(1, &["bleh"]),
                HN: 0,
            }),
        ));
        assert_eq!(
            network_state.highest_block_index_on_network(),
            Some(local_block + 12)
        );
    }
}
