// Copyright (c) 2018-2022 The MobileCoin Foundation

//! [QuorumSet] helpers.

use crate::{msg::Msg, predicates::Predicate, GenericNodeId, QuorumSet, QuorumSetMember, Value};
use mc_common::{HashMap, HashSet};

/// Helper extension for [QuorumSet].
pub trait QuorumSetExt<ID: GenericNodeId> {
    /// Gives the fraction of quorum slices containing the given node.
    /// It assumes that id appears in at most one QuorumSet
    /// (either the top level one or a single reachable nested one)
    /// and then only once in that QuorumSet.
    ///
    /// # Returns
    /// * (numerator, denominator) representing the node's weight.
    fn weight(&self, node_id: &ID) -> (u32, u32);

    /// Attempts to find a blocking set matching a given predicate `predicate`.
    ///
    /// # Arguments
    /// * `msgs` - A map of ID -> Msg holding the newest message received from
    ///   each node.
    /// * `pred` - Predicate to apply to the messages.
    ///
    /// # Returns
    /// * (Set of nodes forming a bocking set and matching the predicate, the
    ///   predicate). The set of nodes would be empty if no blocking set
    ///   matching the predicate was found.
    fn findBlockingSet<V: Value, P: Predicate<V, ID>>(
        &self,
        msgs: &HashMap<ID, Msg<V, ID>>,
        pred: P,
    ) -> (HashSet<ID>, P);

    /// Attempts to find a quorum matching a given predicate `predicate`.
    ///
    /// # Arguments
    /// * `node_id` - The local node ID.
    /// * `msgs` - A map of ID -> Msg holding the newest message received from
    ///   each node.
    /// * `pred` - Predicate to apply to the messages.
    ///
    /// # Returns
    /// * (Set of nodes forming a quorum and matching the predicate, the
    ///   predicate). The set of nodes would be empty if no quorum matching the
    ///   predicate was found.
    fn findQuorum<V: Value, P: Predicate<V, ID>>(
        &self,
        node_id: &ID,
        msgs: &HashMap<ID, Msg<V, ID>>,
        pred: P,
    ) -> (HashSet<ID>, P);
}

impl<ID: GenericNodeId> QuorumSetExt<ID> for QuorumSet<ID> {
    fn weight(&self, node_id: &ID) -> (u32, u32) {
        for m in self.members.iter() {
            match m {
                QuorumSetMember::Node(id) => {
                    if id == node_id {
                        return (self.threshold, self.members.len() as u32);
                    }
                }
                QuorumSetMember::InnerSet(Q) => {
                    let (num2, denom2) = Q.weight(node_id);
                    if num2 > 0 {
                        return (self.threshold * num2, self.members.len() as u32 * denom2);
                    }
                }
            }
        }

        (0, 1)
    }

    fn findBlockingSet<V: Value, P: Predicate<V, ID>>(
        &self,
        msgs: &HashMap<ID, Msg<V, ID>>,
        pred: P,
    ) -> (HashSet<ID>, P) {
        findBlockingSetHelper(
            self.members.len() as u32 - self.threshold + 1,
            &self.members,
            msgs,
            pred,
            HashSet::default(),
        )
    }

    fn findQuorum<V: Value, P: Predicate<V, ID>>(
        &self,
        node_id: &ID,
        msgs: &HashMap<ID, Msg<V, ID>>,
        pred: P,
    ) -> (HashSet<ID>, P) {
        findQuorumHelper(
            self.threshold,
            &self.members,
            msgs,
            pred,
            HashSet::from_iter([node_id.clone()]),
        )
    }
}

/// Internal helper method, implementing the logic for finding a quorum.
///
/// # Arguments
/// * `threshold` - How many more nodes do we need to reach a quorum.
/// * `members` - Array of quorum set members we are considering as potential
///   quorum members.
/// * `msgs` - A map of ID -> Msg holding the newest message received from each
///   node.
/// * `pred` - Predicate to apply to the messages.
/// * `node_so_far` - Nodes we have collected so far in our quest for finding a
///   quorum.
fn findQuorumHelper<ID: GenericNodeId, V: Value, P: Predicate<V, ID>>(
    threshold: u32,
    members: &[QuorumSetMember<ID>],
    msgs: &HashMap<ID, Msg<V, ID>>,
    pred: P,
    nodes_so_far: HashSet<ID>,
) -> (HashSet<ID>, P) {
    // If we don't need any more nodes, we're done.
    if threshold == 0 {
        return (nodes_so_far, pred);
    }

    // If we need more nodes/sets than we have, we will never find a match.
    if threshold as usize > members.len() {
        return (HashSet::default(), pred);
    }

    // See if the first member of our potential nodes/sets allows us to reach
    // quorum.
    match &members[0] {
        QuorumSetMember::Node(N) => {
            // If we already seen this node and it got added to the list of potential
            // quorum-forming nodes, we need one less node to reach quorum.
            if nodes_so_far.contains(N) {
                return findQuorumHelper(threshold - 1, &members[1..], msgs, pred, nodes_so_far);
            }

            // If we have received a message from node N
            if let Some(msg) = msgs.get(N) {
                // and if the predicate accepts it
                if let Some(nextPred) = pred.test(msg) {
                    // then add this node into the list of potentoal quorum-forming nodes, and
                    // see if we can find a quorum that satisfies its validators.
                    let mut nodes_so_far_with_N = nodes_so_far.clone();
                    nodes_so_far_with_N.insert(N.clone());

                    let (nodes_so_far2, pred2) = findQuorumHelper(
                        msg.quorum_set.threshold,
                        &msg.quorum_set.members,
                        msgs,
                        nextPred,
                        nodes_so_far_with_N,
                    );
                    if !nodes_so_far2.is_empty() {
                        // We can find a quorum for the node's validators, so consider it a
                        // good potential fit and keep searching for `threshold - 1` nodes.
                        return findQuorumHelper(
                            threshold - 1,
                            &members[1..],
                            msgs,
                            pred2,
                            nodes_so_far2,
                        );
                    }
                }
            }
        }
        QuorumSetMember::InnerSet(Q) => {
            // See if we can find quorum for the inner set.
            let (nodes_so_far2, pred2) = findQuorumHelper(
                Q.threshold,
                &Q.members,
                msgs,
                pred.clone(),
                nodes_so_far.clone(),
            );
            if !nodes_so_far2.is_empty() {
                // We found a quorum for the inner set, we need 1 validator less.
                return findQuorumHelper(threshold - 1, &members[1..], msgs, pred2, nodes_so_far2);
            }
        }
    }

    // First member didn't get us to a quorum, move to the next member and try
    // again.
    findQuorumHelper(threshold, &members[1..], msgs, pred, nodes_so_far)
}

/// Internal helper method, implementing the logic for finding a blocking
/// set.
///
/// # Arguments
/// * `needed` - How many more nodes do we need to reach a blocking set.
/// * `members` - Array of quorum set members we are considering as potential
///   blocking set members.
/// * `msgs` - A map of ID -> Msg holding the newest message received from each
///   node.
/// * `pred` - Predicate to apply to the messages.
/// * `node_so_far` - Nodes we have collected so far in our quest for finding a
///   blocking set.
fn findBlockingSetHelper<ID: GenericNodeId, V: Value, P: Predicate<V, ID>>(
    needed: u32,
    members: &[QuorumSetMember<ID>],
    msgs: &HashMap<ID, Msg<V, ID>>,
    pred: P,
    nodes_so_far: HashSet<ID>,
) -> (HashSet<ID>, P) {
    // If we don't need any more nodes, we're done.
    if needed == 0 {
        return (nodes_so_far, pred);
    }

    // If we need more nodes/sets than we have, we will never find a match.
    if needed as usize > members.len() {
        return (HashSet::default(), pred);
    }

    // See if the first member of our potential nodes/sets allows us to reach a
    // blocking threshold.
    match &members[0] {
        QuorumSetMember::Node(N) => {
            // If we have received a message from this member
            if let Some(msg) = msgs.get(N) {
                // and the predicate accepts it
                if let Some(nextPred) = pred.test(msg) {
                    // then add this node to the list of potential matches, and continue
                    // searching.
                    let mut nodes_so_far2 = nodes_so_far;
                    nodes_so_far2.insert(N.clone());
                    return findBlockingSetHelper(
                        needed - 1,
                        &members[1..],
                        msgs,
                        nextPred,
                        nodes_so_far2,
                    );
                }
            }
        }

        QuorumSetMember::InnerSet(Q) => {
            let (nodes_so_far2, pred2) = findBlockingSetHelper(
                // "A message reaches blocking threshold at "v" when the number of
                //  "validators" making the statement plus (recursively) the number
                // "innerSets" reaching blocking threshold exceeds "n-k"."a
                // p.9 of the [IETF draft](https://tools.ietf.org/pdf/draft-mazieres-dinrg-scp-04.pdf).
                Q.members.len() as u32 - Q.threshold + 1,
                &Q.members,
                msgs,
                pred.clone(),
                nodes_so_far.clone(),
            );
            if !nodes_so_far2.is_empty() {
                return findBlockingSetHelper(
                    needed - 1,
                    &members[1..],
                    msgs,
                    pred2,
                    nodes_so_far2,
                );
            }
        }
    }

    // First member didn't get us to a blocking set, move to the next member and try
    // again.
    findBlockingSetHelper(needed, &members[1..], msgs, pred, nodes_so_far)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ballot::Ballot,
        msg::{PreparePayload, Topic},
        predicates::FuncPredicate,
        test_utils::test_node_id,
    };
    use mc_common::{NodeID, ResponderId};

    #[test]
    // findBlockingSet returns an empty set when there is no blocking set
    fn test_no_blocking_set() {
        // Node 2 and 3 form a blocking set
        let local_node_quorum_set: QuorumSet = {
            let inner_quorum_set_one = QuorumSet::new_with_node_ids(
                2,
                vec![test_node_id(2), test_node_id(3), test_node_id(4)],
            );
            let inner_quorum_set_two = QuorumSet::new_with_node_ids(
                2,
                vec![test_node_id(5), test_node_id(6), test_node_id(7)],
            );
            QuorumSet::new_with_inner_sets(2, vec![inner_quorum_set_one, inner_quorum_set_two])
        };

        let node_2_quorum_set =
            QuorumSet::new_with_node_ids(1, vec![test_node_id(3), test_node_id(4)]);
        let node_5_quorum_set =
            QuorumSet::new_with_node_ids(1, vec![test_node_id(6), test_node_id(7)]);

        let topic = Topic::Prepare(PreparePayload::<u32> {
            B: Ballot::new(1, &[1234, 5678]),
            P: None,
            PP: None,
            CN: 0,
            HN: 0,
        });

        let mut msgs = HashMap::<NodeID, Msg<u32>>::default();
        msgs.insert(
            test_node_id(2),
            Msg::new(test_node_id(2), node_2_quorum_set, 1, topic.clone()),
        );
        msgs.insert(
            test_node_id(5),
            Msg::new(test_node_id(5), node_5_quorum_set, 1, topic),
        );
        let (node_ids, _) = local_node_quorum_set.findBlockingSet(
            &msgs,
            FuncPredicate {
                test_fn: &|_msg| true,
            },
        );
        assert_eq!(node_ids.len(), 0);
    }

    #[test]
    // findBlockingSet returns the correct set of nodes when there is a blocking set
    fn test_has_blocking_set() {
        // Node 2 and 3 form a blocking set
        let local_node_quorum_set: QuorumSet = {
            let inner_quorum_set_one = QuorumSet::new_with_node_ids(
                2,
                vec![test_node_id(2), test_node_id(3), test_node_id(4)],
            );
            let inner_quorum_set_two = QuorumSet::new_with_node_ids(
                2,
                vec![test_node_id(5), test_node_id(6), test_node_id(7)],
            );
            QuorumSet::new_with_inner_sets(2, vec![inner_quorum_set_one, inner_quorum_set_two])
        };

        let node_2_quorum_set =
            QuorumSet::new_with_node_ids(1, vec![test_node_id(3), test_node_id(4)]);
        let node_3_quorum_set =
            QuorumSet::new_with_node_ids(1, vec![test_node_id(2), test_node_id(4)]);

        let topic = Topic::Prepare(PreparePayload::<u32> {
            B: Ballot::new(1, &[1234, 5678]),
            P: None,
            PP: None,
            CN: 0,
            HN: 0,
        });

        let mut msgs = HashMap::<NodeID, Msg<u32>>::default();
        msgs.insert(
            test_node_id(2),
            Msg::new(test_node_id(2), node_2_quorum_set, 1, topic.clone()),
        );
        msgs.insert(
            test_node_id(3),
            Msg::new(test_node_id(3), node_3_quorum_set, 1, topic),
        );

        let (node_ids, _) = local_node_quorum_set.findBlockingSet(
            &msgs,
            FuncPredicate {
                test_fn: &|_msg| true,
            },
        );
        assert_eq!(
            node_ids,
            HashSet::from_iter([test_node_id(2), test_node_id(3)])
        );
    }

    #[test]
    // findBlockingSet returns an empty set if the predicate returns false for the
    // blocking set
    fn test_blocking_set_with_false_predicate() {
        // Node 2 and 3 form a blocking set
        let local_node_quorum_set: QuorumSet = {
            let inner_quorum_set_one = QuorumSet::new_with_node_ids(
                2,
                vec![test_node_id(2), test_node_id(3), test_node_id(4)],
            );
            let inner_quorum_set_two = QuorumSet::new_with_node_ids(
                2,
                vec![test_node_id(5), test_node_id(6), test_node_id(7)],
            );
            QuorumSet::new_with_inner_sets(2, vec![inner_quorum_set_one, inner_quorum_set_two])
        };

        let node_2_quorum_set =
            QuorumSet::new_with_node_ids(1, vec![test_node_id(3), test_node_id(4)]);
        let node_3_quorum_set =
            QuorumSet::new_with_node_ids(1, vec![test_node_id(2), test_node_id(4)]);

        let topic = Topic::Prepare(PreparePayload::<u32> {
            B: Ballot::new(1, &[1234, 5678]),
            P: None,
            PP: None,
            CN: 0,
            HN: 0,
        });

        let mut msgs = HashMap::<NodeID, Msg<u32>>::default();
        msgs.insert(
            test_node_id(2),
            Msg::new(test_node_id(2), node_2_quorum_set, 1, topic.clone()),
        );
        msgs.insert(
            test_node_id(3),
            Msg::new(test_node_id(3), node_3_quorum_set, 1, topic),
        );

        let (node_ids, _) = local_node_quorum_set.findBlockingSet(
            &msgs,
            FuncPredicate {
                test_fn: &|msg| msg.sender_id == test_node_id(2),
            },
        );
        assert_eq!(node_ids.len(), 0);
    }

    #[test]
    // findQuorum returns an empty set when there is no quorum
    fn test_no_quorum() {
        // Node 2 and 3 form a blocking set. Node 2, 3, 5, 6 form a quorum.
        let local_node_quorum_set: QuorumSet = {
            let inner_quorum_set_one = QuorumSet::new_with_node_ids(
                2,
                vec![test_node_id(2), test_node_id(3), test_node_id(4)],
            );
            let inner_quorum_set_two = QuorumSet::new_with_node_ids(
                2,
                vec![test_node_id(5), test_node_id(6), test_node_id(7)],
            );
            QuorumSet::new_with_inner_sets(2, vec![inner_quorum_set_one, inner_quorum_set_two])
        };
        let local_node_id = test_node_id(1);

        let node_2_quorum_set =
            QuorumSet::new_with_node_ids(1, vec![test_node_id(3), test_node_id(4)]);
        let node_3_quorum_set =
            QuorumSet::new_with_node_ids(1, vec![test_node_id(2), test_node_id(4)]);

        let topic = Topic::Prepare(PreparePayload::<u32> {
            B: Ballot::new(1, &[1234, 5678]),
            P: None,
            PP: None,
            CN: 0,
            HN: 0,
        });

        let mut msgs = HashMap::<NodeID, Msg<u32>>::default();
        msgs.insert(
            test_node_id(2),
            Msg::new(test_node_id(2), node_2_quorum_set, 1, topic.clone()),
        );
        msgs.insert(
            test_node_id(3),
            Msg::new(test_node_id(3), node_3_quorum_set, 1, topic),
        );

        let (node_ids, _) = local_node_quorum_set.findQuorum(
            &local_node_id,
            &msgs,
            FuncPredicate {
                test_fn: &|_msg| true,
            },
        );
        assert_eq!(node_ids, HashSet::from_iter([]));
    }

    #[test]
    // findQuorum returns the correct set of nodes when there is a quorum
    fn test_has_quorum() {
        // Node 2 and 3 form a blocking set. Node 2, 3, 5, 6 form a quorum.
        let local_node_quorum_set: QuorumSet = {
            let inner_quorum_set_one = QuorumSet::new_with_node_ids(
                2,
                vec![test_node_id(2), test_node_id(3), test_node_id(4)],
            );
            let inner_quorum_set_two = QuorumSet::new_with_node_ids(
                2,
                vec![test_node_id(5), test_node_id(6), test_node_id(7)],
            );
            QuorumSet::new_with_inner_sets(2, vec![inner_quorum_set_one, inner_quorum_set_two])
        };
        let local_node_id = test_node_id(1);

        let node_2_quorum_set =
            QuorumSet::new_with_node_ids(1, vec![test_node_id(3), test_node_id(4)]);
        let node_3_quorum_set =
            QuorumSet::new_with_node_ids(1, vec![test_node_id(2), test_node_id(4)]);
        let node_5_quorum_set =
            QuorumSet::new_with_node_ids(1, vec![test_node_id(6), test_node_id(7)]);
        let node_6_quorum_set =
            QuorumSet::new_with_node_ids(1, vec![test_node_id(5), test_node_id(7)]);

        let topic = Topic::Prepare(PreparePayload::<u32> {
            B: Ballot::new(1, &[1234, 5678]),
            P: None,
            PP: None,
            CN: 0,
            HN: 0,
        });

        let mut msgs = HashMap::<NodeID, Msg<u32>>::default();
        msgs.insert(
            test_node_id(2),
            Msg::new(test_node_id(2), node_2_quorum_set, 1, topic.clone()),
        );
        msgs.insert(
            test_node_id(3),
            Msg::new(test_node_id(3), node_3_quorum_set, 1, topic.clone()),
        );
        msgs.insert(
            test_node_id(5),
            Msg::new(test_node_id(5), node_5_quorum_set, 1, topic.clone()),
        );
        msgs.insert(
            test_node_id(6),
            Msg::new(test_node_id(6), node_6_quorum_set, 1, topic),
        );

        let (node_ids, _) = local_node_quorum_set.findQuorum(
            &local_node_id,
            &msgs,
            FuncPredicate {
                test_fn: &|_msg| true,
            },
        );
        assert_eq!(
            node_ids,
            HashSet::from_iter([
                test_node_id(2),
                test_node_id(3),
                test_node_id(5),
                test_node_id(6),
                test_node_id(1)
            ])
        );
    }

    #[test]
    // findQuorum returns an empty set when there is a quorum but the predicate
    // returns false
    fn test_has_quorum_with_false_predicate() {
        // Node 2 and 3 form a blocking set. Node 2, 3, 5, 6 form a quorum.
        let local_node_quorum_set: QuorumSet = {
            let inner_quorum_set_one = QuorumSet::new_with_node_ids(
                2,
                vec![test_node_id(2), test_node_id(3), test_node_id(4)],
            );
            let inner_quorum_set_two = QuorumSet::new_with_node_ids(
                2,
                vec![test_node_id(5), test_node_id(6), test_node_id(7)],
            );
            QuorumSet::new_with_inner_sets(2, vec![inner_quorum_set_one, inner_quorum_set_two])
        };
        let local_node_id = test_node_id(1);

        let node_2_quorum_set =
            QuorumSet::new_with_node_ids(1, vec![test_node_id(3), test_node_id(4)]);
        let node_3_quorum_set =
            QuorumSet::new_with_node_ids(1, vec![test_node_id(2), test_node_id(4)]);
        let node_5_quorum_set =
            QuorumSet::new_with_node_ids(1, vec![test_node_id(6), test_node_id(7)]);
        let node_6_quorum_set =
            QuorumSet::new_with_node_ids(1, vec![test_node_id(5), test_node_id(7)]);

        let topic = Topic::Prepare(PreparePayload::<u32> {
            B: Ballot::new(1, &[1234, 5678]),
            P: None,
            PP: None,
            CN: 0,
            HN: 0,
        });

        let mut msgs = HashMap::<NodeID, Msg<u32>>::default();
        msgs.insert(
            test_node_id(2),
            Msg::new(test_node_id(2), node_2_quorum_set, 1, topic.clone()),
        );
        msgs.insert(
            test_node_id(3),
            Msg::new(test_node_id(3), node_3_quorum_set, 1, topic.clone()),
        );
        msgs.insert(
            test_node_id(5),
            Msg::new(test_node_id(5), node_5_quorum_set, 1, topic.clone()),
        );
        msgs.insert(
            test_node_id(6),
            Msg::new(test_node_id(6), node_6_quorum_set, 1, topic),
        );

        let (node_ids, _) = local_node_quorum_set.findQuorum(
            &local_node_id,
            &msgs,
            FuncPredicate {
                test_fn: &|msg| msg.sender_id != test_node_id(2),
            },
        );
        assert_eq!(node_ids, HashSet::from_iter([]));
    }

    #[test]
    // Quorum set can be constructed with ResponderId
    fn test_blocking_set_with_responder_id() {
        // Quorum set by ResponderId, as employed by e.g. mobilecoind
        let mobilecoind_quorum_set: QuorumSet<ResponderId> = {
            let inner_quorum_set_one: QuorumSet<ResponderId> = QuorumSet::new_with_node_ids(
                2,
                vec![
                    test_node_id(2).responder_id,
                    test_node_id(3).responder_id,
                    test_node_id(4).responder_id,
                ],
            );
            let inner_quorum_set_two: QuorumSet<ResponderId> = QuorumSet::new_with_node_ids(
                2,
                vec![
                    test_node_id(5).responder_id,
                    test_node_id(6).responder_id,
                    test_node_id(7).responder_id,
                ],
            );
            QuorumSet::new_with_inner_sets(2, vec![inner_quorum_set_one, inner_quorum_set_two])
        };

        let topic = Topic::Prepare(PreparePayload::<u32> {
            B: Ballot::new(1, &[1234, 5678]),
            P: None,
            PP: None,
            CN: 0,
            HN: 0,
        });

        // Mimic polling_network_state.scp_network_state::push(Msg)
        let mut msgs = HashMap::<ResponderId, Msg<u32, ResponderId>>::default();
        msgs.insert(
            test_node_id(2).responder_id,
            Msg::new(
                test_node_id(2).responder_id,
                QuorumSet::empty(),
                1,
                topic.clone(),
            ),
        );
        msgs.insert(
            test_node_id(3).responder_id,
            Msg::new(test_node_id(3).responder_id, QuorumSet::empty(), 1, topic),
        );

        let responder_ids: HashSet<ResponderId> = HashSet::from_iter([
            test_node_id(2).responder_id,
            test_node_id(3).responder_id,
            test_node_id(4).responder_id,
            test_node_id(5).responder_id,
            test_node_id(6).responder_id,
            test_node_id(7).responder_id,
        ]);

        let fp = FuncPredicate {
            test_fn: &|msg: &Msg<u32, ResponderId>| responder_ids.contains(&msg.sender_id),
        };

        let (node_ids, _) = mobilecoind_quorum_set.findBlockingSet(&msgs, fp);
        assert_eq!(
            node_ids,
            HashSet::from_iter([test_node_id(2).responder_id, test_node_id(3).responder_id])
        );
    }
}
