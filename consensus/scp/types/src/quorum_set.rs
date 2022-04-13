// Copyright (c) 2018-2022 The MobileCoin Foundation

//! The quorum set is the essential unit of trust in SCP.
//!
//! A quorum set includes the members of the network, which a given node trusts
//! and depends on.
use crate::GenericNodeId;
use alloc::{vec, vec::Vec};
use core::hash::{Hash, Hasher};
use mc_common::{HashSet, NodeID, ResponderId};
use mc_crypto_digestible::Digestible;
use serde::{Deserialize, Serialize};

/// A member in a QuorumSet. Can be either a Node or another QuorumSet.
#[derive(
    Clone, Debug, Deserialize, Digestible, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(tag = "type", content = "args")]
pub enum QuorumSetMember<ID: GenericNodeId> {
    /// A single trusted entity with an identity.
    Node(ID),

    /// A quorum set can also be a member of a quorum set.
    InnerSet(QuorumSet<ID>),
}

/// The quorum set defining the trusted set of peers.
#[derive(Clone, Debug, Deserialize, Digestible, Ord, PartialOrd, Serialize)]
pub struct QuorumSet<ID: GenericNodeId = NodeID> {
    /// Threshold (how many members do we need to reach quorum).
    pub threshold: u32,

    /// Members.
    pub members: Vec<QuorumSetMember<ID>>,
}

impl<ID: GenericNodeId> PartialEq for QuorumSet<ID> {
    fn eq(&self, other: &QuorumSet<ID>) -> bool {
        if self.threshold == other.threshold && self.members.len() == other.members.len() {
            // sort before comparing
            let mut self_clone = self.clone();
            let mut other_clone = other.clone();
            self_clone.sort();
            other_clone.sort();
            return self_clone.members == other_clone.members;
        }
        false
    }
}
impl<ID: GenericNodeId> Eq for QuorumSet<ID> {}

impl<ID: GenericNodeId> Hash for QuorumSet<ID> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // hash over a recursively sorted copy
        let mut qs_clone = self.clone();
        qs_clone.sort();
        qs_clone.threshold.hash(state);
        qs_clone.members.hash(state);
    }
}

impl<ID: GenericNodeId> QuorumSet<ID> {
    /// Create a new quorum set.
    pub fn new(threshold: u32, members: Vec<QuorumSetMember<ID>>) -> Self {
        Self { threshold, members }
    }

    /// Create a new quorum set from the given node IDs.
    pub fn new_with_node_ids(threshold: u32, node_ids: Vec<ID>) -> Self {
        Self::new(
            threshold,
            node_ids.into_iter().map(QuorumSetMember::Node).collect(),
        )
    }

    /// Create a new quorum set from the given inner sets.
    pub fn new_with_inner_sets(threshold: u32, inner_sets: Vec<Self>) -> Self {
        Self::new(
            threshold,
            inner_sets
                .into_iter()
                .map(QuorumSetMember::InnerSet)
                .collect(),
        )
    }

    /// A quorum set with no members and a threshold of 0.
    pub fn empty() -> Self {
        Self::new(0, vec![])
    }

    /// Check if a quorum set is valid.
    pub fn is_valid(&self) -> bool {
        // Must have at least `threshold` members.
        if self.threshold as usize > self.members.len() {
            return false;
        }

        // All of our inner sets must be valid.
        for member in self.members.iter() {
            if let QuorumSetMember::InnerSet(qs) = member {
                if !qs.is_valid() {
                    return false;
                }
            }
        }

        // QuorumSet is valid
        true
    }

    /// Recursively sort the QS and all inner sets
    pub fn sort(&mut self) {
        for member in self.members.iter_mut() {
            if let QuorumSetMember::InnerSet(qs) = member {
                qs.sort()
            };
        }
        // sort the members after any internal reordering!
        self.members.sort();
    }

    /// Returns a flattened set of all nodes contained in q and its nested
    /// QSets.
    pub fn nodes(&self) -> HashSet<ID> {
        let mut result = HashSet::<ID>::default();
        for member in self.members.iter() {
            match member {
                QuorumSetMember::Node(node_id) => {
                    result.insert(node_id.clone());
                }
                QuorumSetMember::InnerSet(qs) => {
                    result.extend(qs.nodes());
                }
            }
        }
        result
    }
}

impl<ID: GenericNodeId + AsRef<ResponderId>> From<&QuorumSet<ID>> for QuorumSet<ResponderId> {
    fn from(src: &QuorumSet<ID>) -> QuorumSet<ResponderId> {
        let members = src
            .members
            .iter()
            .map(|member| match member {
                QuorumSetMember::Node(node_id) => QuorumSetMember::Node(node_id.as_ref().clone()),
                QuorumSetMember::InnerSet(quorum_set) => {
                    QuorumSetMember::InnerSet(quorum_set.into())
                }
            })
            .collect();
        QuorumSet::new(src.threshold, members)
    }
}

#[cfg(test)]
mod quorum_set_tests {
    use super::*;
    use crate::test_utils::test_node_id;
    use core::hash::{BuildHasher, Hash, Hasher};
    use mc_common::HasherBuilder;

    fn assert_quorum_sets_equal(quorum_set_1: &QuorumSet, quorum_set_2: &QuorumSet) {
        assert_eq!(quorum_set_1, quorum_set_2);

        // qs1 == qs2 must imply hash(qs1) == hash(qs2)
        let hasher_builder = HasherBuilder::default();
        let quorum_set_1_hash = {
            let mut hasher = hasher_builder.build_hasher();
            quorum_set_1.hash(&mut hasher);
            hasher.finish()
        };
        let quorum_set_2_hash = {
            let mut hasher = hasher_builder.build_hasher();
            quorum_set_2.hash(&mut hasher);
            hasher.finish()
        };
        assert_eq!(quorum_set_1_hash, quorum_set_2_hash);
    }
    #[test]
    // quorum sets should sort recursively
    fn test_quorum_set_sorting() {
        let qs = QuorumSet::new(
            2,
            vec![
                QuorumSetMember::Node(test_node_id(1)),
                QuorumSetMember::InnerSet(QuorumSet::new(
                    2,
                    vec![
                        QuorumSetMember::Node(test_node_id(3)),
                        QuorumSetMember::Node(test_node_id(2)),
                        QuorumSetMember::InnerSet(QuorumSet::new_with_node_ids(
                            2,
                            vec![test_node_id(5), test_node_id(7), test_node_id(6)],
                        )),
                    ],
                )),
                QuorumSetMember::Node(test_node_id(0)),
            ],
        );
        let mut qs_sorted = qs.clone();
        qs_sorted.sort();

        assert_quorum_sets_equal(&qs, &qs_sorted);
    }

    #[test]
    // ordering of members should not matter
    fn test_quorum_set_equality_1() {
        let quorum_set_1 = QuorumSet::new(
            2,
            vec![
                QuorumSetMember::Node(test_node_id(0)),
                QuorumSetMember::Node(test_node_id(1)),
                QuorumSetMember::Node(test_node_id(2)),
                QuorumSetMember::Node(test_node_id(3)),
            ],
        );
        let quorum_set_2 = QuorumSet::new(
            2,
            vec![
                QuorumSetMember::Node(test_node_id(3)),
                QuorumSetMember::Node(test_node_id(1)),
                QuorumSetMember::Node(test_node_id(2)),
                QuorumSetMember::Node(test_node_id(0)),
            ],
        );

        assert_quorum_sets_equal(&quorum_set_1, &quorum_set_2);
    }

    #[test]
    // ordering of members should not matter wrt member Enum type
    fn test_quorum_set_equality_2() {
        let quorum_set_1 = QuorumSet::new(
            2,
            vec![
                QuorumSetMember::Node(test_node_id(0)),
                QuorumSetMember::Node(test_node_id(1)),
                QuorumSetMember::InnerSet(QuorumSet::new(
                    2,
                    vec![
                        QuorumSetMember::Node(test_node_id(3)),
                        QuorumSetMember::Node(test_node_id(4)),
                    ],
                )),
                QuorumSetMember::InnerSet(QuorumSet::new(
                    2,
                    vec![
                        QuorumSetMember::Node(test_node_id(5)),
                        QuorumSetMember::Node(test_node_id(6)),
                        QuorumSetMember::Node(test_node_id(7)),
                    ],
                )),
            ],
        );
        let quorum_set_2 = QuorumSet::new(
            2,
            vec![
                QuorumSetMember::Node(test_node_id(1)),
                QuorumSetMember::InnerSet(QuorumSet::new(
                    2,
                    vec![
                        QuorumSetMember::Node(test_node_id(3)),
                        QuorumSetMember::Node(test_node_id(4)),
                    ],
                )),
                QuorumSetMember::Node(test_node_id(0)),
                QuorumSetMember::InnerSet(QuorumSet::new(
                    2,
                    vec![
                        QuorumSetMember::Node(test_node_id(5)),
                        QuorumSetMember::Node(test_node_id(6)),
                        QuorumSetMember::Node(test_node_id(7)),
                    ],
                )),
            ],
        );
        assert_quorum_sets_equal(&quorum_set_1, &quorum_set_2);
    }

    #[test]
    // ordering of members inside inner sets should not matter
    fn test_quorum_set_equality_3() {
        let quorum_set_1 = QuorumSet::new(
            2,
            vec![
                QuorumSetMember::Node(test_node_id(0)),
                QuorumSetMember::Node(test_node_id(1)),
                QuorumSetMember::InnerSet(QuorumSet::new(
                    2,
                    vec![
                        QuorumSetMember::Node(test_node_id(3)),
                        QuorumSetMember::Node(test_node_id(4)),
                    ],
                )),
                QuorumSetMember::InnerSet(QuorumSet::new(
                    2,
                    vec![
                        QuorumSetMember::Node(test_node_id(5)),
                        QuorumSetMember::Node(test_node_id(6)),
                        QuorumSetMember::Node(test_node_id(7)),
                    ],
                )),
            ],
        );
        let quorum_set_2 = QuorumSet::new(
            2,
            vec![
                QuorumSetMember::Node(test_node_id(1)),
                QuorumSetMember::Node(test_node_id(0)),
                QuorumSetMember::InnerSet(QuorumSet::new(
                    2,
                    vec![
                        QuorumSetMember::Node(test_node_id(4)),
                        QuorumSetMember::Node(test_node_id(3)),
                    ],
                )),
                QuorumSetMember::InnerSet(QuorumSet::new(
                    2,
                    vec![
                        QuorumSetMember::Node(test_node_id(5)),
                        QuorumSetMember::Node(test_node_id(7)),
                        QuorumSetMember::Node(test_node_id(6)),
                    ],
                )),
            ],
        );
        assert_quorum_sets_equal(&quorum_set_1, &quorum_set_2);
    }

    #[test]
    fn test_is_valid() {
        // An empty quorum set is valid.
        assert!(QuorumSet::<String>::empty().is_valid());

        // A quorum set with num of members > threshold is valid.
        assert!(QuorumSet::new(
            2,
            vec![
                QuorumSetMember::Node(test_node_id(0)),
                QuorumSetMember::Node(test_node_id(1)),
                QuorumSetMember::Node(test_node_id(2)),
            ],
        )
        .is_valid());

        // A quorum set with num of members == threshold is valid.
        assert!(QuorumSet::new(
            3,
            vec![
                QuorumSetMember::Node(test_node_id(0)),
                QuorumSetMember::Node(test_node_id(1)),
                QuorumSetMember::Node(test_node_id(2)),
            ],
        )
        .is_valid());

        // A quorum set with num of members < threshold is invalid
        assert!(!QuorumSet::new(
            4,
            vec![
                QuorumSetMember::Node(test_node_id(0)),
                QuorumSetMember::Node(test_node_id(1)),
                QuorumSetMember::Node(test_node_id(2)),
            ],
        )
        .is_valid());

        // A quorum set with a valid inner set is valid.
        let qs = QuorumSet::new(
            2,
            vec![
                QuorumSetMember::Node(test_node_id(1)),
                QuorumSetMember::InnerSet(QuorumSet::new(
                    2,
                    vec![
                        QuorumSetMember::Node(test_node_id(3)),
                        QuorumSetMember::Node(test_node_id(2)),
                        QuorumSetMember::InnerSet(QuorumSet::new_with_node_ids(
                            2,
                            vec![test_node_id(5), test_node_id(7), test_node_id(6)],
                        )),
                    ],
                )),
                QuorumSetMember::Node(test_node_id(0)),
            ],
        );
        assert!(qs.is_valid());

        // A quorum set with an invalid inner set is invalid.
        let qs = QuorumSet::new(
            2,
            vec![
                QuorumSetMember::Node(test_node_id(1)),
                QuorumSetMember::InnerSet(QuorumSet::new(
                    2,
                    vec![
                        QuorumSetMember::Node(test_node_id(3)),
                        QuorumSetMember::Node(test_node_id(2)),
                        QuorumSetMember::InnerSet(QuorumSet::new_with_node_ids(
                            20,
                            vec![test_node_id(5), test_node_id(7), test_node_id(6)],
                        )),
                    ],
                )),
                QuorumSetMember::Node(test_node_id(0)),
            ],
        );
        assert!(!qs.is_valid());
    }
}
