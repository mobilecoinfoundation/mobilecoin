// Copyright (c) 2018-2022 The MobileCoin Foundation

//! QuorumSet helpers for tests.

use mc_consensus_scp::{test_utils::test_node_id, QuorumSet, QuorumSetMember};

/// Create a QuorumSet for tests.
pub fn make_quorum_set() -> QuorumSet {
    let qs = QuorumSet::new(
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
    assert!(qs.is_valid());
    qs
}
