use mc_consensus_scp::{test_utils::test_node_id, QuorumSet, QuorumSetMember};

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
