// Copyright (c) 2018-2022 The MobileCoin Foundation

use mc_common::logger::{test_with_logger, Logger};
use mc_fog_ingest_server_test_utils::{get_ingress_keys, IngestServerTestHelper};
use std::collections::{HashSet, VecDeque};

const BASE_PORT: u16 = 3997;

#[test_with_logger]
fn test_key_sharing_on_activate(logger: Logger) {
    let mut helper = IngestServerTestHelper::new(BASE_PORT, logger.clone());
    helper.add_origin_block();

    let nodes = helper.make_nodes(5);
    let node_keys = get_ingress_keys(&nodes);
    let original_node_key = node_keys[0];

    let keys_set = node_keys.iter().collect::<HashSet<_>>();
    assert_eq!(keys_set.len(), 5, "expected 5 unique keys");

    nodes[0].activate().expect("node0 failed to activate");

    assert_eq!(
        original_node_key,
        nodes[0].get_ingress_key(),
        "node0 key changed after activating, unexpectedly!"
    );

    let node_keys = get_ingress_keys(&nodes);
    assert_eq!(node_keys, vec![original_node_key; 5]);

    nodes.iter().skip(1).enumerate().for_each(|(i, node)| {
        assert!(
            node.activate().is_err(),
            "node{} should not be able to activate",
            i
        )
    });

    // drop node0 and then bring it back
    let mut nodes = VecDeque::from(nodes);
    drop(nodes.pop_front());
    nodes.push_front(helper.make_node(0, 0..5));

    assert_ne!(
        original_node_key,
        nodes[0].get_ingress_key(),
        "node0 somehow got its old key back"
    );

    nodes[1].activate().expect("node1 failed to activate!");

    assert_eq!(
        original_node_key,
        nodes[0].get_ingress_key(),
        "node0 didn't get the old key back after node1 was activated"
    );
    assert!(
        nodes[0].activate().is_err(),
        "node0 should not have been able to activate"
    );
    assert!(
        nodes[2].activate().is_err(),
        "node2 should not have been able to activate"
    );
    assert!(
        nodes[3].activate().is_err(),
        "node3 should not have been able to activate"
    );
    assert!(
        nodes[4].activate().is_err(),
        "node4 should not have been able to activate"
    );

    let node_keys = get_ingress_keys(nodes.make_contiguous());
    assert_eq!(node_keys, vec![original_node_key; 5]);
}
