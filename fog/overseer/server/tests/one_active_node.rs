// Copyright (c) 2018-2022 The MobileCoin Foundation

mod utils;

use mc_common::logger::{test_with_logger, Logger};
use mc_fog_ingest_server_test_utils::{get_ingress_keys, IngestServerTestHelper};
use utils::TestHelperExt;

const BASE_PORT: u16 = 8650;

// In this scenario, the Fog Ingest cluster has one active node, which is the
// expected state for the cluster.
//
// Fog Overseer shouldn't take any action.
#[test_with_logger]
fn one_active_node_cluster_state_does_not_change(logger: Logger) {
    let mut helper = IngestServerTestHelper::new(BASE_PORT, logger.clone());
    helper.add_origin_block();
    let nodes = helper.make_nodes(3);

    nodes[0].activate().expect("first node failed to activate");
    assert!(nodes[0].is_active());
    assert!(!nodes[1].is_active());
    assert!(!nodes[2].is_active());

    // Track the original keys.
    let original_ingress_keys = get_ingress_keys(&nodes);

    // Initialize an OverseerService with an associated server.
    let _ = helper.enable_overseer_for_nodes(&nodes);

    assert!(nodes[0].is_active());
    assert!(!nodes[1].is_active());
    assert!(!nodes[2].is_active());
    // None of the keys should change.
    assert_eq!(original_ingress_keys, get_ingress_keys(&nodes));

    // The original key should still be active.
    helper.check_ingress_key(&original_ingress_keys[0], false, false);
}
