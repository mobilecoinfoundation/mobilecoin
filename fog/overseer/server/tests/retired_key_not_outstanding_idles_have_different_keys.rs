// Copyright (c) 2018-2022 The MobileCoin Foundation

mod utils;

use mc_common::logger::{test_with_logger, Logger};
use mc_fog_ingest_server_test_utils::{get_ingress_keys, IngestServerTestHelper};
use utils::TestHelperExt;

const BASE_PORT: u16 = 8750;

// Tests the scenario in which the active node retires its key and scans all
// its blocks, which means that it's not outstanding. The idle nodes have
// different keys than the retired key.
//
// In this scenario, Fog Overseer should set new keys on an idle node and
// activate it.
#[test_with_logger]
fn active_key_is_retired_not_outstanding_idle_nodes_have_different_keys_new_key_is_set_node_activated(
    logger: Logger,
) {
    let mut helper = IngestServerTestHelper::new(BASE_PORT, logger.clone());
    helper.add_origin_block();
    let nodes = helper.make_nodes(3);

    nodes[0].activate().expect("first node failed to activate");

    assert!(nodes[0].is_active());
    assert!(!nodes[1].is_active());
    assert!(!nodes[2].is_active());

    // Change the ingress keys on node1 and node2 so that they're different
    // than node0's currently active ingress key.
    nodes[1].set_new_keys().unwrap();
    nodes[2].set_new_keys().unwrap();

    let original_ingress_keys = get_ingress_keys(&nodes);

    // Initialize an OverseerService with an associated server.
    let _client = helper.enable_overseer_for_nodes(&nodes);

    // Retire the current active node.
    nodes[0].retire().unwrap();

    // This will trigger the Fog Ingest controller to set node0 to idle since it
    // will be retired and past the pubkey_expiry.
    helper.add_test_blocks(11);
    helper.wait_till_recovery_db_in_sync();

    // While it would be nice to make sure that the node0 is
    // actually in an idle state (to ensure that it isn't just active
    // the entire time), it isn't practical because it introduces a lot of
    // flakiness. It's hard to use sleep statements to separate out when
    // the node is reported idle and when the overseer reactivates it.
    //
    // Instead, at the end of the test, we make sure that the
    // original_node0_ingress_key is retired. If this is the case, then this
    // confirms that node0 would have been idle for some time.

    // Fog Overseer should have activated any node.
    assert!(nodes.iter().any(|n| n.is_active()));

    // We don't care which key changed, just make sure that one of the keys changed!
    assert_ne!(original_ingress_keys, get_ingress_keys(&nodes));

    // Assert that original key that was active was retired and not lost.
    // It shouldn't be marked as lost because node0 successfully scanned
    // each block up until the pubkey_expiry.
    helper.check_ingress_key(&original_ingress_keys[0], true, false);
}
