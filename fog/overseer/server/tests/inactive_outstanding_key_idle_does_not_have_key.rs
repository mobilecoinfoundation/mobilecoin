// Copyright (c) 2018-2022 The MobileCoin Foundation

mod utils;

use mc_common::logger::{test_with_logger, Logger};
use mc_fog_ingest_server_test_utils::{get_ingress_keys, IngestServerTestHelper};
use std::{collections::VecDeque, thread::sleep, time::Duration};
use utils::TestHelperExt;

const BASE_PORT: u16 = 8550;

// Tests the scenario in which the most recent active node goes down, and
// its key is oustanding, which means that the key still needs to be used to
// scan the blockchain. None of the idle nodes have this active key.
//
// In this scenario, Fog Overseer should activate an idle node and report the
// original active key as lost.
#[test_with_logger]
fn inactive_oustanding_key_idle_node_does_not_have_key_idle_node_is_activated_and_original_key_is_reported_lost(
    logger: Logger,
) {
    let mut helper = IngestServerTestHelper::new(BASE_PORT, logger.clone());
    helper.add_origin_block();
    let mut nodes = VecDeque::from(helper.make_nodes(3));

    let original_ingress_key = nodes[0].get_ingress_key();

    nodes[0].activate().expect("first node failed to activate");

    assert!(nodes[0].is_active());
    assert!(!nodes[1].is_active());
    assert!(!nodes[2].is_active());

    // Initialize an OverseerService with an associated server.
    let _client = helper.enable_overseer_for_nodes(nodes.make_contiguous());

    // This will trigger the Fog Ingest controller to set node0 to idle since it
    // will be retired and past the pubkey_expiry.
    helper.add_test_blocks(11);
    helper.wait_till_recovery_db_in_sync();

    // Stop the current active node. This should make this node's key
    // "outstanding" because at this point in time, there will be no active node
    // that uses this key to scan.
    drop(nodes.pop_front());
    // Give node0 time to stop. There's a gRPC bug that prevents threads from
    // being joined automatically, but if we give it a second then it should
    // successfully join the threads.
    sleep(Duration::from_secs(2));

    // Change the ingress keys on the remaining nodes so that they're different
    // than former node0's ingress key, which is the currently active key.
    nodes[0].set_new_keys().unwrap();
    nodes[1].set_new_keys().unwrap();
    sleep(Duration::from_secs(5));

    // Verify the keys changed.
    let first_node1_ingress_key = nodes[0].get_ingress_key();
    let first_node2_ingress_key = nodes[1].get_ingress_key();
    assert_ne!(original_ingress_key, first_node1_ingress_key);
    assert_ne!(original_ingress_key, first_node2_ingress_key);
    assert_ne!(first_node1_ingress_key, first_node2_ingress_key);

    // Restart node0. This mimics what happens when our cloud infra provider
    // "brings back" a bounced node.
    nodes.push_front(helper.make_node(0, 0..3));

    helper.add_test_blocks(11);
    nodes[0].wait_for_ingest(22);

    // Fog Overseer should have activated any node.
    assert!(nodes.iter().any(|n| n.is_active()));

    // We don't care which key changed, just make sure that one of the keys changed!
    let new_ingress_keys = get_ingress_keys(nodes.make_contiguous());
    assert_ne!(
        new_ingress_keys,
        vec![
            original_ingress_key,
            first_node1_ingress_key,
            first_node2_ingress_key
        ]
    );

    // Assert that the first active key has been reported lost.
    helper.check_ingress_key(&original_ingress_key, false, true);
}
