// Copyright (c) 2018-2022 The MobileCoin Foundation

mod utils;

use mc_common::logger::{test_with_logger, Logger};
use mc_fog_ingest_server_test_utils::{get_ingress_keys, IngestServerTestHelper};
use std::{collections::VecDeque, thread::sleep, time::Duration};
use utils::TestHelperExt;

const BASE_PORT: u16 = 8600;

// Tests the scenario in which the most recent active node goes down, and
// its key is oustanding, which means that the key still needs to be used to
// scan the blockchain. The idle nodes have this active key.
//
// In this scenario, Fog Overseer should activate an idle node and not set a
// new key or report this original key as lost.
#[test_with_logger]
fn inactive_oustanding_key_idle_node_has_original_key_node_is_activated_and_key_is_not_reported_lost_or_retired(
    logger: Logger,
) {
    let mut helper = IngestServerTestHelper::new(BASE_PORT, logger.clone());
    helper.add_origin_block();
    let mut nodes = VecDeque::from(helper.make_nodes(3));

    nodes[0].activate().expect("nodes[0] failed to activate");

    assert!(nodes[0].is_active());
    assert!(!nodes[1].is_active());
    assert!(!nodes[2].is_active());

    // Keys should be identical.
    let original_ingress_keys = get_ingress_keys(nodes.make_contiguous());
    assert_eq!(original_ingress_keys[0], original_ingress_keys[1]);
    assert_eq!(original_ingress_keys[0], original_ingress_keys[2]);

    // Initialize an OverseerService with an associated server.
    let _client = helper.enable_overseer_for_nodes(nodes.make_contiguous());

    // This will trigger the Fog Ingest controller to set node0 to idle since it
    // will be retired and past the pubkey_expiry.
    helper.add_test_blocks(11);
    helper.wait_till_recovery_db_in_sync();

    // Stop the current active node. This should make this node's key
    // "outstanding" because at this point in time, there will be no active node
    // that uses the in-use key to scan.
    // This also deletes the state dir.
    drop(nodes.pop_front());

    // Give node0 time to stop. There's a gRPC bug that prevents threads from
    // being joined automatically, but if we give it a second then it should
    // successfully join the threads.
    sleep(Duration::from_secs(2));

    // Restart node0 by creating a new FogIngestServer instance with the same
    // url as the original node0 instance. This mimics what happens when our
    // cloud infra provider "brings back" a bounced node.
    nodes.push_front(helper.make_node(0, 0..3));
    assert!(!nodes[0].is_active());

    helper.add_test_blocks(11);
    helper.wait_till_recovery_db_in_sync();

    // Fog Overseer should have activated any node.
    assert!(nodes.iter().any(|n| n.is_active()));

    // Ensure that none of the keys changed.
    let new_ingress_keys = get_ingress_keys(nodes.make_contiguous());
    assert_eq!(original_ingress_keys, new_ingress_keys);

    // Assert that first key that was active has not been retired or reported
    // lost.
    //
    // It should not be retired or lost because the node that is activated
    // by overseer should be using this key to scan blocks.
    helper.check_ingress_key(&original_ingress_keys[0], false, false);
}
