// Copyright (c) 2018-2022 The MobileCoin Foundation

mod utils;

use mc_common::logger::{test_with_logger, Logger};
use mc_fog_ingest_server_test_utils::{get_ingress_keys, IngestServerTestHelper};
use std::{thread::sleep, time::Duration};
use utils::TestHelperExt;

const BASE_PORT: u16 = 8800;

// Tests the scenario in which the active node retires its key and scans all
// its blocks, which means that it's not outstanding. The idle nodes have the
// same key as this retired key.
//
// In this scenario, Fog Overseer should set new keys on an idle node and
// activate it.
#[test_with_logger]
fn active_key_is_retired_not_outstanding_new_key_is_set_node_activated(logger: Logger) {
    let mut helper = IngestServerTestHelper::new(BASE_PORT, logger.clone());
    helper.add_origin_block();
    let nodes = helper.make_nodes(3);

    nodes[0].activate().expect("first node failed to activate");
    assert!(nodes[0].is_active());
    assert!(!nodes[1].is_active());
    assert!(!nodes[2].is_active());

    // Keys should be idential.
    let original_ingress_keys = get_ingress_keys(&nodes);
    assert_eq!(original_ingress_keys[0], original_ingress_keys[1]);
    assert_eq!(original_ingress_keys[0], original_ingress_keys[2]);

    // Initialize an OverseerService with an associated server.
    let _client = helper.enable_overseer_for_nodes(&nodes);

    assert!(nodes[0].is_active());
    assert!(!nodes[1].is_active());
    assert!(!nodes[2].is_active());

    // Retire the current active node.
    nodes[0].retire().expect("failed to retire active server");

    // This will trigger the Fog Ingest controller to set node0 to idle since it
    // will be retired and past the pubkey_expiry.
    helper.add_test_blocks(11);
    helper.wait_till_recovery_db_in_sync();
    helper.add_test_blocks(2);
    // Give the new keys more time to propagate.
    sleep(Duration::from_secs(5));

    // Fog Overseer should have activated any node.
    assert!(nodes.iter().any(|n| n.is_active()));

    // Each key should change.
    let new_ingress_keys = get_ingress_keys(&nodes);
    assert_ne!(original_ingress_keys, new_ingress_keys);
    original_ingress_keys
        .iter()
        .zip(new_ingress_keys.iter())
        .enumerate()
        .for_each(|(index, (original, new))| {
            assert_ne!(original, new, "node{} ingress key did not change", index)
        });

    // Ensure that the old active key is retired.
    helper.check_ingress_key(&original_ingress_keys[0], true, false);
    // Ensure that this new key is not lost or retired.
    helper.check_ingress_key(&new_ingress_keys[0], false, false);
}
