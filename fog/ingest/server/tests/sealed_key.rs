// Copyright (c) 2018-2022 The MobileCoin Foundation

use mc_common::logger::{test_with_logger, Logger};
use mc_fog_ingest_server_test_utils::IngestServerTestHelper;

const BASE_PORT: u16 = 3457;

#[test_with_logger]
fn test_ingest_sealed_key_recovery(logger: Logger) {
    let helper = IngestServerTestHelper::new(BASE_PORT, logger.clone());

    let node = helper.make_node(1, 1..=1);
    let original_key = node.get_ingress_key();
    let state_file_path = node.state_file_path.clone();
    drop(node);

    let node = helper.make_node_with_state(1, 1..=1, state_file_path.clone());
    let new_key = node.get_ingress_key();
    assert_eq!(
        original_key, new_key,
        "Failed to recover the same ingress key from restart with keyfile!"
    );

    drop(node);
    drop(std::fs::remove_file(&state_file_path));

    let node = helper.make_node_with_state(1, 1..=1, state_file_path);
    let new_key = node.get_ingress_key();
    assert_ne!(
        original_key, new_key,
        "Ingress private key was successfully recovered when it should not have been!"
    );
}
