// Copyright (c) 2018-2022 The MobileCoin Foundation

mod utils;

use mc_common::logger::{test_with_logger, Logger};
use mc_fog_ingest_server_test_utils::IngestServerTestHelper;
use regex::Regex;
use utils::TestHelperExt;

const BASE_PORT: u16 = 8850;

// Ensures that the correct ingest summaries are produced when the Fog Ingest
// cluster has one active node.
#[test_with_logger]
fn one_active_node_produces_ingest_summaries(logger: Logger) {
    let mut helper = IngestServerTestHelper::new(BASE_PORT, logger.clone());
    helper.add_origin_block();
    let nodes = helper.make_nodes(3);

    nodes[0].activate().expect("first node failed to activate");

    assert!(nodes[0].is_active());
    assert!(!nodes[1].is_active());
    assert!(!nodes[2].is_active());

    // Initialize an OverseerService with an associated server.
    let client = helper.enable_overseer_for_nodes(&nodes);

    // Query the summaries.
    let response = client.get("/ingest_summaries").dispatch();
    let body = response.into_string().unwrap();

    let active_pattern = Regex::new("ACTIVE").unwrap();
    active_pattern.captures(&body);
    assert_eq!(
        active_pattern.captures_len(),
        1,
        "JSON body should have exactly 1 ACTIVE: {}",
        body
    );
}
