// Copyright (c) 2018-2022 The MobileCoin Foundation

mod utils;

use mc_common::logger::{test_with_logger, Logger};
use mc_fog_ingest_server_test_utils::IngestServerTestHelper;
use regex::Regex;
use utils::TestHelperExt;

const BASE_PORT: u16 = 8700;

// Tests the scenario in which the most recent active node goes down, and
// its key is oustanding, which means that the key still needs to be used to
// scan the blockchain. None of the idle nodes have this active key.
//
// In this scenario, Fog Overseer should activate an idle node and report the
// original active key as lost.
#[test_with_logger]
fn one_active_node_idle_nodes_different_keys_produces_prometheus_metrics(logger: Logger) {
    let mut helper = IngestServerTestHelper::new(BASE_PORT, logger.clone());
    helper.add_origin_block();
    let nodes = helper.make_nodes(3);

    nodes[0].activate().expect("first node failed to activate");

    assert!(nodes[0].is_active());
    assert!(!nodes[1].is_active());
    assert!(!nodes[2].is_active());

    // Initialize an OverseerService with an associated server.
    let client = helper.enable_overseer_for_nodes(&nodes);
    let response = client.get("/metrics").dispatch();
    let body = response.into_string().unwrap();

    let correct_active_node_count = Regex::new(r#"active_node_count"} 1"#).unwrap();
    assert!(
        correct_active_node_count.is_match(&body),
        "Body does not have expected active_node_count: {}",
        body
    );

    let correct_egress_key_count = Regex::new(r#"egress_key_count"} 3"#).unwrap();
    assert!(
        correct_egress_key_count.is_match(&body),
        "Body does not have expected egress_key_count: {}",
        body
    );

    let correct_idle_node_count = Regex::new(r#"idle_node_count"} 2"#).unwrap();
    assert!(
        correct_idle_node_count.is_match(&body),
        "Body does not have expected idle_node_count: {}",
        body
    );

    let correct_ingress_key_count = Regex::new(r#"ingress_key_count"} 1"#).unwrap();
    assert!(
        correct_ingress_key_count.is_match(&body),
        "Body does not have expected ingress_key_count: {}",
        body
    );

    let correct_unresponsive_node_count_name = Regex::new(r#"unresponsive_node_count"#).unwrap();
    assert!(
        !correct_unresponsive_node_count_name.is_match(&body),
        "Body should not have unresponsive_node_count: {}",
        body
    );
}
