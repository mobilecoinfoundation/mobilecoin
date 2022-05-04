// Copyright (c) 2018-2022 The MobileCoin Foundation

use mc_common::logger::{test_with_logger, Logger};
use mc_fog_overseer_server::{server, server::OverseerState, service::OverseerService};
use mc_fog_sql_recovery_db::test_utils::SqlRecoveryDbTestContext;
use mc_ledger_db::{Ledger, LedgerDB};
use mc_transaction_core::{Block, BlockContents};
use mc_watcher::watcher_db::WatcherDB;
use rand_core::SeedableRng;
use rand_hc::Hc128Rng;
use regex::Regex;
use rocket::local::blocking::Client;
use std::time::Duration;
use tempdir::TempDir;

mod utils;

const PORT_NUMBER: u16 = 8085;

// Tests the scenario in which the most recent active node goes down, and
// its key is oustanding, which means that the key still needs to be used to
// scan the blockchain. None of the idle nodes have this active key.
//
// In this scenario, Fog Overseer should activate an idle node and report the
// original active key as lost.
#[test_with_logger]
fn one_active_node_idle_nodes_different_keys_produces_prometheus_metrics(logger: Logger) {
    let db_test_context = SqlRecoveryDbTestContext::new(logger.clone());
    let recovery_db = db_test_context.get_db_instance();
    let mut rng: Hc128Rng = SeedableRng::from_seed([0u8; 32]);

    // Set up the watcher db
    let blockchain_path =
        TempDir::new("blockchain").expect("Could not make tempdir for blockchain state");
    let watcher_path = blockchain_path.path().join("watcher");
    std::fs::create_dir(&watcher_path).expect("couldn't create dir");
    WatcherDB::create(&watcher_path).unwrap();

    // Set up an empty ledger db.
    let ledger_db_path = blockchain_path.path().join("ledger_db");
    std::fs::create_dir(&ledger_db_path).expect("couldn't create dir");
    LedgerDB::create(&ledger_db_path).unwrap();
    let mut ledger = LedgerDB::open(&ledger_db_path).unwrap();

    // Make origin block before starting Fog Ingest servers
    let origin_txo = utils::random_output(&mut rng);
    let origin_contents = BlockContents {
        key_images: Default::default(),
        outputs: origin_txo.clone(),
        ..Default::default()
    };
    let origin_block = Block::new_origin_block(&origin_txo);
    ledger
        .append_block(&origin_block, &origin_contents, None)
        .expect("failed writing initial transactions");

    let peer_indices = vec![0u16, 1u16, 2u16];
    let (node0, _state_file_node_0, client_listen_uri0) = utils::make_node(
        0,
        peer_indices.iter().cloned(),
        recovery_db.clone(),
        &watcher_path,
        &ledger_db_path,
        logger.clone(),
    );
    let (node1, _state_file_node_1, client_listen_uri1) = utils::make_node(
        1,
        peer_indices.iter().cloned(),
        recovery_db.clone(),
        &watcher_path,
        &ledger_db_path,
        logger.clone(),
    );
    let (node2, _state_file_node2, client_listen_uri2) = utils::make_node(
        2,
        peer_indices.iter().cloned(),
        recovery_db.clone(),
        &watcher_path,
        &ledger_db_path,
        logger.clone(),
    );

    assert!(!node0.is_active());
    assert!(!node1.is_active());
    assert!(!node2.is_active());

    // Give RPC etc. time to start
    std::thread::sleep(Duration::from_secs(1));

    node0.activate().expect("node0 failed to activate");

    assert!(node0.is_active());
    assert!(!node1.is_active());
    assert!(!node2.is_active());

    // Initialize an OverSeerService object
    let mut overseer_service = OverseerService::new(
        vec![client_listen_uri0, client_listen_uri1, client_listen_uri2],
        recovery_db,
        logger.clone(),
    );
    overseer_service.start().unwrap();

    // Set up the Rocket instance
    let overseer_state = OverseerState { overseer_service };
    // TODO: Consider testing the CLI here instead.
    let rocket_config = rocket::Config::figment()
        .merge(("port", PORT_NUMBER))
        .merge(("address", "127.0.0.1"));
    let rocket = server::initialize_rocket_server(rocket_config, overseer_state);
    let client = Client::tracked(rocket).expect("valid rocket instance");
    client.post("/enable").dispatch();

    // Give overseer time to perform its logic.
    std::thread::sleep(Duration::from_secs(10));

    let response = client.get("/metrics").dispatch();

    let body = response.into_string().unwrap();

    let correct_active_node_count = Regex::new(r#"active_node_count"} 1"#).unwrap();
    assert!(correct_active_node_count.is_match(&body));

    let correct_egress_key_count = Regex::new(r#"egress_key_count"} 3"#).unwrap();
    assert!(correct_egress_key_count.is_match(&body));

    let correct_idle_node_count = Regex::new(r#"idle_node_count"} 2"#).unwrap();
    assert!(correct_idle_node_count.is_match(&body));

    let correct_ingress_key_count = Regex::new(r#"ingress_key_count"} 1"#).unwrap();
    assert!(correct_ingress_key_count.is_match(&body));

    let correct_unresponsive_node_count_name = Regex::new(r#"unresponsive_node_count"#).unwrap();
    assert!(!correct_unresponsive_node_count_name.is_match(&body));
}
