// Copyright (c) 2018-2022 The MobileCoin Foundation

use mc_common::logger::{test_with_logger, Logger};
use mc_crypto_keys::CompressedRistrettoPublic;
use mc_fog_overseer_server::{server, server::OverseerState, service::OverseerService};
use mc_fog_recovery_db_iface::RecoveryDb;
use mc_fog_sql_recovery_db::test_utils::SqlRecoveryDbTestContext;
use mc_ledger_db::LedgerDB;
use mc_watcher::watcher_db::WatcherDB;
use rocket::local::Client;
use std::{convert::TryFrom, str::FromStr, time::Duration};
use tempdir::TempDir;
use url::Url;

mod utils;

const PORT_NUMBER: u16 = 8082;

// In this scenario, the Fog Ingest cluster has one active node, which is the
// expected state for the cluster.
//
// Fog Overseer shouldn't take any action.
#[test_with_logger]
fn one_active_node_cluster_state_does_not_change(logger: Logger) {
    let db_test_context = SqlRecoveryDbTestContext::new(logger.clone());
    let recovery_db = db_test_context.get_db_instance();

    // Set up the Watcher db.
    let blockchain_path =
        TempDir::new("blockchain").expect("Could not make tempdir for blockchain state");
    let watcher_path = blockchain_path.path().join("watcher");
    std::fs::create_dir(&watcher_path).expect("couldn't create dir");
    WatcherDB::create(&watcher_path).unwrap();

    // Open the watcher db
    let tx_source_url = Url::from_str("https://localhost").unwrap();
    let _watcher =
        mc_watcher::watcher_db::WatcherDB::open_rw(&watcher_path, &[tx_source_url], logger.clone())
            .expect("Could not create watcher_db");

    // Set up an empty ledger db.
    let ledger_db_path = blockchain_path.path().join("ledger_db");
    std::fs::create_dir(&ledger_db_path).expect("couldn't create dir");
    LedgerDB::create(&ledger_db_path).unwrap();
    let _ledger = LedgerDB::open(&ledger_db_path).unwrap();

    let peer_indices = vec![0u16, 1u16, 2u16];
    let (node0, _node0dir, client_listen_uri0) = utils::make_node(
        0,
        peer_indices.iter().cloned(),
        recovery_db.clone(),
        &watcher_path,
        &ledger_db_path,
        logger.clone(),
    );
    let (node1, _node1dir, client_listen_uri1) = utils::make_node(
        1,
        peer_indices.iter().cloned(),
        recovery_db.clone(),
        &watcher_path,
        &ledger_db_path,
        logger.clone(),
    );
    let (node2, _node2dir, client_listen_uri2) = utils::make_node(
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
    std::thread::sleep(Duration::from_millis(1000));

    node0.activate().expect("node0 failed to activate");

    assert!(node0.is_active());
    assert!(!node1.is_active());
    assert!(!node2.is_active());
    // Get the original keys using node.
    let original_node0_status = node0.get_ingest_summary();
    let original_node0_ingress_key = original_node0_status.get_ingress_pubkey();
    let original_node1_status = node1.get_ingest_summary();
    let original_node1_ingress_key = original_node1_status.get_ingress_pubkey();
    let original_node2_status = node2.get_ingest_summary();
    let original_node2_ingress_key = original_node2_status.get_ingress_pubkey();

    // Consider testing the CLI here instead
    // Initialize an OverSeerService object...
    let rocket_config: rocket::Config =
        rocket::Config::build(rocket::config::Environment::Development)
            // TODO: Make these either passed from CLI or in a Rocket.toml.
            .address("127.0.0.1")
            .port(PORT_NUMBER)
            .unwrap();

    let mut overseer_service = OverseerService::new(
        vec![client_listen_uri0, client_listen_uri1, client_listen_uri2],
        recovery_db.clone(),
        logger,
    );
    overseer_service.start().unwrap();
    let overseer_state = OverseerState { overseer_service };
    let rocket = server::initialize_rocket_server(rocket_config, overseer_state);
    let client = Client::new(rocket).expect("valid rocket instance");
    let _req = client.post("/enable").dispatch();

    // Give Overseer time to perform logic
    std::thread::sleep(Duration::from_millis(5000));

    assert!(node0.is_active());
    assert!(!node1.is_active());
    assert!(!node2.is_active());

    let new_node0_status = node0.get_ingest_summary();
    let new_node0_ingress_key = new_node0_status.get_ingress_pubkey();
    let new_node1_status = node1.get_ingest_summary();
    let new_node1_ingress_key = new_node1_status.get_ingress_pubkey();
    let new_node2_status = node2.get_ingest_summary();
    let new_node2_ingress_key = new_node2_status.get_ingress_pubkey();

    assert_eq!(original_node0_ingress_key, new_node0_ingress_key);
    assert_eq!(original_node1_ingress_key, new_node1_ingress_key);
    assert_eq!(original_node2_ingress_key, new_node2_ingress_key);

    let query_key = CompressedRistrettoPublic::try_from(new_node0_ingress_key).unwrap();
    let ingress_key_public_status = recovery_db
        .get_ingress_key_status(&query_key)
        .unwrap()
        .unwrap();

    assert!(!ingress_key_public_status.retired);
    assert!(!ingress_key_public_status.lost);
}
