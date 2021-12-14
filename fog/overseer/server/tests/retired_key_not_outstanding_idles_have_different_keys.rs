// Copyright (c) 2018-2021 The MobileCoin Foundation

use mc_common::logger::{test_with_logger, Logger};
use mc_crypto_keys::CompressedRistrettoPublic;
use mc_fog_overseer_server::{server, server::OverseerState, service::OverseerService};
use mc_fog_recovery_db_iface::RecoveryDb;
use mc_fog_sql_recovery_db::test_utils::SqlRecoveryDbTestContext;
use mc_ledger_db::{Ledger, LedgerDB};
use mc_transaction_core::{Block, BlockContents};
use mc_watcher::watcher_db::WatcherDB;
use rand_core::SeedableRng;
use rand_hc::Hc128Rng;
use rocket::local::Client;
use std::{convert::TryFrom, str::FromStr, time::Duration};
use tempdir::TempDir;
use url::Url;

mod utils;

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
    let db_test_context = SqlRecoveryDbTestContext::new(logger.clone());
    let recovery_db = db_test_context.get_db_instance();
    let mut rng: Hc128Rng = SeedableRng::from_seed([0u8; 32]);

    // Set up the watcher db
    let blockchain_path =
        TempDir::new("blockchain").expect("Could not make tempdir for blockchain state");
    let watcher_path = blockchain_path.path().join("watcher");
    std::fs::create_dir(&watcher_path).expect("couldn't create dir");
    WatcherDB::create(&watcher_path).unwrap();

    // Open the watcher db
    let tx_source_url = Url::from_str("https://localhost").unwrap();
    let watcher = mc_watcher::watcher_db::WatcherDB::open_rw(
        &watcher_path,
        &[tx_source_url.clone()],
        logger.clone(),
    )
    .expect("Could not create watcher_db");

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
    };
    let origin_block = Block::new_origin_block(&origin_txo);
    ledger
        .append_block(&origin_block, &origin_contents, None)
        .expect("failed writing initial transactions");

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

    // Change the ingress keys on node1 and node2 so that they're different than
    // node0's currently active ingress key.
    node1.set_new_keys().unwrap();
    node2.set_new_keys().unwrap();

    let first_node0_ingress_key = node0.get_ingest_summary().get_ingress_pubkey().clone();
    let first_node1_ingress_key = node1.get_ingest_summary().get_ingress_pubkey().clone();
    let first_node2_ingress_key = node2.get_ingest_summary().get_ingress_pubkey().clone();

    assert_ne!(first_node0_ingress_key, first_node1_ingress_key);
    assert_ne!(first_node0_ingress_key, first_node2_ingress_key);
    assert_ne!(first_node1_ingress_key, first_node2_ingress_key);

    // Initialize an OverSeerService object
    let mut overseer_service = OverseerService::new(
        vec![client_listen_uri0, client_listen_uri1, client_listen_uri2],
        recovery_db.clone(),
        logger.clone(),
    );
    overseer_service.start().unwrap();

    // Set up the Rocket instance
    let overseer_state = OverseerState { overseer_service };
    // Consider testng the CLI here instead
    let rocket_config: rocket::Config =
        rocket::Config::build(rocket::config::Environment::Development)
            // TODO: Make these either passed from CLI or in a Rocket.toml.
            .address("127.0.0.1")
            .port(80)
            .unwrap();
    let rocket = server::initialize_rocket_server(rocket_config, overseer_state);
    let client = Client::new(rocket).expect("valid rocket instance");
    let _req = client.post("/arm");

    // Retire the current active node.
    node0.retire().unwrap();

    // Add 11 test blocks. This will trigger the Fog Ingest controller to set
    // Node0 to idle since it will be retired and past the pubkey_expiry.
    for _ in 0..11 {
        utils::add_test_block(&mut ledger, &watcher, &mut rng);
    }

    // While it would be nice to make sure that the node0 is
    // actually in an idle state (to ensure that it isn't just active
    // the entire time), it isn't practical because it introduces a lot of
    // flakiness. It's hard to use sleep statements to separate out when
    // the node is reported idle and when the overseer reactivates it.
    //
    // Instead, at the end of the test, we make sure that the
    // first_node0_ingress_key is retired. If this is the case, then this
    // confirms that node0 would have been idle for some time.

    // During this sleep, overseer should be performing it's automatic
    // failover logic.
    std::thread::sleep(Duration::from_millis(10000));
    // Fog Overseer should have activated any node.
    assert!(node0.is_active() || node0.is_active() || node2.is_active());

    let second_node0_ingress_key = node0.get_ingest_summary().get_ingress_pubkey().clone();
    let second_node1_ingress_key = node1.get_ingest_summary().get_ingress_pubkey().clone();
    let second_node2_ingress_key = node2.get_ingest_summary().get_ingress_pubkey().clone();

    // We don't care which key changed, just make sure that one of the keys changed!
    let did_node0_ingress_key_change = first_node0_ingress_key != second_node0_ingress_key;
    let did_node1_ingress_key_change = first_node1_ingress_key != second_node1_ingress_key;
    let did_node2_ingress_key_change = first_node2_ingress_key != second_node2_ingress_key;
    assert!(
        did_node0_ingress_key_change
            || did_node1_ingress_key_change
            || did_node2_ingress_key_change
    );

    // Assert that first key that was active was retired and not lost.
    //
    // It shouldn't be marked as lost because node0 successfully scanned
    // each block up until the pubkey_expiry.
    let node0_query_key = CompressedRistrettoPublic::try_from(&first_node0_ingress_key).unwrap();
    let ingress_key_public_status = recovery_db
        .get_ingress_key_status(&node0_query_key)
        .unwrap()
        .unwrap();
    assert!(ingress_key_public_status.retired);
    assert!(!ingress_key_public_status.lost);
}
