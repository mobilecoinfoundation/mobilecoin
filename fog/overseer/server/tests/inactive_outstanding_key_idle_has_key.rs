// Copyright (c) 2018-2022 The MobileCoin Foundation

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
use rocket::local::blocking::Client;
use std::{convert::TryFrom, str::FromStr, time::Duration};
use tempdir::TempDir;
use url::Url;

mod utils;

const PORT_NUMBER: u16 = 8080;

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
    let watcher =
        mc_watcher::watcher_db::WatcherDB::open_rw(&watcher_path, &[tx_source_url], logger.clone())
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
        ..Default::default()
    };
    let origin_block = Block::new_origin_block(&origin_txo);
    ledger
        .append_block(&origin_block, &origin_contents, None)
        .expect("failed writing initial transactions");

    let peer_indices = vec![0u16, 1u16, 2u16];
    let (node0, state_file_node_0, client_listen_uri0) = utils::make_node(
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

    let first_node0_ingress_key = node0.get_ingest_summary().get_ingress_pubkey().clone();
    let first_node1_ingress_key = node1.get_ingest_summary().get_ingress_pubkey().clone();
    let first_node2_ingress_key = node2.get_ingest_summary().get_ingress_pubkey().clone();

    // All the keys should be equal.
    assert_eq!(first_node0_ingress_key, first_node1_ingress_key);
    assert_eq!(first_node0_ingress_key, first_node2_ingress_key);
    assert_eq!(first_node1_ingress_key, first_node2_ingress_key);

    // Initialize an OverSeerService object
    let mut overseer_service = OverseerService::new(
        vec![client_listen_uri0, client_listen_uri1, client_listen_uri2],
        recovery_db.clone(),
        logger.clone(),
    );
    overseer_service.start().unwrap();

    // Set up the Rocket instance
    let overseer_state = OverseerState { overseer_service };
    // TODO: Consider testng the CLI here instead
    let rocket_config = rocket::Config::figment()
        .merge(("port", PORT_NUMBER))
        .merge(("address", "127.0.0.1"));
    let rocket = server::initialize_rocket_server(rocket_config, overseer_state);
    let client = Client::tracked(rocket).expect("valid rocket instance");
    client.post("/enable").dispatch();

    // Add 11 test blocks.
    for _ in 0..11 {
        utils::add_test_block(&mut ledger, &watcher, &mut rng);
    }

    // Stop the current active node. This should make this node's key
    // "outstanding" because at this point in time, there will be no active node
    // that uses the in-use key to scan.
    drop(node0);

    // Give node0 time to stop. There's a gRPC bug that prevents threads from
    // being joined automatically, but if we give it a second then it should
    // successfully join the threads.
    std::thread::sleep(Duration::from_secs(2));

    // Delete the state file for nod0. This ensures that when it's restarted,
    // it won't be automatically moved to the Active state.
    drop(std::fs::remove_file(&state_file_node_0));

    // Restart node0 by creating a new FogIngestServer instance with the same
    // url as the original node0 instance. This mimics what happens when our
    // cloud infra provider "brings back" a bounced node.
    let (node0, _state_file_node_0, _client_listen_uri0) = utils::make_node(
        0,
        peer_indices.iter().cloned(),
        recovery_db.clone(),
        &watcher_path,
        &ledger_db_path,
        logger.clone(),
    );
    assert!(!node0.is_active());

    for _ in 0..11 {
        utils::add_test_block(&mut ledger, &watcher, &mut rng);
    }

    // It takes overseer on average 10 seconds to realize that the node has
    // gone down. Make it 15 seconds to be safe.
    std::thread::sleep(Duration::from_secs(15));

    // Fog Overseer should have activated any node.
    assert!(node0.is_active() || node1.is_active() || node2.is_active());

    let second_node0_ingress_key = node0.get_ingest_summary().get_ingress_pubkey().clone();
    let second_node1_ingress_key = node1.get_ingest_summary().get_ingress_pubkey().clone();
    let second_node2_ingress_key = node2.get_ingest_summary().get_ingress_pubkey().clone();

    // Ensure that none of the keys changed.
    let did_node0_ingress_key_change = first_node0_ingress_key != second_node0_ingress_key;
    let did_node1_ingress_key_change = first_node1_ingress_key != second_node1_ingress_key;
    let did_node2_ingress_key_change = first_node2_ingress_key != second_node2_ingress_key;

    let did_any_node_keys_change = did_node0_ingress_key_change
        || did_node1_ingress_key_change
        || did_node2_ingress_key_change;
    assert!(!did_any_node_keys_change);

    // Assert that first key that was active has not been retired or reported
    // lost.
    //
    // It should not be retired or lost because the node that is activated
    // by overseer should be using this key to scan blocks.
    let node0_query_key = CompressedRistrettoPublic::try_from(&first_node0_ingress_key).unwrap();
    let ingress_key_public_status = recovery_db
        .get_ingress_key_status(&node0_query_key)
        .unwrap()
        .unwrap();
    assert!(!ingress_key_public_status.retired);
    assert!(!ingress_key_public_status.lost);

    let _req = client.post("/disable").dispatch();
    std::thread::sleep(Duration::from_secs(10));
}
