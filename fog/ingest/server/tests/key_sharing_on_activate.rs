// Copyright (c) 2018-2021 The MobileCoin Foundation

use mc_attest_net::{Client as AttestClient, RaClient};
use mc_common::{
    logger::{o, test_with_logger, Logger},
    ResponderId,
};
use mc_fog_ingest_server::{
    server::{IngestServer, IngestServerConfig},
    state_file::StateFile,
};
use mc_fog_sql_recovery_db::{test_utils::SqlRecoveryDbTestContext, SqlRecoveryDb};
use mc_fog_test_infra::get_enclave_path;
use mc_fog_uri::{FogIngestUri, IngestPeerUri};
use mc_ledger_db::LedgerDB;
use mc_watcher::watcher_db::WatcherDB;
use std::{collections::BTreeSet, str::FromStr, time::Duration};
use tempdir::TempDir;

const OMAP_CAPACITY: u64 = 256;
const BASE_PORT: u16 = 3997;

// Helper which makes URIs and responder id for i'th server
fn make_uris(idx: u16) -> (ResponderId, FogIngestUri, IngestPeerUri) {
    let base_port = BASE_PORT + 10 * idx;

    let local_node_id = ResponderId::from_str(&format!("0.0.0.0:{}", base_port + 5)).unwrap();
    let client_listen_uri =
        FogIngestUri::from_str(&format!("insecure-fog-ingest://0.0.0.0:{}/", base_port + 4))
            .unwrap();
    let peer_listen_uri =
        IngestPeerUri::from_str(&format!("insecure-igp://0.0.0.0:{}/", base_port + 5)).unwrap();

    (local_node_id, client_listen_uri, peer_listen_uri)
}

// Helper which makes i'th server and temp dir for its stuff (deleted when
// objects are dropped)
fn make_node(
    idx: u16,
    peer_idxs: impl Iterator<Item = u16>,
    db: SqlRecoveryDb,
    logger: Logger,
) -> (IngestServer<AttestClient, SqlRecoveryDb>, TempDir) {
    let logger = logger.new(o!("mc.node_id" => idx.to_string()));
    let (local_node_id, client_listen_uri, peer_listen_uri) = make_uris(idx);

    let peers: BTreeSet<IngestPeerUri> = peer_idxs.map(|idx| make_uris(idx).2).collect();

    let state_tmp = TempDir::new("ingest_state").expect("Could not make tempdir for ingest state");
    let state_file = state_tmp.path().join("mc-ingest-state");

    let config = IngestServerConfig {
        ias_spid: Default::default(),
        local_node_id,
        client_listen_uri,
        peer_listen_uri,
        peers,
        fog_report_id: Default::default(),
        max_transactions: 10_000,
        pubkey_expiry_window: 100,
        peer_checkup_period: None,
        watcher_timeout: Duration::default(),
        state_file: Some(StateFile::new(state_file.clone())),
        enclave_path: get_enclave_path(mc_fog_ingest_enclave::ENCLAVE_FILE),
        omap_capacity: OMAP_CAPACITY,
    };

    // Set up the Watcher DB - create a new watcher DB for each phase
    let watcher_path = state_tmp.path().join("watcher");
    std::fs::create_dir(&watcher_path).expect("couldn't create dir");
    WatcherDB::create(&watcher_path).unwrap();
    let watcher = WatcherDB::open_ro(&watcher_path, logger.clone()).unwrap();

    // Set up an empty ledger db.
    let ledger_db_path = state_tmp.path().join("ledger_db");
    std::fs::create_dir(&ledger_db_path).expect("couldn't create dir");
    LedgerDB::create(&ledger_db_path).unwrap();
    let ledger_db = LedgerDB::open(&ledger_db_path).unwrap();

    let ra_client = AttestClient::new("").expect("Could not create IAS client");
    let mut node = IngestServer::new(config, ra_client, db, watcher, ledger_db, logger);
    node.start().expect("couldn't start node");

    (node, state_tmp)
}

#[test_with_logger]
fn test_key_sharing_on_activate(logger: Logger) {
    let db_test_context = SqlRecoveryDbTestContext::new(logger.clone());

    let peer_indices = vec![0u16, 1u16, 2u16, 3u16, 4u16];

    let (node0, _node0dir) = make_node(
        0,
        peer_indices.iter().cloned(),
        db_test_context.get_db_instance(),
        logger.clone(),
    );
    let (node1, _node1dir) = make_node(
        1,
        peer_indices.iter().cloned(),
        db_test_context.get_db_instance(),
        logger.clone(),
    );
    let (node2, _node2dir) = make_node(
        2,
        peer_indices.iter().cloned(),
        db_test_context.get_db_instance(),
        logger.clone(),
    );
    let (node3, _node3dir) = make_node(
        3,
        peer_indices.iter().cloned(),
        db_test_context.get_db_instance(),
        logger.clone(),
    );
    let (node4, _node4dir) = make_node(
        4,
        peer_indices.iter().cloned(),
        db_test_context.get_db_instance(),
        logger.clone(),
    );

    let node0_key = node0.get_ingest_summary().get_ingress_pubkey().clone();
    let node1_key = node1.get_ingest_summary().get_ingress_pubkey().clone();
    let node2_key = node2.get_ingest_summary().get_ingress_pubkey().clone();
    let node3_key = node3.get_ingest_summary().get_ingress_pubkey().clone();
    let node4_key = node4.get_ingest_summary().get_ingress_pubkey().clone();

    assert_ne!(node0_key, node1_key);
    assert_ne!(node0_key, node2_key);
    assert_ne!(node0_key, node3_key);
    assert_ne!(node0_key, node4_key);

    // Give RPC etc. time to start
    std::thread::sleep(Duration::from_millis(1000));

    node0.activate().expect("node0 failed to activate");

    assert_eq!(
        node0_key,
        node0.get_ingest_summary().get_ingress_pubkey().clone(),
        "node0 key changed after activating, unexpectedly!"
    );

    let node1_key = node1.get_ingest_summary().get_ingress_pubkey().clone();
    let node2_key = node2.get_ingest_summary().get_ingress_pubkey().clone();
    let node3_key = node3.get_ingest_summary().get_ingress_pubkey().clone();
    let node4_key = node4.get_ingest_summary().get_ingress_pubkey().clone();

    assert_eq!(node0_key, node1_key);
    assert_eq!(node0_key, node2_key);
    assert_eq!(node0_key, node3_key);
    assert_eq!(node0_key, node4_key);

    assert!(
        !node1.activate().is_ok(),
        "node1 should not have been able to activate"
    );
    assert!(
        !node2.activate().is_ok(),
        "node2 should not have been able to activate"
    );
    assert!(
        !node3.activate().is_ok(),
        "node3 should not have been able to activate"
    );
    assert!(
        !node4.activate().is_ok(),
        "node4 should not have been able to activate"
    );

    // drop node0 and then bring it back
    drop(node0);
    let (node0, _node0dir) = make_node(
        0,
        peer_indices.iter().cloned(),
        db_test_context.get_db_instance(),
        logger.clone(),
    );
    assert_ne!(
        node0_key,
        node0.get_ingest_summary().get_ingress_pubkey().clone(),
        "node0 somehow got its old key back, unexpectedly! (tempdir was reused?)"
    );

    node1.activate().expect("node1 failed to activate!");
    assert_eq!(
        node0_key,
        node0.get_ingest_summary().get_ingress_pubkey().clone(),
        "node0 didn't get the old key back after node1 was activated"
    );
    assert!(
        !node0.activate().is_ok(),
        "node1 should not have been able to activate"
    );
    assert!(
        !node2.activate().is_ok(),
        "node2 should not have been able to activate"
    );
    assert!(
        !node3.activate().is_ok(),
        "node3 should not have been able to activate"
    );
    assert!(
        !node4.activate().is_ok(),
        "node4 should not have been able to activate"
    );

    let node1_key = node1.get_ingest_summary().get_ingress_pubkey().clone();
    let node2_key = node2.get_ingest_summary().get_ingress_pubkey().clone();
    let node3_key = node3.get_ingest_summary().get_ingress_pubkey().clone();
    let node4_key = node4.get_ingest_summary().get_ingress_pubkey().clone();

    assert_eq!(node0_key, node1_key);
    assert_eq!(node0_key, node2_key);
    assert_eq!(node0_key, node3_key);
    assert_eq!(node0_key, node4_key);
}
