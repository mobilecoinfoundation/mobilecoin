// Copyright (c) 2018-2021 The MobileCoin Foundation

use maplit::btreeset;
use mc_attest_net::{Client as AttestClient, RaClient};
use mc_common::logger::{test_with_logger, Logger};
use mc_fog_ingest_server::{
    server::{IngestServer, IngestServerConfig},
    state_file::StateFile,
};
use mc_fog_sql_recovery_db::test_utils::SqlRecoveryDbTestContext;
use mc_fog_test_infra::get_enclave_path;
use mc_fog_uri::{FogIngestUri, IngestPeerUri};
use mc_ledger_db::LedgerDB;
use mc_util_uri::ConnectionUri;
use mc_watcher::watcher_db::WatcherDB;
use std::{str::FromStr, time::Duration};
use tempdir::TempDir;

const OMAP_CAPACITY: u64 = 256;

#[test_with_logger]
fn test_ingest_sealed_key_recovery(logger: Logger) {
    let db_test_context = SqlRecoveryDbTestContext::new(logger.clone());

    let db = db_test_context.get_db_instance();

    let base_port: u16 = 3457;

    let igp_uri =
        IngestPeerUri::from_str(&format!("insecure-igp://127.0.0.1:{}/", base_port + 5)).unwrap();
    let local_node_id = igp_uri.responder_id().unwrap();

    let state_file_tmp =
        TempDir::new("ingest_state").expect("Could not make tempdir for ingest state");
    let state_file = state_file_tmp.path().join("mc-ingest-state");

    let config = IngestServerConfig {
        ias_spid: Default::default(),
        local_node_id: local_node_id.clone(),
        client_listen_uri: FogIngestUri::from_str(&format!(
            "insecure-fog-ingest://0.0.0.0:{}/",
            base_port + 4
        ))
        .unwrap(),
        peer_listen_uri: igp_uri.clone(),
        peers: btreeset![igp_uri.clone()],
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
    let db_tmp = TempDir::new("wallet_db").expect("Could not make tempdir for wallet db");
    WatcherDB::create(db_tmp.path()).unwrap();
    let watcher = WatcherDB::open_ro(db_tmp.path(), logger.clone()).unwrap();

    // Set up an empty ledger db.
    let ledger_db_path = TempDir::new("ledger_db").expect("Could not make tempdir for ledger db");
    LedgerDB::create(ledger_db_path.path()).unwrap();
    let ledger_db = LedgerDB::open(ledger_db_path.path()).unwrap();

    let ra_client = AttestClient::new("").expect("Could not create IAS client");
    let node = IngestServer::new(
        config.clone(),
        ra_client,
        db.clone(),
        watcher.clone(),
        ledger_db.clone(),
        logger.clone(),
    );

    let summary = node.get_ingest_summary();

    drop(node);

    let ra_client = AttestClient::new("").expect("Could not create IAS client");
    let node = IngestServer::new(
        config.clone(),
        ra_client,
        db.clone(),
        watcher.clone(),
        ledger_db.clone(),
        logger.clone(),
    );

    let summary2 = node.get_ingest_summary();

    assert_eq!(
        summary.get_ingress_pubkey(),
        summary2.get_ingress_pubkey(),
        "Failed to recover the same ingress key from restart with keyfile!"
    );

    drop(node);

    drop(std::fs::remove_file(&state_file));

    let ra_client = AttestClient::new("").expect("Could not create IAS client");
    let node = IngestServer::new(
        config.clone(),
        ra_client,
        db.clone(),
        watcher.clone(),
        ledger_db.clone(),
        logger.clone(),
    );

    let summary3 = node.get_ingest_summary();
    assert_ne!(
        summary.get_ingress_pubkey(),
        summary3.get_ingress_pubkey(),
        "Ingress private key was successfully recovered when it should not have been!"
    );
}
