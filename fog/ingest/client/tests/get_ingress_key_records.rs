// Copyright (c) 2018-2022 The MobileCoin Foundation

use assert_cmd::Command;
use maplit::btreeset;
use mc_api::external;
use mc_attest_net::{Client as AttestClient, RaClient};
use mc_common::logger::{test_with_logger, Logger};
use mc_crypto_keys::CompressedRistrettoPublic;
use mc_fog_ingest_server::server::{IngestServer, IngestServerConfig};
use mc_fog_recovery_db_iface::RecoveryDb;
use mc_fog_sql_recovery_db::{test_utils::SqlRecoveryDbTestContext, SqlRecoveryDb};
use mc_fog_test_infra::get_enclave_path;
use mc_fog_uri::{ConnectionUri, FogIngestUri, IngestPeerUri};
use mc_ledger_db::LedgerDB;
use mc_util_from_random::FromRandom;
use mc_watcher::watcher_db::WatcherDB;
use predicates::prelude::*;
use rand::{rngs::StdRng, SeedableRng};
use std::{str::FromStr, time::Duration};
use tempdir::TempDir;

const OMAP_CAPACITY: u64 = 256;
const BASE_PORT: u32 = 3220;

#[test_with_logger]
fn test_get_ingress_key_records(logger: Logger) {
    let ingest_server_set_up_data = set_up_ingest_servers(logger);

    // Test that the command excludes retired and lost keys by default.
    {
        let mut cmd = Command::cargo_bin("fog_ingest_client").unwrap();
        cmd.arg("--uri")
            .arg(&ingest_server_set_up_data.ingest_server_client_uri)
            .arg("get-ingress-public-key-records")
            .arg("--start-block-at-least")
            .arg("0")
            .assert()
            .success()
            .stdout(predicate::str::contains(hex::encode(
                &ingest_server_set_up_data.active_ingress_pubkey.get_data(),
            )))
            .stdout(
                predicate::str::contains(hex::encode(
                    &ingest_server_set_up_data.retired_ingress_pubkey.get_data(),
                ))
                .not(),
            )
            .stdout(
                predicate::str::contains(hex::encode(
                    &ingest_server_set_up_data.lost_ingress_pubkey.get_data(),
                ))
                .not(),
            );
    }
    // Test that the "--include-lost" option includes active and lost keys.
    {
        let mut cmd = Command::cargo_bin("fog_ingest_client").unwrap();
        cmd.arg("--uri")
            .arg(&ingest_server_set_up_data.ingest_server_client_uri)
            .arg("get-ingress-public-key-records")
            .arg("--start-block-at-least")
            .arg("0")
            .arg("--include-lost")
            .assert()
            .success()
            .stdout(predicate::str::contains(hex::encode(
                &ingest_server_set_up_data.active_ingress_pubkey.get_data(),
            )))
            .stdout(
                predicate::str::contains(hex::encode(
                    &ingest_server_set_up_data.retired_ingress_pubkey.get_data(),
                ))
                .not(),
            )
            .stdout(predicate::str::contains(hex::encode(
                &ingest_server_set_up_data.lost_ingress_pubkey.get_data(),
            )));
    }

    // Test that the "--include-retired" option includes active and retired keys.
    {
        let mut cmd = Command::cargo_bin("fog_ingest_client").unwrap();
        cmd.arg("--uri")
            .arg(&ingest_server_set_up_data.ingest_server_client_uri)
            .arg("get-ingress-public-key-records")
            .arg("--start-block-at-least")
            .arg("0")
            .arg("--include-retired")
            .assert()
            .success()
            .stdout(predicate::str::contains(hex::encode(
                &ingest_server_set_up_data.active_ingress_pubkey.get_data(),
            )))
            .stdout(predicate::str::contains(hex::encode(
                &ingest_server_set_up_data.retired_ingress_pubkey.get_data(),
            )))
            .stdout(
                predicate::str::contains(hex::encode(
                    &ingest_server_set_up_data.lost_ingress_pubkey.get_data(),
                ))
                .not(),
            );
    }

    // Test that the "--include-lost" and "--include-retired" options
    // include active, retired, and lost keys.
    {
        let mut cmd = Command::cargo_bin("fog_ingest_client").unwrap();
        cmd.arg("--uri")
            .arg(&ingest_server_set_up_data.ingest_server_client_uri)
            .arg("get-ingress-public-key-records")
            .arg("--start-block-at-least")
            .arg("0")
            .arg("--include-lost")
            .arg("--include-retired")
            .assert()
            .success()
            .stdout(predicate::str::contains(hex::encode(
                &ingest_server_set_up_data.active_ingress_pubkey.get_data(),
            )))
            .stdout(predicate::str::contains(hex::encode(
                &ingest_server_set_up_data.retired_ingress_pubkey.get_data(),
            )))
            .stdout(predicate::str::contains(hex::encode(
                &ingest_server_set_up_data.lost_ingress_pubkey.get_data(),
            )));
    }
    // Test that the "--start-block-at-least" option works correctly.
    // This should exclude the retired ingress key because its start block is
    // 123.
    {
        let mut cmd = Command::cargo_bin("fog_ingest_client").unwrap();
        cmd.arg("--uri")
            .arg(&ingest_server_set_up_data.ingest_server_client_uri)
            .arg("get-ingress-public-key-records")
            .arg("--start-block-at-least")
            .arg("200")
            .arg("--include-lost")
            .arg("--include-retired")
            .assert()
            .success()
            .stdout(predicate::str::contains(hex::encode(
                &ingest_server_set_up_data.active_ingress_pubkey.get_data(),
            )))
            .stdout(
                predicate::str::contains(hex::encode(
                    &ingest_server_set_up_data.retired_ingress_pubkey.get_data(),
                ))
                .not(),
            )
            .stdout(predicate::str::contains(hex::encode(
                &ingest_server_set_up_data.lost_ingress_pubkey.get_data(),
            )));
    }
}

/// Contains data pertaining to the set up of the ingest server and the ingress
/// public keys.
struct IngestServerSetUpData {
    /// The ingest server that handles incoming client requests.
    _ingest_server: IngestServer<AttestClient, SqlRecoveryDb>,
    /// The db context that is used to created the RecoveryDb. This must be
    /// included here to ensure that the RecoveryDb is not dropped at the end
    /// of the set up method.
    _db_test_context: SqlRecoveryDbTestContext,
    /// The url that can be used to address the ingest server.
    ingest_server_client_uri: String,
    /// An ingress public key that has been retired.
    retired_ingress_pubkey: external::CompressedRistretto,
    /// An ingress public key that has been lost.
    lost_ingress_pubkey: external::CompressedRistretto,
    /// The ingest server's active ingress public key.
    active_ingress_pubkey: external::CompressedRistretto,
}

fn set_up_ingest_servers(logger: Logger) -> IngestServerSetUpData {
    let db_test_context = SqlRecoveryDbTestContext::new(logger.clone());
    let db = db_test_context.get_db_instance();

    let mut rng: StdRng = SeedableRng::from_seed([123u8; 32]);

    let ingress_key1 = CompressedRistrettoPublic::from_random(&mut rng);
    db.new_ingress_key(&ingress_key1, 123).unwrap();
    let ingress_key2 = CompressedRistrettoPublic::from_random(&mut rng);
    db.new_ingress_key(&ingress_key2, 456).unwrap();
    let ingress_key3 = CompressedRistrettoPublic::from_random(&mut rng);
    db.new_ingress_key(&ingress_key3, 789).unwrap();

    db.retire_ingress_key(&ingress_key1, true).unwrap();
    db.report_lost_ingress_key(ingress_key2).unwrap();

    let ingest_server_client_uri = &format!("insecure-fog-ingest://0.0.0.0:{}/", BASE_PORT + 4);
    let ingest_server = {
        let igp_uri =
            IngestPeerUri::from_str(&format!("insecure-igp://127.0.0.1:{}/", BASE_PORT + 5))
                .unwrap();
        let local_node_id = igp_uri.responder_id().unwrap();

        let config = IngestServerConfig {
            ias_spid: Default::default(),
            local_node_id,
            client_listen_uri: FogIngestUri::from_str(ingest_server_client_uri).unwrap(),
            peer_listen_uri: igp_uri.clone(),
            peers: btreeset![igp_uri],
            fog_report_id: Default::default(),
            max_transactions: 10_000,
            pubkey_expiry_window: 100,
            peer_checkup_period: None,
            watcher_timeout: Duration::default(),
            state_file: None,
            enclave_path: get_enclave_path(mc_fog_ingest_enclave::ENCLAVE_FILE),
            omap_capacity: OMAP_CAPACITY,
        };

        // Set up the Watcher DB - create a new watcher DB for each phase
        let db_tmp = TempDir::new("wallet_db").expect("Could not make tempdir for wallet db");
        WatcherDB::create(db_tmp.path()).unwrap();
        let watcher = WatcherDB::open_ro(db_tmp.path(), logger.clone()).unwrap();

        // Set up an empty ledger db.
        let ledger_db_path =
            TempDir::new("ledger_db").expect("Could not make tempdir for ledger db");
        LedgerDB::create(ledger_db_path.path()).unwrap();
        let ledger_db = LedgerDB::open(ledger_db_path.path()).unwrap();

        let ra_client = AttestClient::new("").expect("Could not create IAS client");
        let mut node = IngestServer::new(config, ra_client, db, watcher, ledger_db, logger.clone());
        node.start().expect("Could not start Ingest Service");

        node
    };

    std::thread::sleep(std::time::Duration::from_millis(1000));

    IngestServerSetUpData {
        _ingest_server: ingest_server,
        _db_test_context: db_test_context,
        ingest_server_client_uri: ingest_server_client_uri.to_owned(),
        retired_ingress_pubkey: external::CompressedRistretto::from(&ingress_key1),
        lost_ingress_pubkey: external::CompressedRistretto::from(&ingress_key2),
        active_ingress_pubkey: external::CompressedRistretto::from(&ingress_key3),
    }
}
