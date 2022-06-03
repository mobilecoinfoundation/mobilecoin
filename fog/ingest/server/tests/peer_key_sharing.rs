// Copyright (c) 2018-2022 The MobileCoin Foundation

// This integration-level test checks that a backup ingest node will
// use the private key from its primary.

use mc_common::logger::{log, test_with_logger, Logger};
use mc_fog_ingest_client::FogIngestGrpcClient;
use mc_fog_ingest_server_test_utils::IngestServerTestHelper;
use mc_fog_sql_recovery_db::test_utils::SqlRecoveryDbTestContext;
use std::{sync::Arc, thread::sleep, time::Duration};

const NUM_PHASES: usize = 3; // phase = until account server goes down
const BASE_PORT: u16 = 3240;

/// Run the ingest validation test using sql recovery db
#[test_with_logger]
fn test_ingest_pool_sql(logger: Logger) {
    let db_test_context = Arc::new(SqlRecoveryDbTestContext::new(logger.clone()));

    for trial_count in 1..3 {
        log::info!(logger, "Trial {}", trial_count);

        test_ingest_pool_integration(db_test_context.clone(), logger.clone())
    }
}

// Test that ingest server key backup is working, in the sense that if we
// start an ingest server, then run another in backup mode pointing at the
// first, the backup and primary pubkeys will be identical.
fn test_ingest_pool_integration(db_test_context: Arc<SqlRecoveryDbTestContext>, logger: Logger) {
    // In each phase we tear down and restart ingest
    for phase_count in 0..NUM_PHASES {
        {
            log::info!(logger, "Phase {}/{}", phase_count + 1, NUM_PHASES);

            // Create an ingest server with new ledger and watcher DBs, while reusing
            // db_test_context.
            let primary_helper = IngestServerTestHelper::from_existing(
                BASE_PORT,
                None,
                None,
                db_test_context.clone(),
                logger.clone(),
            );
            let primary = primary_helper.make_node(1, 1..=1);
            primary
                .activate()
                .expect("Could not activate primary Ingest server");

            sleep(std::time::Duration::from_millis(1000));

            let backup_helper = IngestServerTestHelper::from_existing(
                BASE_PORT,
                None,
                None,
                db_test_context.clone(),
                logger.clone(),
            );
            let mut backup = backup_helper.make_node(3, 3..=3);
            // Sync key from primary.
            backup
                .sync_keys_from_remote(&primary.peer_listen_uri)
                .expect("failed syncing key from primary");

            // Note: DONT move this outside the phase_count loop or you will have a bad time
            // It needs to be destroyed when the ingest server is destroyed.
            let env = Arc::new(
                grpcio::EnvBuilder::new()
                    .name_prefix("test_peer_key_sharing")
                    .build(),
            );

            // We are submitting the blocks to ingest over the grpc api
            let primary_ingest_client = FogIngestGrpcClient::new(
                primary.client_listen_uri,
                Duration::from_millis(100),
                env.clone(),
                logger.clone(),
            );
            let backup_ingest_client = FogIngestGrpcClient::new(
                backup.client_listen_uri,
                Duration::from_millis(100),
                env.clone(),
                logger.clone(),
            );

            // get the pubkey from the primary, then poll the backup and see
            // it it gets the same pubkey

            let primary_pubkey = primary_ingest_client
                .get_status()
                .unwrap()
                .take_ingress_pubkey();
            let mut backup_pubkey = backup_ingest_client
                .get_status()
                .unwrap()
                .take_ingress_pubkey();

            for _ in 0..30 {
                if primary_pubkey == backup_pubkey {
                    break;
                }

                sleep(std::time::Duration::from_millis(1000));

                backup_pubkey = backup_ingest_client
                    .get_status()
                    .unwrap()
                    .take_ingress_pubkey();
            }

            assert_eq!(primary_pubkey, backup_pubkey);

            // Now, let's call "new_keys" on the backup, which should make it pick new keys
            loop {
                // We are racing the primary here, so we'll use retries
                let mut tries = 3;
                backup_ingest_client.new_keys().unwrap();

                // Confirm that the key changed
                backup_pubkey = backup_ingest_client
                    .get_status()
                    .unwrap()
                    .take_ingress_pubkey();
                if primary_pubkey != backup_pubkey {
                    break;
                }
                tries -= 1;
                if tries == 0 {
                    assert_ne!(primary_pubkey, backup_pubkey, "new_keys is not working");
                }
            }

            // Confirm that after at most 30 seconds, the backup is changed (by the active
            // server) back to primary key
            for _ in 0..30 {
                if primary_pubkey == backup_pubkey {
                    break;
                }

                sleep(std::time::Duration::from_millis(1000));

                backup_pubkey = backup_ingest_client
                    .get_status()
                    .unwrap()
                    .take_ingress_pubkey();
            }

            // Lets confirm that new_keys doesn't work on the primary
            let result = primary_ingest_client.new_keys();
            assert!(
                result.is_err(),
                "new_keys should return an error code when the server is active: {:?}",
                result
            );
            let final_primary_key = primary_ingest_client
                .get_status()
                .unwrap()
                .take_ingress_pubkey();
            assert_eq!(
                primary_pubkey, final_primary_key,
                "active server's pubkey should not have changed"
            );
        }

        // grpcio detaches all its threads and does not join them :(
        // we opened a PR here: https://github.com/tikv/grpc-rs/pull/455
        // in the meantime we can just sleep after grpcio env and all related
        // objects have been destroyed, and hope that those 6 threads see the
        // shutdown requests within 1 second.
        sleep(std::time::Duration::from_millis(1000));
    }
}
