// Copyright (c) 2018-2022 The MobileCoin Foundation

// This integration-level test mocks out consensus and tries to show
// that the users are able to recover their transactions.
//
// This is a rewrite of what was historically called test_ingest_view and was an
// end-to-end integration tests of ingest+view+fog-client.
// It exercises both the ingest enclave, and the fog-related crypto that makes
// its way into the client.

use mc_common::logger::{log, test_with_logger, Logger};
use mc_fog_ingest_client::FogIngestGrpcClient;
use mc_fog_ingest_server_test_utils::IngestServerTestHelper;
use mc_fog_test_infra::{mock_client::PassThroughViewClient, mock_users::UserPool};
use mc_util_test_helper::RngType;
use rand_core::RngCore;
use std::{sync::Arc, thread::sleep, time::Duration};

const NUM_USERS: usize = 5;
const NUM_PHASES: u8 = 3; // phases until account server goes down
const NUM_BLOCKS_PER_PHASE: usize = 6;
const NUM_TX_PER_BLOCK: u64 = 12;

#[test_with_logger]
fn test_ingest_sql(logger: Logger) {
    let mut trial_count = 0;
    mc_util_test_helper::run_with_several_seeds(|rng| {
        trial_count += 1;
        log::info!(logger, "Trial {}", trial_count);

        test_ingest_polling_integration(3130, rng, logger.clone());
    })
}

// Test that ingest server is working, in the sense that a client using
// the acct_crypto::polling logic recovers their transactions, even if the
// ingest node goes down sometimes.
fn test_ingest_polling_integration(base_port: u16, mut rng: RngType, logger: Logger) {
    // Count number of blocks that go through the system
    let mut block_index = 0u64;
    // Count number of txos that go through the system
    let mut num_txos = 0usize;

    // Generate random users
    let mut users = UserPool::new(NUM_USERS, &mut rng);

    // Set up an empty ledger DB and recovery DB.
    let mut helper = IngestServerTestHelper::new(base_port, logger.clone());

    // Create the pass-through view client object from test-infra, based on the
    // DB reader handle.
    let mut view_client = PassThroughViewClient::new(helper.recovery_db.clone());

    for phase in 0..NUM_PHASES {
        {
            log::info!(logger, "Phase {}/{}", phase + 1, NUM_PHASES);

            // In each phase we tear down Ingest and WatcherDB
            let phase_helper = IngestServerTestHelper::from_existing(
                base_port,
                helper.ledger_db_path.clone(),
                None,
                helper.db_test_context.clone(),
                logger.clone(),
            );
            let node = phase_helper.make_node(phase, phase..=phase);

            node.activate().expect("Could not activate ingest");

            // We are using the client to get the ingest pubkey.
            // Intentionally using a new grpc env.
            let grpcio_env = Arc::new(grpcio::EnvBuilder::new().build());
            let ingest_client = FogIngestGrpcClient::new(
                node.client_listen_uri,
                Duration::from_secs(1),
                grpcio_env.clone(),
                logger.clone(),
            );

            // Do a series of random blocks
            for block_count in 0..NUM_BLOCKS_PER_PHASE {
                log::info!(logger, "Block {}/{}", block_count + 1, NUM_BLOCKS_PER_PHASE);

                let num_tx = gen_num_tx_for_block(&mut rng);
                num_txos = mc_fog_test_infra::test_block(
                    &mut users,
                    &ingest_client,
                    &mut view_client,
                    // add each test_block to the watcher for timestamp.
                    phase_helper.watcher.clone(),
                    &mut helper.ledger,
                    &mut rng,
                    num_tx,
                    block_index,
                    num_txos,
                );
                block_index += 1;
                mc_fog_test_infra::test_polling_recovery(&mut users, &mut view_client);
            }
        }

        // grpcio detaches all its threads and does not join them :(
        // we opened a PR here: https://github.com/tikv/grpc-rs/pull/455
        // in the meantime we can just sleep after grpcio env and all related
        // objects have been destroyed, and hope that those 6 threads see the
        // shutdown requests within 1 second.
        sleep(Duration::from_millis(1000));
    }
}

// Function for generating the random number of txs to put in a block
fn gen_num_tx_for_block(rng: &mut impl RngCore) -> usize {
    loop {
        let n = (rng.next_u64() % NUM_TX_PER_BLOCK as u64) as usize;
        if n != 0 {
            break n;
        }
    }
}
