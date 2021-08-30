// Copyright (c) 2018-2021 The MobileCoin Foundation

// This integration-level test mocks out consensus and tries to show
// that the users are able to recover their transactions.
//
// This is a rewrite of what was historically called test_ingest_view and was an
// end-to-end integration tests of ingest+view+fog-client.
// It exercises both the ingest enclave, and the fog-related crypto that makes
// its way into the client.

use maplit::btreeset;
use mc_attest_net::{Client as AttestClient, RaClient};
use mc_common::logger::{log, test_with_logger, Logger};
use mc_fog_ingest_client::FogIngestGrpcClient;
use mc_fog_ingest_server::{
    error::IngestServiceError,
    server::{IngestServer, IngestServerConfig},
};
use mc_fog_recovery_db_iface::{RecoveryDb, ReportDb};
use mc_fog_sql_recovery_db::test_utils::SqlRecoveryDbTestContext;
use mc_fog_test_infra::{
    get_enclave_path, mock_client::PassThroughViewClient, mock_users::UserPool,
};
use mc_fog_uri::{FogIngestUri, IngestPeerUri};
use mc_ledger_db::LedgerDB;
use mc_util_uri::ConnectionUri;
use mc_watcher::watcher_db::WatcherDB;
use rand_core::RngCore;
use std::{str::FromStr, sync::Arc, time::Duration};
use tempdir::TempDir;
use url::Url;

const NUM_USERS: usize = 5;
const NUM_PHASES: usize = 3; // phase = until account server goes down
const NUM_BLOCKS_PER_PHASE: usize = 6;
const NUM_TX_PER_BLOCK: u64 = 12;
const OMAP_CAPACITY: u64 = 256; // must be a power of two larger than NUM_USERS

// Function for generating the random number of txs to put in a block
fn gen_num_tx_for_block<T: RngCore>(rng: &mut T) -> usize {
    loop {
        let n = (rng.next_u64() % NUM_TX_PER_BLOCK as u64) as usize;
        if n != 0 {
            break n;
        }
    }
}

// Test that ingest server is working, in the sense that a client using
// the acct_crypto::polling logic recovers their transactions, even if the
// ingest node goes down sometimes.
fn test_ingest_polling_integration<A, DB>(
    mut rng: mc_util_test_helper::RngType,
    db: DB,
    base_port: u16,
    logger: Logger,
) where
    A: RaClient + 'static,
    DB: RecoveryDb + ReportDb + Clone + Send + Sync + 'static,
    IngestServiceError: From<<DB as RecoveryDb>::Error>,
{
    // Count number of blocks that go through the system
    let mut block_index = 0u64;
    // Count number of txos that go through the system
    let mut num_txos = 0usize;

    // Generate random users
    let mut users = UserPool::new(NUM_USERS, &mut rng);

    // Create the pass-through view client object from test-infra, based on the
    // DB reader handle.
    let mut view_client = PassThroughViewClient::new(db.clone());

    // Set up an empty ledger db.
    let ledger_db_path = TempDir::new("ledger_db").expect("Could not make tempdir for ledger db");
    LedgerDB::create(ledger_db_path.path()).unwrap();
    let mut ledger_db = LedgerDB::open(ledger_db_path.path()).unwrap();

    for phase_count in 0..NUM_PHASES {
        {
            log::info!(logger, "Phase {}/{}", phase_count + 1, NUM_PHASES);

            // First make grpcio env
            // Note: DONT move this outside the phase_count loop or you will have a bad time
            // It needs to be destroyed when the ingest server is destroyed.
            let grpcio_env = Arc::new(grpcio::EnvBuilder::new().build());

            // Set up the Watcher DB - create a new watcher DB for each phase
            let db_tmp = TempDir::new("watcher_db").expect("Could not make tempdir for watcher db");
            WatcherDB::create(db_tmp.path()).unwrap();
            let src_urls = vec![Url::parse("http://www.my_url1.com").unwrap()];
            let watcher = WatcherDB::open_rw(db_tmp.path(), &src_urls, logger.clone()).unwrap();

            // In each phase we tear down ingest
            let igp_uri =
                IngestPeerUri::from_str(&format!("insecure-igp://0.0.0.0:{}/", base_port + 5))
                    .unwrap();
            let local_node_id = igp_uri.responder_id().unwrap();

            let _ingest_server = {
                let config = IngestServerConfig {
                    ias_spid: Default::default(),
                    local_node_id,
                    client_listen_uri: FogIngestUri::from_str(&format!(
                        "insecure-fog-ingest://0.0.0.0:{}/",
                        base_port + 4
                    ))
                    .unwrap(),
                    peer_listen_uri: igp_uri.clone(),
                    peers: btreeset![igp_uri.clone()],
                    fog_report_id: Default::default(),
                    max_transactions: 10_000,
                    pubkey_expiry_window: 4,
                    peer_checkup_period: None,
                    watcher_timeout: Duration::default(),
                    state_file: None,
                    omap_capacity: OMAP_CAPACITY,
                    enclave_path: get_enclave_path(mc_fog_ingest_enclave::ENCLAVE_FILE),
                };

                let ra_client = A::new("").expect("Could not create IAS client");
                let mut node = IngestServer::new(
                    config,
                    ra_client,
                    db.clone(),
                    watcher.clone(),
                    ledger_db.clone(),
                    logger.clone(),
                );
                node.start().expect("Could not start Ingest Service");
                node.activate().expect("Could not activate ingest");
                node
            };

            // We are using the client to get the ingest pubkey
            let ingest_client = FogIngestGrpcClient::new(
                FogIngestUri::from_str(&format!(
                    "insecure-fog-ingest://127.0.0.1:{}/",
                    base_port + 4
                ))
                .unwrap(),
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
                    watcher.clone(), // add each test_block to the watcher for timestamp
                    &mut ledger_db,
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
        std::thread::sleep(std::time::Duration::from_millis(1000));
    }
}

#[test_with_logger]
fn test_ingest_sql(logger: Logger) {
    let mut trial_count = 0;
    mc_util_test_helper::run_with_several_seeds(|rng| {
        trial_count += 1;
        log::info!(logger, "Trial {}", trial_count);

        let db_test_context = SqlRecoveryDbTestContext::new(logger.clone());
        let db = db_test_context.get_db_instance();

        test_ingest_polling_integration::<AttestClient, _>(rng, db, 3230, logger.clone());
    })
}
