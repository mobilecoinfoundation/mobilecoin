// Copyright (c) 2018-2022 The MobileCoin Foundation

#![deny(missing_docs)]

//! This load test creates an ingest server, adds users to it, and adds blocks,
//! creating one block every 5 seconds.
//!
//! It attempts to measure:
//! - How many Txos per block can we add while still processing the block every
//!   5 seconds?
//!
//! FIXME: Fog-300
//! Processing Txos gets slower as the map gets more full, the load test
//! should be updated to measure this effect.

use clap::Parser;
use grpcio::{ChannelBuilder, Error as GrpcioError};
use mc_account_keys::AccountKey;
use mc_blockchain_test_utils::get_blocks;
use mc_blockchain_types::{BlockSignature, BlockVersion};
use mc_common::logger::{log, Logger};
use mc_crypto_keys::Ed25519Pair;
use mc_crypto_rand::McRng;
use mc_fog_ingest_client::FogIngestGrpcClient;
use mc_fog_load_testing::get_bin_path;
use mc_fog_recovery_db_iface::RecoveryDb;
use mc_fog_sql_recovery_db::test_utils::SqlRecoveryDbTestContext;
use mc_fog_uri::{ConnectionUri, FogIngestUri, IngestPeerUri};
use mc_ledger_db::{test_utils::initialize_ledger, Ledger, LedgerDB};
use mc_util_from_random::FromRandom;
use mc_util_grpc::{admin_grpc::AdminApiClient, ConnectionUriGrpcioChannel, Empty};
use mc_util_uri::AdminUri;
use mc_watcher::watcher_db::WatcherDB;
use rand::thread_rng;
use retry::{delay, retry, OperationResult};
use std::{
    path::Path,
    str::FromStr,
    sync::Arc,
    time::{Duration, Instant},
};
use tempdir::TempDir;

// Compute mean and std_dev of timings
#[derive(Default, Clone)]
struct BasicTimingStats {
    pub num_samples: usize,
    pub mean: Duration,
    pub std_dev: Duration,
}

impl core::fmt::Display for BasicTimingStats {
    fn fmt(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(
            formatter,
            "num samples: {}, avg: {} ms +/- {} ms",
            self.num_samples,
            self.mean.as_secs_f64() * 1000f64,
            self.std_dev.as_secs_f64() * 1000f64
        )
    }
}

// Take a series of durations, and compute their mean and standard deviation
fn compute_basic_stats(data: &[Duration], logger: &Logger) -> BasicTimingStats {
    let num_samples = data.len();

    let mean = data.iter().fold(0f64, |l, r| l + r.as_secs_f64()) / num_samples as f64;
    let variance = data
        .iter()
        .fold(0f64, |l, r| l + (r.as_secs_f64() - mean).powi(2))
        / num_samples as f64;
    let std_dev = variance.sqrt();

    log::debug!(
        logger,
        "mean sec = {}, variance sec = {}, std_dev sec = {}",
        mean,
        variance,
        std_dev
    );

    BasicTimingStats {
        num_samples,
        mean: Duration::from_secs_f64(mean),
        std_dev: Duration::from_secs_f64(std_dev),
    }
}

// Parameters of interest to twiddle for purposes of load testing
#[derive(Default, Clone)]
struct TestParams {
    user_capacity: u64,
}

impl core::fmt::Display for TestParams {
    fn fmt(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(formatter, "{{ user_capacity: {} }}", self.user_capacity,)
    }
}

// The results of a load test
#[derive(Default, Clone)]
struct TestResult {
    params: TestParams,
    num_txs_added: usize,
    process_tx_timings: BasicTimingStats,
}

impl core::fmt::Display for TestResult {
    fn fmt(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(
            formatter,
            "{}:\nProcess {} txos: {}",
            self.params, self.num_txs_added, self.process_tx_timings,
        )
    }
}

/// RAII gaurd for a child process, which kills the child on drop.
pub struct AutoKillChild(pub std::process::Child);

impl AutoKillChild {
    /// Assert that the child process is still alive.
    ///
    /// Panics:
    ///  * If the process stopped unexpectedly.
    ///  * If there is an error while getting the process' status.
    pub fn assert_not_stopped(&mut self) {
        match self.0.try_wait() {
            Ok(Some(stat)) => {
                panic!("child stopped unexpectedly: status: {}", stat)
            }
            Ok(None) => {}
            Err(err) => {
                panic!("error getting child status: {}", err)
            }
        }
    }
}

impl Drop for AutoKillChild {
    fn drop(&mut self) {
        if let Err(err) = self.0.kill() {
            // Invalid input means the process is already dead, and we don't have to kill
            // it. Anything else means that killing it failed somehow
            if err.kind() != std::io::ErrorKind::InvalidInput {
                panic!("Could not send SIGKILL to child: {}", err)
            }
        }

        self.0.wait().expect("Could not reap child");
    }
}

fn load_test(ingest_server_binary: &Path, test_params: TestParams, logger: Logger) -> TestResult {
    let mut test_results = TestResult {
        params: test_params.clone(),
        ..Default::default()
    };

    let signer = Ed25519Pair::from_random(&mut thread_rng());

    {
        // First make grpcio env
        // Note: This needs to be destroyed when the ingest server is destroyed,
        // then we have to sleep, see end of this scope
        let grpcio_env = Arc::new(grpcio::EnvBuilder::new().build());

        let base_port = 3050;
        let ingest_client_port = base_port + 4;
        let ingest_peer_port = base_port + 5;
        let client_listen_uri = FogIngestUri::from_str(&format!(
            "insecure-fog-ingest://127.0.0.1:{}",
            ingest_client_port
        ))
        .unwrap();
        let peer_listen_uri =
            IngestPeerUri::from_str(&format!("insecure-igp://127.0.0.1:{}", ingest_peer_port))
                .unwrap();
        let local_node_id = peer_listen_uri.responder_id().unwrap();

        let admin_listen_uri = AdminUri::from_str("insecure-mca://127.0.0.1:8003/").unwrap();

        // Set up the Recovery DB
        let db_test_context = SqlRecoveryDbTestContext::new(logger.clone());
        let recovery_db = db_test_context.get_db_instance();

        // Make recovery db available via env var
        std::env::set_var("DATABASE_URL", db_test_context.db_url());

        // Set up the Watcher DB
        let watcher_db_path =
            TempDir::new("wallet_db").expect("Could not make tempdir for wallet db");
        WatcherDB::create(watcher_db_path.path()).unwrap();
        let watcher = WatcherDB::open_rw(
            watcher_db_path.path(),
            &["http://bash.org".parse().unwrap()],
            logger.clone(),
        )
        .unwrap();

        // Set up a fresh ledger db.
        let ledger_db_path =
            TempDir::new("ledger_db").expect("Could not make tempdir for ledger db");
        LedgerDB::create(ledger_db_path.path()).unwrap();
        let mut ledger_db = LedgerDB::open(ledger_db_path.path()).unwrap();

        let block_version = BlockVersion::ZERO;

        initialize_ledger(
            block_version,
            &mut ledger_db,
            1u64,
            &AccountKey::random(&mut McRng {}),
            &mut McRng {},
        );

        // Dir for state file
        let state_file_dir =
            TempDir::new("state_file").expect("Could not make tempdir for state file");
        let mut state_file_path = state_file_dir.path().to_path_buf();
        state_file_path.push(".mc-fog-ingest-state");

        // Start ingest server.
        // Note: we omit IAS API KEY, but maybe we should take from env or something
        // Maybe we should take ias-spid from env also
        let mut command = std::process::Command::new(ingest_server_binary.to_str().unwrap());
        command
            .args(&["--ledger-db", ledger_db_path.path().to_str().unwrap()])
            .args(&["--watcher-db", watcher_db_path.path().to_str().unwrap()])
            .args(&["--client-listen-uri", &client_listen_uri.to_string()])
            .args(&["--peer-listen-uri", &peer_listen_uri.to_string()])
            .args(&["--ias-spid", &"0".repeat(32)])
            .args(&["--ias-api-key", &"0".repeat(32)])
            .args(&["--local-node-id", &local_node_id.to_string()])
            .args(&["--peers", &peer_listen_uri.to_string()])
            .args(&["--state-file", state_file_path.to_str().unwrap()])
            .args(&["--admin-listen-uri", &admin_listen_uri.to_string()])
            .args(&["--user-capacity", &test_params.user_capacity.to_string()]);

        log::info!(logger, "Spawning ingest server: {:?}", command);

        let mut ingest_server =
            AutoKillChild(command.spawn().expect("Could not spawn ingest server"));

        // Wait for admin api to be reachable
        {
            let admin_client = {
                let ch = ChannelBuilder::new(grpcio_env.clone())
                    .connect_to_uri(&admin_listen_uri, &logger);
                AdminApiClient::new(ch)
            };

            let info = retry(delay::Fixed::from_millis(5000).map(delay::jitter), || {
                ingest_server.assert_not_stopped();

                match admin_client.get_info(&Empty::default()) {
                    Ok(info) => OperationResult::Ok(info),
                    Err(GrpcioError::RpcFailure(err)) => {
                        log::info!(&logger, "Waiting for ingest server to become available");
                        OperationResult::Retry(GrpcioError::RpcFailure(err))
                    }
                    Err(err) => OperationResult::Err(err),
                }
            })
            .expect("Could not connect to ingest server");

            log::info!(
                logger,
                "Connected to server:\nbuild_info: {}\nconfig_json: {}",
                info.build_info_json,
                info.config_json
            );
        }

        // Tell server to activate
        {
            let ingest_client = FogIngestGrpcClient::new(
                client_listen_uri,
                Duration::from_secs(30),
                grpcio_env,
                logger.clone(),
            );
            ingest_client
                .activate()
                .expect("Could not activate ingest server");
            std::thread::sleep(std::time::Duration::from_millis(10));
            ingest_server.assert_not_stopped();
        }

        // Measure process_txs load
        {
            // How many txos we add at a time
            const CHUNK_SIZE: usize = 250;
            // How many repetitions we do
            const REPETITIONS: usize = 100;

            log::info!(logger, "Generating {} random blocks", REPETITIONS);
            let num_blocks = ledger_db.num_blocks().unwrap();
            let last_block = ledger_db.get_block(num_blocks - 1).unwrap();
            assert_eq!(
                last_block.cumulative_txo_count,
                ledger_db.num_txos().unwrap()
            );

            let results = get_blocks(
                block_version,
                REPETITIONS,
                CHUNK_SIZE,
                1,
                CHUNK_SIZE,
                1 << 20,
                last_block,
                &mut McRng {},
            );

            log::info!(
                logger,
                "Adding blocks with {} Txos ({} reptitions)",
                CHUNK_SIZE,
                REPETITIONS
            );
            let mut timings = Vec::<Duration>::with_capacity(REPETITIONS);
            for block_data in results {
                let initial_highest_known_block_index = recovery_db
                    .get_highest_known_block_index()
                    .expect("Getting num blocks failed");

                let start = Instant::now();
                ledger_db
                    .append_block_data(&block_data)
                    .expect("Adding block failed");

                let block = block_data.block();
                // Add the timestamp information to watcher for this block index - note watcher
                // does not allow signatures for block 0.
                if block.index > 0 {
                    let mut block_signature =
                        BlockSignature::from_block_and_keypair(block, &signer)
                            .expect("Could not create block signature from keypair");
                    block_signature.set_signed_at(block.index);
                    for src_url in watcher.get_config_urls().unwrap().iter() {
                        watcher
                            .add_block_signature(
                                src_url,
                                block.index,
                                block_signature.clone(),
                                format!("00/{}", block.index),
                            )
                            .expect("Could not add block signature");
                    }
                }
                // Sanity check that watcher is behaving correctly
                assert_eq!(
                    watcher
                        .highest_common_block()
                        .expect("Could not get highest common block"),
                    block.index,
                );

                // Poll for a change in recovery_db highest_known_block_index
                loop {
                    if recovery_db
                        .get_highest_known_block_index()
                        .expect("getting num blocks failed")
                        != initial_highest_known_block_index
                    {
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(10));
                    if start.elapsed() >= std::time::Duration::from_secs(60) {
                        panic!("Time exceeded 30 seconds");
                    }
                    ingest_server.assert_not_stopped();
                }
                let elapsed = start.elapsed();
                timings.push(elapsed);
            }

            // Discard the first 5 runs for "warmup"
            // FIXME: Maybe something better / do it at a different layer
            let stats = compute_basic_stats(&timings[5..], &logger);
            log::crit!(
                logger,
                "Process Txs timings ({} txos): {}",
                CHUNK_SIZE,
                stats
            );
            test_results.num_txs_added = CHUNK_SIZE;
            test_results.process_tx_timings = stats;
        }
    }
    // grpcio detaches all its threads and does not join them :(
    // we opened a PR here: https://github.com/tikv/grpc-rs/pull/455
    // in the meantime we can just sleep after grpcio env and all related
    // objects have been destroyed, and hope that those 6 threads see the
    // shutdown requests within 1 second.
    std::thread::sleep(std::time::Duration::from_millis(1000));

    test_results
}

#[derive(Debug, Parser)]
#[clap(
    name = "fog-ingest-server-load-test",
    about = "Spawns and drives a fog ingest server with input in order to measure its performance"
)]
struct LoadTestOptions {
    #[clap(long, env = "MC_USER_CAPACITY")]
    user_capacity: Option<Vec<u64>>,
}

fn main() {
    mc_common::setup_panic_handler();

    let opt = LoadTestOptions::parse();

    // Reduce log level maybe?
    let logger = mc_common::logger::create_root_logger();

    let load_test_target = get_bin_path("fog_ingest_server");

    let mut results = Vec::new();

    let capacities_to_test = opt.user_capacity.unwrap_or_else(|| vec![1024 * 1024]);
    log::info!(
        logger,
        "Testing server with these capacities: {:?}",
        capacities_to_test
    );

    for cap in capacities_to_test.iter() {
        results.push(load_test(
            &load_test_target,
            TestParams {
                user_capacity: *cap,
            },
            logger.clone(),
        ));
    }

    // XXX: Write results to a results file or something?
    println!("Load testing results\n================");
    for result in results.iter() {
        println!("{}", result);
    }
}
