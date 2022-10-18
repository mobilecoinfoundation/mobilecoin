// Copyright (c) 2018-2022 The MobileCoin Foundation

use futures::executor::block_on;
use mc_common::logger::{create_app_logger, log, o, Logger};
use mc_crypto_keys::{CompressedRistrettoPublic, RistrettoPublic};
use mc_fog_kex_rng::KexRngPubkey;
use mc_fog_recovery_db_iface::{RecoveryDb, ReportData, ReportDb};
use mc_fog_test_infra::db_tests::random_block;
use mc_fog_types::common::BlockRange;
use mc_fog_view_server_test_utils::RouterTestEnvironment;
use mc_util_from_random::FromRandom;
use rand::{rngs::StdRng, SeedableRng};
use std::{thread::sleep, time::Duration};

async fn test_router_integration(test_environment: &mut RouterTestEnvironment, logger: Logger) {
    let mut rng: StdRng = SeedableRng::from_seed([123u8; 32]);
    let db = test_environment
        .db_test_context
        .as_ref()
        .unwrap()
        .get_db_instance();

    let ingress_key = CompressedRistrettoPublic::from(RistrettoPublic::from_random(&mut rng));
    let accepted_block_1 = db.new_ingress_key(&ingress_key, 0).unwrap();
    assert_eq!(accepted_block_1, 0);

    db.set_report(
        &ingress_key,
        "",
        &ReportData {
            pubkey_expiry: 6,
            ingest_invocation_id: None,
            report: Default::default(),
        },
    )
    .unwrap();

    let egress_public_key = KexRngPubkey {
        public_key: vec![1; 32],
        version: 0,
    };

    let invoc_id1 = db
        .new_ingest_invocation(None, &ingress_key, &egress_public_key, 0)
        .unwrap();

    let mut expected_records = Vec::new();
    const BLOCK_COUNT: u64 = 5;
    for i in 0..BLOCK_COUNT {
        let (block, records) = random_block(&mut rng, i, 2);
        db.add_block_data(&invoc_id1, &block, 0, &records).unwrap();
        expected_records.extend(records);
    }

    // Wait until first server has added stuff to ORAM. Since all view servers
    // should load ORAM at the same time, we could choose to wait for any view
    // server.
    let mut allowed_tries = 1000usize;
    loop {
        let db_num_blocks = db
            .get_highest_known_block_index()
            .unwrap()
            .map(|v| v + 1) // convert index to count
            .unwrap_or(0);
        let server_num_blocks = test_environment
            .store_servers
            .as_ref()
            .unwrap()
            .iter()
            .map(|server| server.highest_processed_block_count())
            .max()
            .unwrap_or_default();
        if server_num_blocks > db_num_blocks {
            panic!(
                "Server num blocks should never be larger than db num blocks: {} > {}",
                server_num_blocks, db_num_blocks
            );
        }
        if server_num_blocks == db_num_blocks {
            log::info!(logger, "Stopping, block {}", server_num_blocks);
            break;
        }
        log::info!(
            logger,
            "Waiting for server to catch up to db... {} < {}",
            server_num_blocks,
            db_num_blocks
        );
        if allowed_tries == 0 {
            panic!("Server did not catch up to database!");
        }
        allowed_tries -= 1;
        sleep(Duration::from_secs(1));
    }

    let router_client = test_environment.router_client.as_mut().unwrap();
    let result =
        mc_fog_view_server_test_utils::assert_e_tx_out_records(router_client, &expected_records)
            .await;

    assert!(result.is_ok());

    let result = result.unwrap();
    // TODO: see what we should do about collating these fields... Right now they
    // are in sync, but that won't always be the case...
    assert_eq!(result.highest_processed_block_count, 5);
    assert_eq!(result.next_start_from_user_event_id, 1);
    assert_eq!(result.rng_records.len(), 1);
    assert_eq!(result.rng_records[0].pubkey, egress_public_key);
    assert_eq!(result.missed_block_ranges.len(), 0);
    assert_eq!(result.last_known_block_count, 5);
}

#[test]
fn test_512() {
    let (logger, _global_logger_guard) = create_app_logger(o!());
    const OMAP_CAPACITY: u64 = 512;
    const STORE_COUNT: usize = 5;

    let mut block_ranges = Vec::with_capacity(STORE_COUNT);
    for i in 0..STORE_COUNT {
        let block_range = BlockRange {
            start_block: i as u64,
            end_block: (i + 1) as u64,
        };
        block_ranges.push(block_range);
    }

    let mut test_environment =
        RouterTestEnvironment::new(OMAP_CAPACITY, &block_ranges, logger.clone());

    block_on(test_router_integration(
        &mut test_environment,
        logger.clone(),
    ))
}

#[test]
fn test_1_million() {
    let (logger, _global_logger_guard) = create_app_logger(o!());
    const OMAP_CAPACITY: u64 = 1024 * 1024;
    const STORE_COUNT: usize = 5;

    let mut block_ranges = Vec::with_capacity(STORE_COUNT);
    for i in 0..STORE_COUNT {
        let block_range = BlockRange {
            start_block: i as u64,
            end_block: (i + 1) as u64,
        };
        block_ranges.push(block_range);
    }

    let mut test_environment =
        RouterTestEnvironment::new(OMAP_CAPACITY, &block_ranges, logger.clone());

    block_on(test_router_integration(
        &mut test_environment,
        logger.clone(),
    ))
}

#[test]
fn gaps_in_highest_processed_block() {
    let (logger, _global_logger_guard) = create_app_logger(o!());
    const OMAP_CAPACITY: u64 = 1024 * 1024;
    const STORE_COUNT: usize = 3;

    let mut block_ranges = Vec::with_capacity(STORE_COUNT);
    for i in 0..STORE_COUNT {
        let start_block = (i * STORE_COUNT) as u64;
        let block_range = BlockRange {
            start_block,
            end_block: start_block + (STORE_COUNT as u64),
        };
        block_ranges.push(block_range);
    }

    let mut test_environment =
        RouterTestEnvironment::new(OMAP_CAPACITY, &block_ranges, logger.clone());

    let mut rng: StdRng = SeedableRng::from_seed([123u8; 32]);
    let db = test_environment
        .db_test_context
        .as_ref()
        .unwrap()
        .get_db_instance();

    let ingress_key = CompressedRistrettoPublic::from(RistrettoPublic::from_random(&mut rng));
    let accepted_block_1 = db.new_ingress_key(&ingress_key, 0).unwrap();
    assert_eq!(accepted_block_1, 0);

    db.set_report(
        &ingress_key,
        "",
        &ReportData {
            pubkey_expiry: 6,
            ingest_invocation_id: None,
            report: Default::default(),
        },
    )
    .unwrap();

    let egress_public_key = KexRngPubkey {
        public_key: [1; 32].to_vec(),
        version: 0,
    };

    let invoc_id1 = db
        .new_ingest_invocation(None, &ingress_key, &egress_public_key, 0)
        .unwrap();

    let mut expected_records = Vec::new();
    let total_block_count = STORE_COUNT * 3;
    for i in 0..total_block_count {
        let (block, records) = random_block(&mut rng, i as u64, 2);
        db.add_block_data(&invoc_id1, &block, 0, &records).unwrap();
        expected_records.extend(records);
    }

    // Stop the second store server, i.e. the one that is responsible for Blocks 4
    // to 7.
    let second_server = &mut test_environment.store_servers.as_mut().unwrap()[1];
    second_server.stop();

    // Wait until the server with the highest processed block count has added stuff
    // to ORAM.
    let mut allowed_tries = 1000usize;
    loop {
        for server in test_environment.store_servers.as_ref().unwrap() {
            log::info!(
                logger,
                "Server block count: {}",
                server.highest_processed_block_count()
            );
        }
        let db_num_blocks = db
            .get_highest_known_block_index()
            .unwrap()
            .map(|v| v + 1) // convert index to count
            .unwrap_or(0);
        let server_num_blocks = test_environment
            .store_servers
            .as_ref()
            .unwrap()
            .iter()
            .map(|server| server.highest_processed_block_count())
            .max()
            .unwrap_or_default();
        if server_num_blocks > db_num_blocks {
            panic!(
                "Server num blocks should never be larger than db num blocks: {} > {}",
                server_num_blocks, db_num_blocks
            );
        }
        if server_num_blocks == db_num_blocks {
            log::info!(logger, "Stopping, block {}", server_num_blocks);
            break;
        }
        log::info!(
            logger,
            "Waiting for server to catch up to db... {} < {}",
            server_num_blocks,
            db_num_blocks
        );
        if allowed_tries == 0 {
            panic!("Server did not catch up to database!");
        }
        allowed_tries -= 1;
        sleep(Duration::from_secs(1));
    }

    let router_client = test_environment.router_client.as_mut().unwrap();
    let result = block_on(mc_fog_view_server_test_utils::assert_e_tx_out_records(
        router_client,
        &expected_records,
    ));

    assert!(result.is_ok());

    let result = result.unwrap();
    // TODO: see what we should do about collating these fields... Right now they
    // are in sync, but that won't always be the case...
    assert_eq!(result.highest_processed_block_count, 0);
    assert_eq!(result.next_start_from_user_event_id, 1);
    assert_eq!(result.rng_records.len(), 1);
    assert_eq!(result.rng_records[0].pubkey, egress_public_key);
    assert_eq!(result.missed_block_ranges.len(), 0);
    assert_eq!(result.last_known_block_count, 5);
}
