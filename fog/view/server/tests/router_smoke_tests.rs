// Copyright (c) 2018-2022 The MobileCoin Foundation

use futures::executor::block_on;
use mc_common::logger::{create_app_logger, log, o, Logger};
use mc_crypto_keys::{CompressedRistrettoPublic, RistrettoPublic};
use mc_fog_kex_rng::KexRngPubkey;
use mc_fog_recovery_db_iface::{RecoveryDb, ReportData, ReportDb};
use mc_fog_test_infra::db_tests::{random_block, random_kex_rng_pubkey};
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
    const TX_OUTS_PER_BLOCK: usize = 2;
    for i in 0..BLOCK_COUNT {
        let (block, records) = random_block(&mut rng, i, TX_OUTS_PER_BLOCK);
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
    assert_eq!(result.last_known_block_count, total_block_count);
    assert_eq!(
        result.last_known_block_cumulative_txo_count,
        BLOCK_COUNT * (TX_OUTS_PER_BLOCK as u64)
    );
}

#[test]
fn test_512() {
    let (logger, _global_logger_guard) = create_app_logger(o!());
    const OMAP_CAPACITY: u64 = 512;
    const STORE_COUNT: usize = 5;
    let mut test_environment =
        RouterTestEnvironment::new(OMAP_CAPACITY, STORE_COUNT, logger.clone());

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
    let mut test_environment =
        RouterTestEnvironment::new(OMAP_CAPACITY, STORE_COUNT, logger.clone());

    block_on(test_router_integration(
        &mut test_environment,
        logger.clone(),
    ))
}

/// Test that view server behaves correctly when there is a missing range
/// between two ingest invocations.
#[test]
fn test_middle_missing_range_with_decommission() {
    let (logger, _global_logger_guard) =
        mc_common::logger::create_app_logger(mc_common::logger::o!());
    let mut rng: StdRng = SeedableRng::from_seed([123u8; 32]);
    const NUMBER_OF_STORES: usize = 5;
    const OMAP_CAPACITY: u64 = 1000;
    const TX_OUTS_PER_BLOCK: usize = 5;

    let mut test_environment =
        RouterTestEnvironment::new(OMAP_CAPACITY, NUMBER_OF_STORES, logger.clone());
    let db = test_environment
        .db_test_context
        .as_ref()
        .unwrap()
        .get_db_instance();

    let ingress_key_1 = CompressedRistrettoPublic::from(RistrettoPublic::from_random(&mut rng));
    const INGRESS_KEY_1_START_BLOCK_COUNT: u64 = 0;
    const INGRESS_KEY_1_BLOCK_COUNT_EXPIRY: u64 = 10;
    db.new_ingress_key(&ingress_key_1, INGRESS_KEY_1_START_BLOCK_COUNT)
        .unwrap();
    db.set_report(
        &ingress_key_1,
        "",
        &ReportData {
            pubkey_expiry: INGRESS_KEY_1_BLOCK_COUNT_EXPIRY,
            ingest_invocation_id: None,
            report: Default::default(),
        },
    )
    .unwrap();

    let ingress_key_2 = CompressedRistrettoPublic::from(RistrettoPublic::from_random(&mut rng));
    const INGRESS_KEY_2_START_BLOCK_COUNT: u64 = 10;
    const INGRESS_KEY_2_BLOCK_COUNT_EXPIRY: u64 = 15;
    db.new_ingress_key(&ingress_key_2, INGRESS_KEY_2_START_BLOCK_COUNT)
        .unwrap();

    // invoc_id1 starts at block 0
    let invoc_id1 = db
        .new_ingest_invocation(
            None,
            &ingress_key_1,
            &random_kex_rng_pubkey(&mut rng),
            INGRESS_KEY_1_START_BLOCK_COUNT,
        )
        .unwrap();

    // Add 5 blocks to invoc_id1.
    const LAST_INGRESS_KEY_1_BLOCK_COUNT: u64 = 5;
    let mut expected_records = Vec::new();
    for i in INGRESS_KEY_1_START_BLOCK_COUNT..LAST_INGRESS_KEY_1_BLOCK_COUNT {
        let (block, records) = random_block(&mut rng, i, TX_OUTS_PER_BLOCK); // 5 outputs per block
        let block_signature_timestamp = 0;
        db.add_block_data(&invoc_id1, &block, block_signature_timestamp, &records)
            .unwrap();
        expected_records.extend(records);
    }
    // At this point we should be at highest processed block 5, and highest known 5,
    // because ingress key 2 doesn't start until 10, and doesn't have any blocks
    // associated to it yet.
    let random_search_keys = vec![vec![1; 10]];
    let router_client = test_environment.router_client.as_mut().unwrap();
    let mut allowed_tries = 60usize;
    loop {
        let result = block_on(router_client.query(0, 0, random_search_keys.clone())).unwrap();
        if result.highest_processed_block_count == 5 && result.last_known_block_count == 5 {
            break;
        }

        if allowed_tries == 0 {
            panic!("Server did not catch up to database! highest_processed_block_count = {}, last_known_block_count = {}", result.highest_processed_block_count, result.last_known_block_count);
        }
        allowed_tries -= 1;
        sleep(Duration::from_secs(1));
    }

    // TODO: Maybe loop through the view servers here?
    // assert_eq!(server.highest_processed_block_count(), 5);

    db.report_lost_ingress_key(ingress_key_1).unwrap();
    let expected_missed_block_ranges = vec![BlockRange {
        start_block: LAST_INGRESS_KEY_1_BLOCK_COUNT,
        end_block: INGRESS_KEY_1_BLOCK_COUNT_EXPIRY
    }];
    assert_eq!(
        db.get_missed_block_ranges().unwrap(),
        expected_missed_block_ranges
    );

    // invoc_id2 starts at block 10
    let invoc_id2 = db
        .new_ingest_invocation(
            None,
            &ingress_key_2,
            &random_kex_rng_pubkey(&mut rng),
            INGRESS_KEY_2_START_BLOCK_COUNT,
        )
        .unwrap();

    // Add 5 blocks to invoc_id2.
    for i in INGRESS_KEY_2_START_BLOCK_COUNT..INGRESS_KEY_2_BLOCK_COUNT_EXPIRY {
        let (block, records) = random_block(&mut rng, i, TX_OUTS_PER_BLOCK); // 5 outputs per block
        let block_signature_timestamp = 0;
        db.add_block_data(&invoc_id2, &block, block_signature_timestamp, &records)
            .unwrap();
        expected_records.extend(records);
    }

    let mut allowed_tries = 60usize;
    loop {
        let result = block_on(router_client.query(0, 0, random_search_keys.clone())).unwrap();
        if result.highest_processed_block_count == INGRESS_KEY_2_BLOCK_COUNT_EXPIRY
            && result.last_known_block_count == INGRESS_KEY_2_BLOCK_COUNT_EXPIRY
        {
            break;
        }

        if allowed_tries == 0 {
            panic!("Server did not catch up to database! highest_processed_block_count = {}, last_known_block_count = {}", result.highest_processed_block_count, result.last_known_block_count);
        }
        allowed_tries -= 1;
        sleep(Duration::from_millis(1000));
    }
    // TODO: Maybe loop through the view servers here?
    // assert_eq!(server.highest_processed_block_count(), 15);

    // Decommissioning invoc_id1 should allow us to advance to the last block
    // invoc_id2 has processed.
    db.decommission_ingest_invocation(&invoc_id1).unwrap();

    let mut allowed_tries = 60usize;
    loop {
        let result = block_on(router_client.query(0, 0, random_search_keys.clone())).unwrap();
        if result.highest_processed_block_count == INGRESS_KEY_2_BLOCK_COUNT_EXPIRY
            && result.last_known_block_count == INGRESS_KEY_2_BLOCK_COUNT_EXPIRY
        {
            break;
        }

        if allowed_tries == 0 {
            panic!("Server did not catch up to database! highest_processed_block_count = {}, last_known_block_count = {}", result.highest_processed_block_count, result.last_known_block_count);
        }
        allowed_tries -= 1;
        sleep(Duration::from_secs(1));
    }
    // TODO: Maybe loop through the view servers here?
    // assert_eq!(server.highest_processed_block_count(), 15);

    let result = block_on(mc_fog_view_server_test_utils::assert_e_tx_out_records(
        router_client,
        &expected_records,
    ));
    assert!(result.is_ok());
    let query_response = result.unwrap();

    assert_eq!(query_response.missed_block_ranges, expected_missed_block_ranges);
}
