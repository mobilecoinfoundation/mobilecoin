// Copyright (c) 2018-2022 The MobileCoin Foundation

// This integration-level test mocks out consensus and tries to show
// that the users are able to recover their transactions.
//
// This is a rewrite of what was historically called test_ingest_view and was an
// end-to-end integration tests of ingest+view+fog-client.
// It exercises both the ingest enclave, and the fog-related crypto that makes
// its way into the client.

use mc_blockchain_types::{Block, BlockID, BlockVersion};
use mc_common::logger::{create_app_logger, o};
use mc_crypto_keys::{CompressedRistrettoPublic, RistrettoPublic};
use mc_fog_kex_rng::KexRngPubkey;
use mc_fog_recovery_db_iface::{RecoveryDb, ReportData, ReportDb};
use mc_fog_test_infra::db_tests::{random_block, random_kex_rng_pubkey};
use mc_fog_types::{common::BlockRange, view::TxOutSearchResultCode, ETxOutRecord};
use mc_fog_view_protocol::FogViewConnection;
use mc_fog_view_server_test_utils::RouterTestEnvironment;
use mc_util_from_random::FromRandom;
use rand::{rngs::StdRng, SeedableRng};
use std::{thread::sleep, time::Duration};
use yare::parameterized;

/// Smoke tests that if we add stuff to recovery database, client can see
/// results when they hit a view server.
#[parameterized(
small_omap_one_store = { 512, 1, 6 },
small_omap_multiple_stores = { 512, 6, 1 },
large_omap_one_store = { 1048576, 1, 6 },
large_omap_multiple_stores = { 1048576, 6, 1 },
)]
fn test_view_integration(view_omap_capacity: u64, store_count: usize, blocks_per_store: u64) {
    let (logger, _global_logger_guard) = create_app_logger(o!());
    let mut rng: StdRng = SeedableRng::from_seed([123u8; 32]);
    let store_block_ranges =
        mc_fog_view_server_test_utils::create_block_ranges(store_count, blocks_per_store);
    let mut test_environment =
        RouterTestEnvironment::new_unary(view_omap_capacity, store_block_ranges, logger.clone());
    let db = test_environment
        .db_test_context
        .as_ref()
        .unwrap()
        .get_db_instance();
    let view_client = test_environment.router_unary_client.as_mut().unwrap();
    let store_servers = test_environment.store_servers.as_ref().unwrap();

    let ingress_key = CompressedRistrettoPublic::from(RistrettoPublic::from_random(&mut rng));
    let accepted_block_1 = db.new_ingress_key(&ingress_key, 0).unwrap();
    assert_eq!(accepted_block_1, 0);

    // First add some data to the database
    let txs: Vec<ETxOutRecord> = (1u8..21u8)
        .map(|x| ETxOutRecord {
            search_key: vec![x; 16],
            payload: vec![x; 232],
        })
        .collect();

    let pubkey1 = KexRngPubkey {
        public_key: [1; 32].to_vec(),
        version: 0,
    };
    let invoc_id1 = db
        .new_ingest_invocation(None, &ingress_key, &pubkey1, 0)
        .unwrap();

    db.add_block_data(
        &invoc_id1,
        &Block::new(
            BlockVersion::ZERO,
            &BlockID::default(),
            0,
            2,
            &Default::default(),
            &Default::default(),
        ),
        0,
        &txs[0..2],
    )
    .unwrap();

    db.add_block_data(
        &invoc_id1,
        &Block::new(
            BlockVersion::ZERO,
            &BlockID::default(),
            1,
            6,
            &Default::default(),
            &Default::default(),
        ),
        0,
        &txs[2..6],
    )
    .unwrap();

    let pubkey2 = KexRngPubkey {
        public_key: [2; 32].to_vec(),
        version: 0,
    };
    let invoc_id2 = db
        .new_ingest_invocation(None, &ingress_key, &pubkey2, 2)
        .unwrap();

    db.add_block_data(
        &invoc_id2,
        &Block::new(
            BlockVersion::ZERO,
            &BlockID::default(),
            2,
            12,
            &Default::default(),
            &Default::default(),
        ),
        0,
        &txs[6..12],
    )
    .unwrap();

    // Block 3 is missing (on a different key)
    let ingress_key2 = CompressedRistrettoPublic::from(RistrettoPublic::from_random(&mut rng));
    let accepted_block_2 = db.new_ingress_key(&ingress_key2, 3).unwrap();
    assert_eq!(accepted_block_2, 3);

    db.set_report(
        &ingress_key2,
        "",
        &ReportData {
            pubkey_expiry: 4,
            ingest_invocation_id: None,
            report: Default::default(),
        },
    )
    .unwrap();
    db.report_lost_ingress_key(ingress_key2).unwrap();

    // Block 3 has no data for the original key
    // (view server must support this, ingest skips some TxOuts if the decrypted fog
    // hint is junk)
    db.add_block_data(
        &invoc_id2,
        &Block::new(
            BlockVersion::ZERO,
            &BlockID::default(),
            3,
            12,
            &Default::default(),
            &Default::default(),
        ),
        0,
        &[],
    )
    .unwrap();

    db.add_block_data(
        &invoc_id2,
        &Block::new(
            BlockVersion::ZERO,
            &BlockID::default(),
            4,
            16,
            &Default::default(),
            &Default::default(),
        ),
        0,
        &txs[12..16],
    )
    .unwrap();

    db.decommission_ingest_invocation(&invoc_id1).unwrap();

    db.add_block_data(
        &invoc_id2,
        &Block::new(
            BlockVersion::ZERO,
            &BlockID::default(),
            5,
            20,
            &Default::default(),
            &Default::default(),
        ),
        0,
        &txs[16..20],
    )
    .unwrap();

    mc_fog_view_server_test_utils::wait_for_highest_block_to_load(&db, store_servers, &logger);
    // Now make some requests against view_client

    let nonsense_search_keys = vec![vec![50u8]];

    // Query 1 should yield 4 events:
    // - 1 new rng record (for invoc_id1)
    // - 1 new rng record (for invoc_id2)
    // - 1 missing block range
    // - 1 ingest decommissioning (for invoc_id1)
    let result = view_client.request(0, 0, nonsense_search_keys.clone());
    assert!(result.is_ok());
    let mut result = result.unwrap();
    assert_eq!(result.highest_processed_block_count, 6);
    assert_eq!(result.next_start_from_user_event_id, 4);
    assert_eq!(result.rng_records.len(), 2);
    result
        .rng_records
        .sort_by_key(|rng_record| rng_record.ingest_invocation_id);
    assert_eq!(result.rng_records[0].pubkey, pubkey1);
    assert_eq!(result.rng_records[1].pubkey, pubkey2);
    assert_eq!(result.tx_out_search_results.len(), 1);
    assert_eq!(
        TxOutSearchResultCode::try_from(result.tx_out_search_results[0].result_code).unwrap(),
        TxOutSearchResultCode::BadSearchKey
    );
    assert_eq!(result.missed_block_ranges.len(), 1);
    assert_eq!(result.missed_block_ranges[0], BlockRange::new(3, 4));
    assert_eq!(result.last_known_block_count, 6);

    // Query 2 is the same as Query 1 and tests that identical queries (when no
    // blocks have been added etc.) should yield identical results.
    let result = view_client.request(0, 0, nonsense_search_keys.clone());
    assert!(result.is_ok());
    let mut result = result.unwrap();
    assert_eq!(result.highest_processed_block_count, 6);
    assert_eq!(result.next_start_from_user_event_id, 4);
    assert_eq!(result.rng_records.len(), 2);
    result
        .rng_records
        .sort_by_key(|rng_record| rng_record.ingest_invocation_id);
    assert_eq!(result.rng_records[0].pubkey, pubkey1);
    assert_eq!(result.rng_records[1].pubkey, pubkey2);
    assert_eq!(result.tx_out_search_results.len(), 1);
    assert_eq!(
        TxOutSearchResultCode::try_from(result.tx_out_search_results[0].result_code).unwrap(),
        TxOutSearchResultCode::BadSearchKey
    );
    assert_eq!(result.missed_block_ranges.len(), 1);
    assert_eq!(result.missed_block_ranges[0], BlockRange::new(3, 4));
    assert_eq!(result.last_known_block_count, 6);

    // Query 3 starts at user event id 1, which skips the invoc_id1 new rng record
    // event (which has a user event id of 0).
    let result = view_client.request(1, 0, nonsense_search_keys.clone());
    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(result.highest_processed_block_count, 6);
    assert_eq!(result.next_start_from_user_event_id, 4);
    assert_eq!(result.rng_records.len(), 1);
    assert_eq!(result.rng_records[0].pubkey, pubkey2);
    assert_eq!(result.rng_records[0].start_block, 2);
    assert_eq!(result.tx_out_search_results.len(), 1);
    assert_eq!(
        TxOutSearchResultCode::try_from(result.tx_out_search_results[0].result_code).unwrap(),
        TxOutSearchResultCode::BadSearchKey
    );
    assert_eq!(result.missed_block_ranges.len(), 1);
    assert_eq!(result.missed_block_ranges[0], BlockRange::new(3, 4));
    assert_eq!(result.last_known_block_count, 6);

    // Query 4 starts at user event id 4, which skips all events.
    let result = view_client.request(4, 0, nonsense_search_keys.clone());
    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(result.highest_processed_block_count, 6);
    assert_eq!(result.next_start_from_user_event_id, 4);
    assert_eq!(result.rng_records.len(), 0);
    assert_eq!(result.tx_out_search_results.len(), 1);
    assert_eq!(
        TxOutSearchResultCode::try_from(result.tx_out_search_results[0].result_code).unwrap(),
        TxOutSearchResultCode::BadSearchKey
    );
    assert_eq!(result.missed_block_ranges.len(), 0);
    assert_eq!(result.last_known_block_count, 6);

    // Query 5 starts at a user event id that is much larger than the last known
    // event id. This should  skip all events and return this large user event
    // id.
    let result = view_client.request(80, 0, nonsense_search_keys).unwrap();
    assert_eq!(result.highest_processed_block_count, 6);
    assert_eq!(result.next_start_from_user_event_id, 80);
    assert_eq!(result.rng_records.len(), 0);
    assert_eq!(result.tx_out_search_results.len(), 1);
    assert_eq!(
        TxOutSearchResultCode::try_from(result.tx_out_search_results[0].result_code).unwrap(),
        TxOutSearchResultCode::BadSearchKey
    );
    assert_eq!(result.missed_block_ranges.len(), 0);
    assert_eq!(result.last_known_block_count, 6);

    // Query 6 starts at user event id 4, and supplies search keys that correspond
    // to TxOuts. We expect to find these TxOuts.
    let result = view_client.request(4, 0, vec![vec![1u8; 16], vec![2u8; 16], vec![3u8; 16]]);
    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(result.highest_processed_block_count, 6);
    assert_eq!(result.next_start_from_user_event_id, 4);
    assert_eq!(result.rng_records.len(), 0);
    assert_eq!(result.tx_out_search_results.len(), 3);
    {
        let sort_txs = mc_fog_view_server_test_utils::interpret_tx_out_search_results(
            result.tx_out_search_results.clone(),
        );
        assert_eq!(sort_txs[0].search_key, vec![1u8; 16]);
        assert_eq!(sort_txs[0].result_code, 1);
        assert_eq!(sort_txs[0].ciphertext, vec![1u8; 232]);

        assert_eq!(sort_txs[1].search_key, vec![2u8; 16]);
        assert_eq!(sort_txs[1].result_code, 1);
        assert_eq!(sort_txs[1].ciphertext, vec![2u8; 232]);

        assert_eq!(sort_txs[2].search_key, vec![3u8; 16]);
        assert_eq!(sort_txs[2].result_code, 1);
        assert_eq!(sort_txs[2].ciphertext, vec![3u8; 232]);
    }
    assert_eq!(result.missed_block_ranges.len(), 0); // no range reported since we started at event id 4
    assert_eq!(result.last_known_block_count, 6);

    // Query 7 starts at user event id 4, and supplies 2 search keys that correspond
    // to TxOuts and 1 search key that doesn't correspond to any TxOuts. We to
    // find the TxOuts for the first 2 search keys and to not find TxOuts for
    // the last search key.
    let result = view_client.request(4, 0, vec![vec![5u8; 16], vec![8u8; 16], vec![200u8; 16]]);
    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(result.highest_processed_block_count, 6);
    assert_eq!(result.next_start_from_user_event_id, 4);
    assert_eq!(result.rng_records.len(), 0);
    assert_eq!(result.tx_out_search_results.len(), 3);
    {
        let sort_txs = mc_fog_view_server_test_utils::interpret_tx_out_search_results(
            result.tx_out_search_results.clone(),
        );
        assert_eq!(sort_txs[0].search_key, vec![5u8; 16]);
        assert_eq!(sort_txs[0].result_code, 1);
        assert_eq!(sort_txs[0].ciphertext, vec![5u8; 232]);

        assert_eq!(sort_txs[1].search_key, vec![8u8; 16]);
        assert_eq!(sort_txs[1].result_code, 1);
        assert_eq!(sort_txs[1].ciphertext, vec![8u8; 232]);

        assert_eq!(sort_txs[2].search_key, vec![200u8; 16]);
        assert_eq!(sort_txs[2].result_code, 2);
        assert_eq!(sort_txs[2].ciphertext, vec![0u8; 255]);
    }

    assert_eq!(result.missed_block_ranges.len(), 0); // no range reported since we started at event id 4
    assert_eq!(result.last_known_block_count, 6);

    // Query 8 supplies an ill-formed seach key, so we expect to find that the TxOut
    // that's returned indicates this.
    let result = view_client.request(0, 0, vec![vec![200u8; 17]]);
    assert!(result.is_ok());
    let mut result = result.unwrap();
    result
        .rng_records
        .sort_by_key(|rng_record| rng_record.ingest_invocation_id);
    assert_eq!(result.highest_processed_block_count, 6);
    assert_eq!(result.next_start_from_user_event_id, 4);
    assert_eq!(result.rng_records.len(), 2);
    assert_eq!(result.rng_records[0].pubkey, pubkey1);
    assert_eq!(result.rng_records[1].pubkey, pubkey2);
    assert_eq!(result.tx_out_search_results.len(), 1);
    {
        let sort_txs = mc_fog_view_server_test_utils::interpret_tx_out_search_results(
            result.tx_out_search_results.clone(),
        );
        assert_eq!(sort_txs[0].search_key, vec![200u8; 17]);
        assert_eq!(sort_txs[0].result_code, 3);
        assert_eq!(sort_txs[0].ciphertext, vec![0u8; 232]);
    }
    assert_eq!(result.missed_block_ranges.len(), 1);
    assert_eq!(result.missed_block_ranges[0], BlockRange::new(3, 4));
    assert_eq!(result.last_known_block_count, 6);

    // Sleep before exiting to give view server threads time to join
    sleep(Duration::from_millis(1000));
}

/// Test that view server behaves correctly when there is some overlap between
/// two currently active ingest invocations.
#[parameterized(
one_store = { 1, 40 },
multiple_stores = { 5, 8 },
)]
fn test_overlapping_ingest_ranges(store_count: usize, blocks_per_store: u64) {
    let (logger, _global_logger_guard) = create_app_logger(o!());
    let mut rng: StdRng = SeedableRng::from_seed([123u8; 32]);
    const VIEW_OMAP_CAPACITY: u64 = 512;
    let store_block_ranges =
        mc_fog_view_server_test_utils::create_block_ranges(store_count, blocks_per_store);
    let mut test_environment =
        RouterTestEnvironment::new_unary(VIEW_OMAP_CAPACITY, store_block_ranges, logger.clone());
    let view_client = test_environment.router_unary_client.as_mut().unwrap();
    let db = test_environment
        .db_test_context
        .as_ref()
        .unwrap()
        .get_db_instance();
    let store_servers = test_environment.store_servers.as_ref().unwrap();

    let ingress_key1 = CompressedRistrettoPublic::from(RistrettoPublic::from_random(&mut rng));
    db.new_ingress_key(&ingress_key1, 0).unwrap();

    let ingress_key2 = CompressedRistrettoPublic::from(RistrettoPublic::from_random(&mut rng));
    db.new_ingress_key(&ingress_key2, 10).unwrap();

    // invoc_id1 starts at block 0
    let invoc_id1 = db
        .new_ingest_invocation(None, &ingress_key1, &random_kex_rng_pubkey(&mut rng), 0)
        .unwrap();

    // invoc_id2 starts at block 10
    let invoc_id2 = db
        .new_ingest_invocation(None, &ingress_key2, &random_kex_rng_pubkey(&mut rng), 10)
        .unwrap();

    // Add 5 blocks to both invocations. This will add blocks 0-4 to invoc1 and
    // blocks 10-14 to invoc2. Since we're missing blocks 5-9, we should only
    // see blocks 0-4 for now.
    let mut expected_records = Vec::new();
    for i in 0..5 {
        let (block, records) = random_block(&mut rng, i, 5); // 5 outputs per block
        db.add_block_data(&invoc_id1, &block, 0, &records).unwrap();
        expected_records.extend(records);

        let (block, records) = random_block(&mut rng, i + 10, 5); // start block is 10
        db.add_block_data(&invoc_id2, &block, 0, &records).unwrap();
        expected_records.extend(records);
    }

    let block_count = 5;
    mc_fog_view_server_test_utils::wait_for_block_to_load(block_count, store_servers, &logger);
    let highest_processed_block_count =
        mc_fog_view_server_test_utils::get_highest_processed_block_count(store_servers);
    assert_eq!(highest_processed_block_count, block_count);

    mc_fog_view_server_test_utils::assert_e_tx_out_records(view_client, &expected_records);

    // Give server time to process some more blocks, although it shouldn't.
    sleep(Duration::from_millis(1000));
    let highest_processed_block_count =
        mc_fog_view_server_test_utils::get_highest_processed_block_count(store_servers);
    assert_eq!(highest_processed_block_count, block_count);

    // See that we get a sane client response.
    let nonsense_search_keys = vec![vec![50u8]];
    let result = view_client
        .request(0, 0, nonsense_search_keys.clone())
        .unwrap();
    assert_eq!(result.highest_processed_block_count, block_count);
    assert_eq!(result.last_known_block_count, 15); // The last known block is not tied to the serial processing of blocks.

    // Add blocks 5-19 to invoc_id1. This will allow us to query blocks 0-14, since
    // invoc_id2 only has blocks 10-14.
    for i in 5..20 {
        let (block, records) = random_block(&mut rng, i, 5); // 5 outputs per block
        db.add_block_data(&invoc_id1, &block, 0, &records).unwrap();

        expected_records.extend(records);
    }

    let block_count = 15;
    mc_fog_view_server_test_utils::wait_for_block_to_load(block_count, store_servers, &logger);
    let highest_processed_block_count =
        mc_fog_view_server_test_utils::get_highest_processed_block_count(store_servers);
    assert_eq!(highest_processed_block_count, block_count);

    // Give server time to process some more blocks, although it shouldn't.
    mc_fog_view_server_test_utils::wait_for_highest_processed_and_last_known(
        view_client,
        block_count,
        20,
    );
    let highest_processed_block_count =
        mc_fog_view_server_test_utils::get_highest_processed_block_count(store_servers);
    assert_eq!(highest_processed_block_count, block_count);

    // See that we get a sane client response.
    let result = view_client.request(0, 0, nonsense_search_keys).unwrap();
    assert_eq!(result.highest_processed_block_count, 15);
    assert_eq!(result.last_known_block_count, 20); // The last known block is not tied to the serial processing of blocks.

    // Add blocks 15-30 to invoc_id2, this should bring us to block 20.
    for i in 15..30 {
        let (block, records) = random_block(&mut rng, i, 5); // 5 outputs per block
        db.add_block_data(&invoc_id2, &block, 0, &records).unwrap();
        expected_records.extend(records);
    }

    mc_fog_view_server_test_utils::wait_for_block_to_load(20, store_servers, &logger);
    let highest_processed_block_count =
        mc_fog_view_server_test_utils::get_highest_processed_block_count(store_servers);
    assert_eq!(highest_processed_block_count, 20);

    // Give server time to process some more blocks, although it shouldn't.
    sleep(Duration::from_millis(1000));
    let highest_processed_block_count =
        mc_fog_view_server_test_utils::get_highest_processed_block_count(store_servers);
    assert_eq!(highest_processed_block_count, 20);

    // See that we get a sane client response.
    mc_fog_view_server_test_utils::wait_for_highest_processed_and_last_known(view_client, 20, 30);
    // Ensure all ETxOutRecords are searchable
    mc_fog_view_server_test_utils::assert_e_tx_out_records(view_client, &expected_records);
}

/// Test that view server behaves correctly when there is a missing range before
/// any ingest invocations.
#[parameterized(
one_store = { 1, 40 },
multiple_stores = { 5, 8 },
)]
fn test_start_with_missing_range() {
    let (logger, _global_logger_guard) = create_app_logger(o!());
    let mut rng: StdRng = SeedableRng::from_seed([123u8; 32]);
    const VIEW_OMAP_CAPACITY: u64 = 512;
    const STORE_COUNT: usize = 5;
    const BLOCKS_PER_STORE: u64 = 8;
    let store_block_ranges =
        mc_fog_view_server_test_utils::create_block_ranges(STORE_COUNT, BLOCKS_PER_STORE);
    let mut test_environment =
        RouterTestEnvironment::new_unary(VIEW_OMAP_CAPACITY, store_block_ranges, logger.clone());
    let db = test_environment
        .db_test_context
        .as_ref()
        .unwrap()
        .get_db_instance();
    let store_servers = test_environment.store_servers.as_ref().unwrap();
    let view_client = test_environment.router_unary_client.as_mut().unwrap();

    let ingress_key = CompressedRistrettoPublic::from(RistrettoPublic::from_random(&mut rng));
    db.new_ingress_key(&ingress_key, 5).unwrap();

    // invoc_id1 starts at block 0, but the initial blocks reported are 10-15
    let invoc_id1 = db
        .new_ingest_invocation(None, &ingress_key, &random_kex_rng_pubkey(&mut rng), 5)
        .unwrap();

    // Add 5 blocks to invoc_id1.
    let mut expected_records = Vec::new();
    for i in 10..15 {
        let (block, records) = random_block(&mut rng, i, 5); // 5 outputs per block
        db.add_block_data(&invoc_id1, &block, 0, &records).unwrap();
        expected_records.extend(records);
    }

    // Give server time to process some more blocks, although it shouldn't.
    sleep(Duration::from_millis(1000));
    let highest_processed_block_count =
        mc_fog_view_server_test_utils::get_highest_processed_block_count(store_servers);
    assert_eq!(highest_processed_block_count, 0);

    mc_fog_view_server_test_utils::wait_for_highest_processed_and_last_known(view_client, 0, 0);

    // Adding the first 5 blocks that were the gap
    for i in 5..10 {
        let (block, records) = random_block(&mut rng, i, 5); // 5 outputs per block
        db.add_block_data(&invoc_id1, &block, 0, &records).unwrap();
        expected_records.extend(records);
    }

    mc_fog_view_server_test_utils::wait_for_highest_processed_and_last_known(view_client, 15, 15);

    let highest_processed_block_count =
        mc_fog_view_server_test_utils::get_highest_processed_block_count(store_servers);
    assert_eq!(highest_processed_block_count, 15);

    mc_fog_view_server_test_utils::assert_e_tx_out_records(view_client, &expected_records);
}

/// Test that view server behaves correctly when there is a missing range
/// between two ingest invocations.
#[parameterized(
one_store = { 1, 40 },
multiple_stores = { 5, 8 },
)]
fn test_middle_missing_range_with_decommission() {
    let (logger, _global_logger_guard) = create_app_logger(o!());
    let mut rng: StdRng = SeedableRng::from_seed([123u8; 32]);
    const VIEW_OMAP_CAPACITY: u64 = 512;
    const STORE_COUNT: usize = 5;
    const BLOCKS_PER_STORE: u64 = 8;
    let store_block_ranges =
        mc_fog_view_server_test_utils::create_block_ranges(STORE_COUNT, BLOCKS_PER_STORE);
    let mut test_environment =
        RouterTestEnvironment::new_unary(VIEW_OMAP_CAPACITY, store_block_ranges, logger.clone());
    let db = test_environment
        .db_test_context
        .as_ref()
        .unwrap()
        .get_db_instance();
    let store_servers = test_environment.store_servers.as_ref().unwrap();
    let view_client = test_environment.router_unary_client.as_mut().unwrap();

    let ingress_key1 = CompressedRistrettoPublic::from(RistrettoPublic::from_random(&mut rng));
    db.new_ingress_key(&ingress_key1, 0).unwrap();
    db.set_report(
        &ingress_key1,
        "",
        &ReportData {
            pubkey_expiry: 10,
            ingest_invocation_id: None,
            report: Default::default(),
        },
    )
    .unwrap();

    let ingress_key2 = CompressedRistrettoPublic::from(RistrettoPublic::from_random(&mut rng));
    db.new_ingress_key(&ingress_key2, 10).unwrap();

    // invoc_id1 starts at block 0
    let invoc_id1 = db
        .new_ingest_invocation(None, &ingress_key1, &random_kex_rng_pubkey(&mut rng), 0)
        .unwrap();

    // Add 5 blocks to invoc_id1.
    let mut expected_records = Vec::new();
    for i in 0..5 {
        let (block, records) = random_block(&mut rng, i, 5); // 5 outputs per block
        db.add_block_data(&invoc_id1, &block, 0, &records).unwrap();
        expected_records.extend(records);
    }

    // At this point we should be at highest processed block 5, and highest known 5,
    // because ingress key 2 doesn't start until 10, and doesn't have any blocks
    // associated to it yet.
    mc_fog_view_server_test_utils::wait_for_highest_processed_and_last_known(view_client, 5, 5);
    let highest_processed_block_count =
        mc_fog_view_server_test_utils::get_highest_processed_block_count(store_servers);
    assert_eq!(highest_processed_block_count, 5);

    // Ingress key 1 is lost
    db.report_lost_ingress_key(ingress_key1).unwrap();
    assert_eq!(
        db.get_missed_block_ranges().unwrap(),
        vec![BlockRange {
            start_block: 5,
            end_block: 10
        }]
    );

    // invoc_id2 starts at block 10
    let invoc_id2 = db
        .new_ingest_invocation(None, &ingress_key2, &random_kex_rng_pubkey(&mut rng), 10)
        .unwrap();

    // Add 5 blocks to invoc_id2.
    for i in 10..15 {
        let (block, records) = random_block(&mut rng, i, 5); // 5 outputs per block
        db.add_block_data(&invoc_id2, &block, 0, &records).unwrap();
        expected_records.extend(records);
    }

    // At this point invoc_id1 is marked lost, so we should be at highest processed
    // block 15 and the last known block should be 15.
    mc_fog_view_server_test_utils::wait_for_highest_processed_and_last_known(view_client, 15, 15);
    let highest_processed_block_count =
        mc_fog_view_server_test_utils::get_highest_processed_block_count(store_servers);
    assert_eq!(highest_processed_block_count, 15);

    // Decommissioning invoc_id1 should allow us to advance to the last block
    // invoc_id2 has processed.
    db.decommission_ingest_invocation(&invoc_id1).unwrap();

    mc_fog_view_server_test_utils::wait_for_highest_processed_and_last_known(view_client, 15, 15);
    let highest_processed_block_count =
        mc_fog_view_server_test_utils::get_highest_processed_block_count(store_servers);
    assert_eq!(highest_processed_block_count, 15);

    mc_fog_view_server_test_utils::assert_e_tx_out_records(view_client, &expected_records);
}
