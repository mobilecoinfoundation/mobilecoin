// Copyright (c) 2018-2022 The MobileCoin Foundation

use futures::executor::block_on;
use mc_common::logger::{create_app_logger, o};
use mc_crypto_keys::{CompressedRistrettoPublic, RistrettoPublic};
use mc_fog_kex_rng::KexRngPubkey;
use mc_fog_recovery_db_iface::{RecoveryDb, ReportData, ReportDb};
use mc_fog_types::{common::BlockRange, view::TxOutSearchResultCode, ETxOutRecord};
use mc_fog_view_server_test_utils::RouterTestEnvironment;
use mc_util_from_random::FromRandom;
use rand::{rngs::StdRng, SeedableRng};
use yare::parameterized;

#[parameterized(
small_omap_one_store = { 512, 1, 6 },
small_omap_multiple_stores = { 512, 6, 1 },
large_omap_one_store = { 1048576, 1, 6 },
large_omap_multiple_stores = { 1048576, 6, 1 },
)]
fn test_streaming_integration(omap_capacity: u64, store_count: usize, blocks_per_store: u64) {
    let (logger, _global_logger_guard) = create_app_logger(o!());
    let store_block_ranges =
        mc_fog_view_server_test_utils::create_block_ranges(store_count, blocks_per_store);
    let mut test_environment =
        RouterTestEnvironment::new(omap_capacity, store_block_ranges, logger.clone());

    let mut rng: StdRng = SeedableRng::from_seed([123u8; 32]);
    let db = test_environment
        .db_test_context
        .as_ref()
        .unwrap()
        .get_db_instance();
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

    let egress_public_key_1 = KexRngPubkey {
        public_key: vec![1; 32],
        version: 0,
    };

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

    let invoc_id1 = db
        .new_ingest_invocation(None, &ingress_key, &egress_public_key_1, 0)
        .unwrap();

    mc_fog_view_server_test_utils::add_block_data(&db, &invoc_id1, 0, 2, &txs[0..2]);
    mc_fog_view_server_test_utils::add_block_data(&db, &invoc_id1, 1, 6, &txs[2..6]);

    let egress_public_key_2 = KexRngPubkey {
        public_key: [2; 32].to_vec(),
        version: 0,
    };
    let invoc_id2 = db
        .new_ingest_invocation(None, &ingress_key, &egress_public_key_2, 2)
        .unwrap();

    mc_fog_view_server_test_utils::add_block_data(&db, &invoc_id2, 2, 12, &txs[6..12]);

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
    // Block 3 has no data for the original key. This tests mocks this behavior by
    // adding an empty slice of tx outs for the block.
    //
    // Note: View server must support this behavior, ingest skips some TxOuts if the
    // decrypted fog hint is junk.
    mc_fog_view_server_test_utils::add_block_data(&db, &invoc_id2, 3, 12, &[]);
    mc_fog_view_server_test_utils::add_block_data(&db, &invoc_id2, 4, 16, &txs[12..16]);
    db.decommission_ingest_invocation(&invoc_id1).unwrap();
    mc_fog_view_server_test_utils::add_block_data(&db, &invoc_id2, 5, 20, &txs[16..20]);

    mc_fog_view_server_test_utils::wait_for_highest_block_to_load(&db, store_servers, &logger);

    let router_client = test_environment.router_streaming_client.as_mut().unwrap();
    let nonsense_search_keys = vec![vec![50u8]];

    // Query 1 should yield 4 events:
    // - 1 new rng record (for invoc_id1)
    // - 1 new rng record (for invoc_id2)
    // - 1 missing block range
    // - 1 ingest decommissioning (for invoc_id1)
    let result = block_on(router_client.query(0, 0, nonsense_search_keys.clone()));
    assert!(result.is_ok());
    let mut result = result.unwrap();

    assert_eq!(result.highest_processed_block_count, 6);
    assert_eq!(result.next_start_from_user_event_id, 4);
    assert_eq!(result.rng_records.len(), 2);
    result
        .rng_records
        .sort_by_key(|rng_record| rng_record.ingest_invocation_id);
    assert_eq!(result.rng_records[0].pubkey, egress_public_key_1);
    assert_eq!(result.rng_records[1].pubkey, egress_public_key_2);
    assert_eq!(result.fixed_tx_out_search_results.len(), 1);
    assert_eq!(
        TxOutSearchResultCode::try_from(result.fixed_tx_out_search_results[0].result_code).unwrap(),
        TxOutSearchResultCode::BadSearchKey
    );
    assert_eq!(result.missed_block_ranges.len(), 1);
    assert_eq!(result.missed_block_ranges[0], BlockRange::new(3, 4));
    assert_eq!(result.last_known_block_count, 6);

    // Query 2 is the same as Query 1 and tests that identical queries (when no
    // blocks have been added etc.) should yield identical results.
    let result = block_on(router_client.query(0, 0, nonsense_search_keys.clone()));
    assert!(result.is_ok());
    let mut result = result.unwrap();
    assert_eq!(result.highest_processed_block_count, 6);
    assert_eq!(result.next_start_from_user_event_id, 4);
    assert_eq!(result.rng_records.len(), 2);
    result
        .rng_records
        .sort_by_key(|rng_record| rng_record.ingest_invocation_id);
    assert_eq!(result.rng_records[0].pubkey, egress_public_key_1);
    assert_eq!(result.rng_records[1].pubkey, egress_public_key_2);
    assert_eq!(result.fixed_tx_out_search_results.len(), 1);
    assert_eq!(
        TxOutSearchResultCode::try_from(result.fixed_tx_out_search_results[0].result_code).unwrap(),
        TxOutSearchResultCode::BadSearchKey
    );
    assert_eq!(result.missed_block_ranges.len(), 1);
    assert_eq!(result.missed_block_ranges[0], BlockRange::new(3, 4));
    assert_eq!(result.last_known_block_count, 6);

    // Query 3 starts at user event id 1, which skips the invoc_id1 new rng record
    // event (which has a user event id of 0).
    let result = block_on(router_client.query(1, 0, nonsense_search_keys.clone()));
    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(result.highest_processed_block_count, 6);
    assert_eq!(result.next_start_from_user_event_id, 4);
    assert_eq!(result.rng_records.len(), 1);
    assert_eq!(result.rng_records[0].pubkey, egress_public_key_2);
    assert_eq!(result.rng_records[0].start_block, 2);
    assert_eq!(result.fixed_tx_out_search_results.len(), 1);
    assert_eq!(
        TxOutSearchResultCode::try_from(result.fixed_tx_out_search_results[0].result_code).unwrap(),
        TxOutSearchResultCode::BadSearchKey
    );
    assert_eq!(result.missed_block_ranges.len(), 1);
    assert_eq!(result.missed_block_ranges[0], BlockRange::new(3, 4));
    assert_eq!(result.last_known_block_count, 6);

    // Query 4 starts at user event id 4, which skips all events.
    let result = block_on(router_client.query(4, 0, nonsense_search_keys.clone()));
    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(result.highest_processed_block_count, 6);
    assert_eq!(result.next_start_from_user_event_id, 4);
    assert_eq!(result.rng_records.len(), 0);
    assert_eq!(result.fixed_tx_out_search_results.len(), 1);
    assert_eq!(
        TxOutSearchResultCode::try_from(result.fixed_tx_out_search_results[0].result_code).unwrap(),
        TxOutSearchResultCode::BadSearchKey
    );
    assert_eq!(result.missed_block_ranges.len(), 0);
    assert_eq!(result.last_known_block_count, 6);

    // Query 5 starts at a user event id that is much larger than the last known
    // event id. This should  skip all events and return this large user event
    // id.
    let result = block_on(router_client.query(80, 0, nonsense_search_keys));
    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(result.highest_processed_block_count, 6);
    assert_eq!(result.next_start_from_user_event_id, 80);
    assert_eq!(result.rng_records.len(), 0);
    assert_eq!(result.fixed_tx_out_search_results.len(), 1);
    assert_eq!(
        TxOutSearchResultCode::try_from(result.fixed_tx_out_search_results[0].result_code).unwrap(),
        TxOutSearchResultCode::BadSearchKey
    );
    assert_eq!(result.missed_block_ranges.len(), 0);
    assert_eq!(result.last_known_block_count, 6);

    // Query 6 starts at user event id 4, and supplies search keys that correspond
    // to TxOuts. We expect to find these TxOuts.
    let result =
        block_on(router_client.query(4, 0, vec![vec![1u8; 16], vec![2u8; 16], vec![3u8; 16]]));
    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(result.highest_processed_block_count, 6);
    assert_eq!(result.next_start_from_user_event_id, 4);
    assert_eq!(result.rng_records.len(), 0);
    assert_eq!(result.fixed_tx_out_search_results.len(), 3);
    {
        let sort_txs = mc_fog_view_server_test_utils::interpret_tx_out_search_results(
            result.fixed_tx_out_search_results.clone(),
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
    let result =
        block_on(router_client.query(4, 0, vec![vec![5u8; 16], vec![8u8; 16], vec![200u8; 16]]));
    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(result.highest_processed_block_count, 6);
    assert_eq!(result.next_start_from_user_event_id, 4);
    assert_eq!(result.rng_records.len(), 0);
    assert_eq!(result.fixed_tx_out_search_results.len(), 3);
    {
        let sort_txs = mc_fog_view_server_test_utils::interpret_tx_out_search_results(
            result.fixed_tx_out_search_results.clone(),
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
    let result = block_on(router_client.query(0, 0, vec![vec![200u8; 17]]));
    assert!(result.is_ok());
    let mut result = result.unwrap();
    result
        .rng_records
        .sort_by_key(|rng_record| rng_record.ingest_invocation_id);
    assert_eq!(result.highest_processed_block_count, 6);
    assert_eq!(result.next_start_from_user_event_id, 4);
    assert_eq!(result.rng_records.len(), 2);
    assert_eq!(result.rng_records[0].pubkey, egress_public_key_1);
    assert_eq!(result.rng_records[1].pubkey, egress_public_key_2);
    assert_eq!(result.fixed_tx_out_search_results.len(), 1);
    {
        let sort_txs = mc_fog_view_server_test_utils::interpret_tx_out_search_results(
            result.fixed_tx_out_search_results.clone(),
        );
        assert_eq!(sort_txs[0].search_key, vec![200u8; 17]);
        assert_eq!(sort_txs[0].result_code, 3);
        assert_eq!(sort_txs[0].ciphertext, vec![0u8; 232]);
    }
    assert_eq!(result.missed_block_ranges.len(), 1);
    assert_eq!(result.missed_block_ranges[0], BlockRange::new(3, 4));
    assert_eq!(result.last_known_block_count, 6);
}
