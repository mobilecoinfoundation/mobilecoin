// Copyright (c) 2018-2022 The MobileCoin Foundation

use futures::executor::block_on;
use mc_blockchain_types::{Block, BlockID};
use mc_common::logger::{create_app_logger, log, o, Logger};
use mc_crypto_keys::{CompressedRistrettoPublic, RistrettoPublic};
use mc_fog_kex_rng::KexRngPubkey;
use mc_fog_recovery_db_iface::{RecoveryDb, ReportData, ReportDb};
use mc_fog_types::{
    common::BlockRange,
    view::{TxOutSearchResult, TxOutSearchResultCode},
    ETxOutRecord,
};
use mc_fog_view_server_test_utils::RouterTestEnvironment;
use mc_transaction_core::BlockVersion;
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

    let egress_public_key_2 = KexRngPubkey {
        public_key: [2; 32].to_vec(),
        version: 0,
    };
    let invoc_id2 = db
        .new_ingest_invocation(None, &ingress_key, &egress_public_key_2, 2)
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
    let nonsense_search_keys = vec![vec![50u8]];
    let result = router_client
        .query(0, 0, nonsense_search_keys.clone())
        .await;
    assert!(result.is_ok());
    let mut result = result.unwrap();

    assert_eq!(result.highest_processed_block_count, 6);
    // 4 events are expected (in the following order):
    // - 1 new rng record (for invoc_id1)
    // - 1 new rng record (for invoc_id2)
    // - 1 missing block range
    // - 1 ingest decommissioning (for invoc_id1)
    assert_eq!(result.next_start_from_user_event_id, 4);
    assert_eq!(result.rng_records.len(), 2);
    result
        .rng_records
        .sort_by_key(|rng_record| rng_record.ingest_invocation_id);
    assert_eq!(result.rng_records[0].pubkey, egress_public_key_1);
    assert_eq!(result.rng_records[1].pubkey, egress_public_key_2);
    assert_eq!(result.tx_out_search_results.len(), 1);
    assert_eq!(
        TxOutSearchResultCode::try_from(result.tx_out_search_results[0].result_code).unwrap(),
        TxOutSearchResultCode::BadSearchKey
    );
    assert_eq!(result.missed_block_ranges.len(), 1);
    assert_eq!(result.missed_block_ranges[0], BlockRange::new(3, 4));
    assert_eq!(result.last_known_block_count, 6);

    let result = router_client
        .query(0, 0, nonsense_search_keys.clone())
        .await;
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
    assert_eq!(result.tx_out_search_results.len(), 1);
    assert_eq!(
        TxOutSearchResultCode::try_from(result.tx_out_search_results[0].result_code).unwrap(),
        TxOutSearchResultCode::BadSearchKey
    );
    assert_eq!(result.missed_block_ranges.len(), 1);
    assert_eq!(result.missed_block_ranges[0], BlockRange::new(3, 4));
    assert_eq!(result.last_known_block_count, 6);

    let result = router_client
        // starting at user event id 2 skips invoc_id1
        // (event id 1 is for invoc_id1)
        .query(1, 0, nonsense_search_keys.clone())
        .await;
    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(result.highest_processed_block_count, 6);
    assert_eq!(result.next_start_from_user_event_id, 4);
    assert_eq!(result.rng_records.len(), 1);
    assert_eq!(result.rng_records[0].pubkey, egress_public_key_2);
    assert_eq!(result.rng_records[0].start_block, 2);
    assert_eq!(result.tx_out_search_results.len(), 1);
    assert_eq!(
        TxOutSearchResultCode::try_from(result.tx_out_search_results[0].result_code).unwrap(),
        TxOutSearchResultCode::BadSearchKey
    );
    assert_eq!(result.missed_block_ranges.len(), 1);
    assert_eq!(result.missed_block_ranges[0], BlockRange::new(3, 4));
    assert_eq!(result.last_known_block_count, 6);

    // No events after event id 4
    let result = router_client
        .query(4, 0, nonsense_search_keys.clone())
        .await;
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

    let result = router_client
        .query(80, 0, nonsense_search_keys.clone())
        .await;
    assert!(result.is_ok());
    let result = result.unwrap();
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

    let result = router_client
        .query(4, 0, vec![vec![1u8; 16], vec![2u8; 16], vec![3u8; 16]])
        .await;
    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(result.highest_processed_block_count, 6);
    assert_eq!(result.next_start_from_user_event_id, 4);
    assert_eq!(result.rng_records.len(), 0);
    assert_eq!(result.tx_out_search_results.len(), 3);
    {
        let sort_txs = interpret_tx_out_results(result.tx_out_search_results.clone());
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

    let result = router_client
        .query(4, 0, vec![vec![5u8; 16], vec![8u8; 16], vec![200u8; 16]])
        .await;
    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(result.highest_processed_block_count, 6);
    assert_eq!(result.next_start_from_user_event_id, 4);
    assert_eq!(result.rng_records.len(), 0);
    assert_eq!(result.tx_out_search_results.len(), 3);
    {
        let sort_txs = interpret_tx_out_results(result.tx_out_search_results.clone());
        assert_eq!(sort_txs[0].search_key, vec![5u8; 16]);
        assert_eq!(sort_txs[0].result_code, 1);
        assert_eq!(sort_txs[0].ciphertext, vec![5u8; 232]);

        assert_eq!(sort_txs[1].search_key, vec![8u8; 16]);
        assert_eq!(sort_txs[1].result_code, 1);
        assert_eq!(sort_txs[1].ciphertext, vec![8u8; 232]);

        assert_eq!(sort_txs[2].search_key, vec![200u8; 16]);
        assert_eq!(sort_txs[2].result_code, 2);
        // FIGURE OUT WHAT TO DO HERE
        assert_eq!(sort_txs[2].ciphertext, vec![0u8; 254]);
    }

    assert_eq!(result.missed_block_ranges.len(), 0); // no range reported since we started at event id 4
    assert_eq!(result.last_known_block_count, 6);

    let result = router_client.query(0, 0, vec![vec![200u8; 17]]).await;
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
    assert_eq!(result.tx_out_search_results.len(), 1);
    {
        let sort_txs = interpret_tx_out_results(result.tx_out_search_results.clone());
        assert_eq!(sort_txs[0].search_key, vec![200u8; 17]);
        assert_eq!(sort_txs[0].result_code, 3);
        assert_eq!(sort_txs[0].ciphertext, vec![0u8; 232]);
    }
    assert_eq!(result.missed_block_ranges.len(), 1);
    assert_eq!(result.missed_block_ranges[0], BlockRange::new(3, 4));
    assert_eq!(result.last_known_block_count, 6);
}

fn interpret_tx_out_results(
    mut tx_out_search_results: Vec<TxOutSearchResult>,
) -> Vec<TxOutSearchResult> {
    tx_out_search_results.sort_by(|x, y| x.search_key.cmp(&y.search_key));
    tx_out_search_results
        .iter()
        .map(|result| {
            let payload_length = result.ciphertext.len() - (result.ciphertext[0] as usize);
            TxOutSearchResult {
                search_key: result.search_key.clone(),
                result_code: result.result_code,
                ciphertext: result.ciphertext.clone(),
                payload_length: payload_length as u32,
                
            }
        })
        .collect::<Vec<_>>()
}

#[test]
fn test_512() {
    let (logger, _global_logger_guard) = create_app_logger(o!());
    const OMAP_CAPACITY: u64 = 512;
    const STORE_COUNT: usize = 6;
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
    const STORE_COUNT: usize = 6;
    let mut test_environment =
        RouterTestEnvironment::new(OMAP_CAPACITY, STORE_COUNT, logger.clone());

    block_on(test_router_integration(
        &mut test_environment,
        logger.clone(),
    ))
}
