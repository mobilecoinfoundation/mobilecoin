// Copyright (c) 2018-2021 The MobileCoin Foundation

// This integration-level test mocks out consensus and tries to show
// that the users are able to recover their transactions.
//
// This is a rewrite of what was historically called test_ingest_view and was an
// end-to-end integration tests of ingest+view+fog-client.
// It exercises both the ingest enclave, and the fog-related crypto that makes
// its way into the client.

use mc_attest_core::{MrSignerVerifier, Verifier, DEBUG_ENCLAVE};
use mc_attest_net::{Client as AttestClient, RaClient};
use mc_common::{
    logger::{log, test_with_logger, Logger},
    time::SystemTimeProvider,
    ResponderId,
};
use mc_crypto_keys::{CompressedRistrettoPublic, RistrettoPublic};
use mc_fog_kex_rng::KexRngPubkey;
use mc_fog_recovery_db_iface::{RecoveryDb, ReportData, ReportDb};
use mc_fog_sql_recovery_db::{test_utils::SqlRecoveryDbTestContext, SqlRecoveryDb};
use mc_fog_test_infra::{db_tests::random_kex_rng_pubkey, get_enclave_path};
use mc_fog_types::{
    common::BlockRange,
    view::{TxOutSearchResult, TxOutSearchResultCode},
    ETxOutRecord,
};
use mc_fog_uri::{ConnectionUri, FogViewUri};
use mc_fog_view_connection::FogViewGrpcClient;
use mc_fog_view_enclave::SgxViewEnclave;
use mc_fog_view_protocol::FogViewConnection;
use mc_fog_view_server::{config::MobileAcctViewConfig as ViewConfig, server::ViewServer};
use mc_transaction_core::{Block, BlockID, BLOCK_VERSION};
use mc_util_from_random::FromRandom;
use rand::{rngs::StdRng, SeedableRng};
use std::{
    str::FromStr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

static PORT_NR: AtomicUsize = AtomicUsize::new(40100);

fn get_test_environment(
    view_omap_capacity: u64,
    logger: Logger,
) -> (
    SqlRecoveryDbTestContext,
    ViewServer<SgxViewEnclave, AttestClient, SqlRecoveryDb>,
    FogViewGrpcClient,
) {
    let db_test_context = SqlRecoveryDbTestContext::new(logger.clone());
    let db = db_test_context.get_db_instance();

    let port = PORT_NR.fetch_add(1, Ordering::SeqCst) as u16;

    let uri = FogViewUri::from_str(&format!("insecure-fog-view://127.0.0.1:{}", port)).unwrap();

    let server = {
        let config = ViewConfig {
            ias_spid: Default::default(),
            ias_api_key: Default::default(),
            client_responder_id: ResponderId::from_str(&uri.addr()).unwrap(),
            client_listen_uri: uri.clone(),
            admin_listen_uri: Default::default(),
            client_auth_token_secret: None,
            client_auth_token_max_lifetime: Default::default(),
            omap_capacity: view_omap_capacity,
        };

        let enclave = SgxViewEnclave::new(
            get_enclave_path(mc_fog_view_enclave::ENCLAVE_FILE),
            config.client_responder_id.clone(),
            config.omap_capacity,
            logger.clone(),
        );

        let ra_client =
            AttestClient::new(&config.ias_api_key).expect("Could not create IAS client");

        let mut server = ViewServer::new(
            config,
            enclave,
            db.clone(),
            ra_client,
            SystemTimeProvider::default(),
            logger.clone(),
        );
        server.start();
        server
    };

    let client = {
        let grpcio_env = Arc::new(grpcio::EnvBuilder::new().build());
        let mut mr_signer_verifier =
            MrSignerVerifier::from(mc_fog_view_enclave_measurement::sigstruct());
        mr_signer_verifier.allow_hardening_advisory("INTEL-SA-00334");

        let mut verifier = Verifier::default();
        verifier.mr_signer(mr_signer_verifier).debug(DEBUG_ENCLAVE);

        FogViewGrpcClient::new(uri, verifier, grpcio_env.clone(), logger)
    };

    (db_test_context, server, client)
}

// Smoke tests that if we add stuff to recovery database, client can see
// results when they hit a view server.
fn test_view_integration(view_omap_capacity: u64, logger: Logger) {
    let mut rng: StdRng = SeedableRng::from_seed([123u8; 32]);
    let (db_context, server, mut view_client) =
        get_test_environment(view_omap_capacity, logger.clone());
    let db = db_context.get_db_instance();

    let ingress_key = CompressedRistrettoPublic::from(RistrettoPublic::from_random(&mut rng));
    db.new_ingress_key(&ingress_key, 0).unwrap();

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
            BLOCK_VERSION,
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
            BLOCK_VERSION,
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
            BLOCK_VERSION,
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
    db.new_ingress_key(&ingress_key2, 3).unwrap();
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
            BLOCK_VERSION,
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
            BLOCK_VERSION,
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
            BLOCK_VERSION,
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

    // Wait until server has added stuff to ORAM
    let mut allowed_tries = 1000usize;
    loop {
        let db_num_blocks = db
            .get_highest_known_block_index()
            .unwrap()
            .map(|v| v + 1) // convert index to count
            .unwrap_or(0);
        let server_num_blocks = server.highest_processed_block_count();
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
        std::thread::sleep(Duration::from_millis(1000));
    }

    // Now make some requests against view_client
    let result = view_client.request(0, 0, Default::default()).unwrap();
    assert_eq!(result.highest_processed_block_count, 6);
    // 4 events are expected (in the following order):
    // - 1 new rng record (for invoc_id1)
    // - 1 new rng record (for invoc_id2)
    // - 1 missing block range
    // - 1 ingest decommissioning (for invoc_id1)
    assert_eq!(result.next_start_from_user_event_id, 4);
    assert_eq!(result.rng_records.len(), 2);
    assert_eq!(result.rng_records[0].pubkey, pubkey1);
    assert_eq!(result.rng_records[1].pubkey, pubkey2);
    assert_eq!(result.tx_out_search_results.len(), 0);
    assert_eq!(result.missed_block_ranges.len(), 1);
    assert_eq!(result.missed_block_ranges[0], BlockRange::new(3, 4));
    assert_eq!(result.last_known_block_count, 6);

    let result = view_client.request(0, 0, Default::default()).unwrap();
    assert_eq!(result.highest_processed_block_count, 6);
    assert_eq!(result.next_start_from_user_event_id, 4);
    assert_eq!(result.rng_records.len(), 2);
    assert_eq!(result.rng_records[0].pubkey, pubkey1);
    assert_eq!(result.rng_records[1].pubkey, pubkey2);
    assert_eq!(result.tx_out_search_results.len(), 0);
    assert_eq!(result.missed_block_ranges.len(), 1);
    assert_eq!(result.missed_block_ranges[0], BlockRange::new(3, 4));
    assert_eq!(result.last_known_block_count, 6);

    let result = view_client
        // starting at user event id 2 skips invoc_id1
        // (event id 1 is for invoc_id1)
        .request(1, 0, Default::default())
        .unwrap();
    assert_eq!(result.highest_processed_block_count, 6);
    assert_eq!(result.next_start_from_user_event_id, 4);
    assert_eq!(result.rng_records.len(), 1);
    assert_eq!(result.rng_records[0].pubkey, pubkey2);
    assert_eq!(result.rng_records[0].start_block, 2);
    assert_eq!(result.tx_out_search_results.len(), 0);
    assert_eq!(result.missed_block_ranges.len(), 1);
    assert_eq!(result.missed_block_ranges[0], BlockRange::new(3, 4));
    assert_eq!(result.last_known_block_count, 6);

    // No events after event id 4
    let result = view_client.request(4, 0, Default::default()).unwrap();
    assert_eq!(result.highest_processed_block_count, 6);
    assert_eq!(result.next_start_from_user_event_id, 4);
    assert_eq!(result.rng_records.len(), 0);
    assert_eq!(result.tx_out_search_results.len(), 0);
    assert_eq!(result.missed_block_ranges.len(), 0);
    assert_eq!(result.last_known_block_count, 6);

    let result = view_client.request(80, 0, Default::default()).unwrap();
    assert_eq!(result.highest_processed_block_count, 6);
    assert_eq!(result.next_start_from_user_event_id, 80);
    assert_eq!(result.rng_records.len(), 0);
    assert_eq!(result.tx_out_search_results.len(), 0);
    assert_eq!(result.missed_block_ranges.len(), 0);
    assert_eq!(result.last_known_block_count, 6);

    let result = view_client
        .request(4, 0, vec![vec![1u8; 16], vec![2u8; 16], vec![3u8; 16]])
        .unwrap();
    assert_eq!(result.highest_processed_block_count, 6);
    assert_eq!(result.next_start_from_user_event_id, 4);
    assert_eq!(result.rng_records.len(), 0);
    assert_eq!(result.tx_out_search_results.len(), 3);
    {
        let mut sort_txs = result.tx_out_search_results.clone();
        sort_txs.sort_by(|x, y| x.search_key.cmp(&y.search_key));
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

    let result = view_client
        .request(4, 0, vec![vec![5u8; 16], vec![8u8; 16], vec![200u8; 16]])
        .unwrap();
    assert_eq!(result.highest_processed_block_count, 6);
    assert_eq!(result.next_start_from_user_event_id, 4);
    assert_eq!(result.rng_records.len(), 0);
    assert_eq!(result.tx_out_search_results.len(), 3);
    {
        let mut sort_txs = result.tx_out_search_results.clone();
        sort_txs.sort_by(|x, y| x.search_key.cmp(&y.search_key));
        assert_eq!(sort_txs[0].search_key, vec![5u8; 16]);
        assert_eq!(sort_txs[0].result_code, 1);
        assert_eq!(sort_txs[0].ciphertext, vec![5u8; 232]);

        assert_eq!(sort_txs[1].search_key, vec![8u8; 16]);
        assert_eq!(sort_txs[1].result_code, 1);
        assert_eq!(sort_txs[1].ciphertext, vec![8u8; 232]);

        assert_eq!(sort_txs[2].search_key, vec![200u8; 16]);
        assert_eq!(sort_txs[2].result_code, 2);
        assert_eq!(sort_txs[2].ciphertext, vec![0u8; 232]);
    }

    assert_eq!(result.missed_block_ranges.len(), 0); // no range reported since we started at event id 4
    assert_eq!(result.last_known_block_count, 6);

    let result = view_client.request(0, 0, vec![vec![200u8; 17]]).unwrap();
    assert_eq!(result.highest_processed_block_count, 6);
    assert_eq!(result.next_start_from_user_event_id, 4);
    assert_eq!(result.rng_records.len(), 2);
    assert_eq!(result.rng_records[0].pubkey, pubkey1);
    assert_eq!(result.rng_records[1].pubkey, pubkey2);
    assert_eq!(result.tx_out_search_results.len(), 1);
    {
        let mut sort_txs = result.tx_out_search_results.clone();
        sort_txs.sort_by(|x, y| x.search_key.cmp(&y.search_key));
        assert_eq!(sort_txs[0].search_key, vec![200u8; 17]);
        assert_eq!(sort_txs[0].result_code, 3);
        assert_eq!(sort_txs[0].ciphertext, vec![0u8; 232]);
    }
    assert_eq!(result.missed_block_ranges.len(), 1);
    assert_eq!(result.missed_block_ranges[0], BlockRange::new(3, 4));
    assert_eq!(result.last_known_block_count, 6);
}

#[test_with_logger]
fn test_view_sql_512(logger: Logger) {
    test_view_integration(512, logger);

    // Sleep before exiting to give view server threads time to join
    std::thread::sleep(std::time::Duration::from_millis(1000));
}

#[test_with_logger]
fn test_view_sql_1mil(logger: Logger) {
    test_view_integration(1024 * 1024, logger);

    // Sleep before exiting to give view server threads time to join
    std::thread::sleep(std::time::Duration::from_millis(1000));
}

/// Ensure that all provided ETxOutRecords are in the enclave, and that
/// non-existing ones aren't.
fn assert_e_tx_out_records_sanity(
    client: &mut FogViewGrpcClient,
    records: &[ETxOutRecord],

    logger: &Logger,
) {
    // Construct an array of expected results that includes both records we expect
    // to find and records we expect not to find.
    let mut expected_results = Vec::new();
    for record in records {
        expected_results.push(TxOutSearchResult {
            search_key: record.search_key.clone(),
            result_code: TxOutSearchResultCode::Found as u32,
            ciphertext: record.payload.clone(),
        });
    }
    for i in 0..3 {
        expected_results.push(TxOutSearchResult {
            search_key: vec![i + 1; 16], // Search key if all zeros is invalid.
            result_code: TxOutSearchResultCode::NotFound as u32,
            ciphertext: vec![0; 64],
        });
    }

    let search_keys: Vec<_> = expected_results
        .iter()
        .map(|result| result.search_key.clone())
        .collect();

    let mut allowed_tries = 60usize;
    loop {
        let result = client.request(0, 0, search_keys.clone()).unwrap();
        if result.tx_out_search_results == expected_results {
            break;
        }

        log::info!(logger, "A {:?}", result.tx_out_search_results);
        log::info!(logger, "B {:?}", expected_results);

        if allowed_tries == 0 {
            panic!("Server did not catch up to database!");
        }
        allowed_tries -= 1;
        std::thread::sleep(Duration::from_millis(1000));
    }
}

/// Test that view server behaves correctly when there is some overlap between
/// two currently active ingest invocations.
#[test_with_logger]
fn test_overlapping_ingest_ranges(logger: Logger) {
    let mut rng: StdRng = SeedableRng::from_seed([123u8; 32]);
    let (db_context, server, mut view_client) = get_test_environment(512, logger.clone());
    let db = db_context.get_db_instance();

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
        let (block, records) = mc_fog_test_infra::db_tests::random_block(&mut rng, i, 5); // 5 outputs per block
        db.add_block_data(&invoc_id1, &block, 0, &records).unwrap();
        expected_records.extend(records);

        let (block, records) = mc_fog_test_infra::db_tests::random_block(&mut rng, i + 10, 5); // start block is 10
        db.add_block_data(&invoc_id2, &block, 0, &records).unwrap();
        expected_records.extend(records);
    }

    let mut allowed_tries = 60usize;
    loop {
        let server_num_blocks = server.highest_processed_block_count();
        if server_num_blocks >= 5 {
            break;
        }
        log::info!(
            logger,
            "Waiting for server to catch up to db... {} < 5",
            server_num_blocks,
        );
        if allowed_tries == 0 {
            panic!("Server did not catch up to database!");
        }
        allowed_tries -= 1;
        std::thread::sleep(Duration::from_millis(1000));
    }

    assert_eq!(server.highest_processed_block_count(), 5);

    assert_e_tx_out_records_sanity(&mut view_client, &expected_records, &logger);

    // Give server time to process some more blocks, although it shouldn't.
    std::thread::sleep(Duration::from_millis(1000));
    assert_eq!(server.highest_processed_block_count(), 5);

    // See that we get a sane client response.
    let result = view_client.request(0, 0, Default::default()).unwrap();
    assert_eq!(result.highest_processed_block_count, 5);
    assert_eq!(result.last_known_block_count, 15); // The last known block is not tied to the serial processing of blocks.

    // Add blocks 5-19 to invoc_id1. This will allow us to query blocks 0-14, since
    // invoc_id2 only has blocks 10-14.
    for i in 5..20 {
        let (block, records) = mc_fog_test_infra::db_tests::random_block(&mut rng, i, 5); // 5 outputs per block
        db.add_block_data(&invoc_id1, &block, 0, &records).unwrap();

        expected_records.extend(records);
    }

    let mut allowed_tries = 60usize;
    loop {
        let server_num_blocks = server.highest_processed_block_count();
        if server_num_blocks >= 15 {
            break;
        }
        log::info!(
            logger,
            "Waiting for server to catch up to db... {} < 15",
            server_num_blocks,
        );
        if allowed_tries == 0 {
            panic!("Server did not catch up to database!");
        }
        allowed_tries -= 1;
        std::thread::sleep(Duration::from_millis(1000));
    }

    assert_eq!(server.highest_processed_block_count(), 15);

    // Give server time to process some more blocks, although it shouldn't.
    let mut allowed_tries = 60usize;
    while allowed_tries > 0 {
        std::thread::sleep(Duration::from_millis(1000));
        allowed_tries -= 1;

        if server.highest_processed_block_count() != 15 {
            continue;
        }

        let result = view_client.request(0, 0, Default::default()).unwrap();
        if result.last_known_block_count != 20 {
            continue;
        }

        break;
    }

    assert_eq!(server.highest_processed_block_count(), 15);

    // See that we get a sane client response.
    let result = view_client.request(0, 0, Default::default()).unwrap();
    assert_eq!(result.highest_processed_block_count, 15);
    assert_eq!(result.last_known_block_count, 20); // The last known block is not tied to the serial processing of blocks.

    // Add blocks 15-30 to invoc_id2, this should bring us to block 20.
    for i in 15..30 {
        let (block, records) = mc_fog_test_infra::db_tests::random_block(&mut rng, i, 5); // 5 outputs per block
        db.add_block_data(&invoc_id2, &block, 0, &records).unwrap();
        expected_records.extend(records);
    }

    let mut allowed_tries = 60usize;
    loop {
        let server_num_blocks = server.highest_processed_block_count();
        if server_num_blocks >= 20 {
            break;
        }
        log::info!(
            logger,
            "Waiting for server to catch up to db... {} < 20",
            server_num_blocks,
        );
        if allowed_tries == 0 {
            panic!("Server did not catch up to database!");
        }
        allowed_tries -= 1;
        std::thread::sleep(Duration::from_millis(1000));
    }

    assert_eq!(server.highest_processed_block_count(), 20);

    // Give server time to process some more blocks, although it shouldn't.
    std::thread::sleep(Duration::from_millis(1000));
    assert_eq!(server.highest_processed_block_count(), 20);

    // See that we get a sane client response.
    let mut allowed_tries = 60usize;
    loop {
        let result = view_client.request(0, 0, Default::default()).unwrap();
        if result.highest_processed_block_count == 20 && result.last_known_block_count == 30 {
            break;
        }

        if allowed_tries == 0 {
            panic!("Server did not catch up to database! highest_processed_block_count = {}, last_known_block_count = {}", result.highest_processed_block_count, result.last_known_block_count);
        }
        allowed_tries -= 1;
        std::thread::sleep(Duration::from_millis(1000));
    }

    // Ensure all ETxOutRecords are searchable
    assert_e_tx_out_records_sanity(&mut view_client, &expected_records, &logger);
}

/// Test that view server behaves correctly when there is a missing range before
/// any ingest invocations.
#[test_with_logger]
fn test_start_with_missing_range(logger: Logger) {
    let mut rng: StdRng = SeedableRng::from_seed([123u8; 32]);
    let (db_context, server, mut view_client) = get_test_environment(512, logger.clone());
    let db = db_context.get_db_instance();

    let ingress_key = CompressedRistrettoPublic::from(RistrettoPublic::from_random(&mut rng));
    db.new_ingress_key(&ingress_key, 5).unwrap();

    // invoc_id1 starts at block 0, but the initial blocks reported are 10-15
    let invoc_id1 = db
        .new_ingest_invocation(None, &ingress_key, &random_kex_rng_pubkey(&mut rng), 5)
        .unwrap();

    // Add 5 blocks to invoc_id1.
    let mut expected_records = Vec::new();
    for i in 10..15 {
        let (block, records) = mc_fog_test_infra::db_tests::random_block(&mut rng, i, 5); // 5 outputs per block
        db.add_block_data(&invoc_id1, &block, 0, &records).unwrap();
        expected_records.extend(records);
    }

    // Give server time to process some more blocks, although it shouldn't.
    std::thread::sleep(Duration::from_millis(1000));
    assert_eq!(server.highest_processed_block_count(), 0);

    // See that we get a sane client response.
    let mut allowed_tries = 60usize;
    loop {
        let result = view_client.request(0, 0, Default::default()).unwrap();
        if result.highest_processed_block_count == 0 && result.last_known_block_count == 0 {
            break;
        }

        if allowed_tries == 0 {
            panic!("Server did not catch up to database! highest_processed_block_count = {}, last_known_block_count = {}", result.highest_processed_block_count, result.last_known_block_count);
        }
        allowed_tries -= 1;
        std::thread::sleep(Duration::from_millis(1000));
    }

    // Adding the first 5 blocks that were the gap
    for i in 5..10 {
        let (block, records) = mc_fog_test_infra::db_tests::random_block(&mut rng, i, 5); // 5 outputs per block
        db.add_block_data(&invoc_id1, &block, 0, &records).unwrap();
        expected_records.extend(records);
    }

    let mut allowed_tries = 60usize;
    loop {
        let result = view_client.request(0, 0, Default::default()).unwrap();
        if result.highest_processed_block_count == 15 && result.last_known_block_count == 15 {
            break;
        }

        if allowed_tries == 0 {
            panic!("Server did not catch up to database! highest_processed_block_count = {}, last_known_block_count = {}", result.highest_processed_block_count, result.last_known_block_count);
        }
        allowed_tries -= 1;
        std::thread::sleep(Duration::from_millis(1000));
    }
    assert_eq!(server.highest_processed_block_count(), 15);

    assert_e_tx_out_records_sanity(&mut view_client, &expected_records, &logger);
}

/// Test that view server behaves correctly when there is a missing range
/// between two ingest invocations.
#[test_with_logger]
fn test_middle_missing_range_with_decommission(logger: Logger) {
    let mut rng: StdRng = SeedableRng::from_seed([123u8; 32]);
    let (db_context, server, mut view_client) = get_test_environment(512, logger.clone());
    let db = db_context.get_db_instance();

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
        let (block, records) = mc_fog_test_infra::db_tests::random_block(&mut rng, i, 5); // 5 outputs per block
        db.add_block_data(&invoc_id1, &block, 0, &records).unwrap();
        expected_records.extend(records);
    }

    // At this point we should be at highest processed block 5, and highest known 5,
    // because ingress key 2 doesn't start until 10, and doesn't have any blocks
    // associated to it yet.
    let mut allowed_tries = 60usize;
    loop {
        let result = view_client.request(0, 0, Default::default()).unwrap();
        if result.highest_processed_block_count == 5 && result.last_known_block_count == 5 {
            break;
        }

        if allowed_tries == 0 {
            panic!("Server did not catch up to database! highest_processed_block_count = {}, last_known_block_count = {}", result.highest_processed_block_count, result.last_known_block_count);
        }
        allowed_tries -= 1;
        std::thread::sleep(Duration::from_millis(1000));
    }
    assert_eq!(server.highest_processed_block_count(), 5);

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
        let (block, records) = mc_fog_test_infra::db_tests::random_block(&mut rng, i, 5); // 5 outputs per block
        db.add_block_data(&invoc_id2, &block, 0, &records).unwrap();
        expected_records.extend(records);
    }

    // At this point invoc_id1 is marked lost, so we should be at highest processed
    // block 10 but the last known block should be 15.
    let mut allowed_tries = 60usize;
    loop {
        let result = view_client.request(0, 0, Default::default()).unwrap();
        if result.highest_processed_block_count == 15 && result.last_known_block_count == 15 {
            break;
        }

        if allowed_tries == 0 {
            panic!("Server did not catch up to database! highest_processed_block_count = {}, last_known_block_count = {}", result.highest_processed_block_count, result.last_known_block_count);
        }
        allowed_tries -= 1;
        std::thread::sleep(Duration::from_millis(1000));
    }
    assert_eq!(server.highest_processed_block_count(), 15);

    // Decommissioning invoc_id1 should allow us to advance to the last block
    // invoc_id2 has processed.
    db.decommission_ingest_invocation(&invoc_id1).unwrap();

    let mut allowed_tries = 60usize;
    loop {
        let result = view_client.request(0, 0, Default::default()).unwrap();
        if result.highest_processed_block_count == 15 && result.last_known_block_count == 15 {
            break;
        }

        if allowed_tries == 0 {
            panic!("Server did not catch up to database! highest_processed_block_count = {}, last_known_block_count = {}", result.highest_processed_block_count, result.last_known_block_count);
        }
        allowed_tries -= 1;
        std::thread::sleep(Duration::from_millis(1000));
    }
    assert_eq!(server.highest_processed_block_count(), 15);

    assert_e_tx_out_records_sanity(&mut view_client, &expected_records, &logger);
}
