// Copyright (c) 2018-2021 The MobileCoin Foundation

use mc_crypto_keys::{CompressedRistrettoPublic, RistrettoPublic};
use mc_fog_kex_rng::KexRngPubkey;
use mc_fog_recovery_db_iface::{
    ETxOutRecord, FogUserEvent, IngestInvocationId, IngressPublicKeyStatus, RecoveryDb, ReportData,
    ReportDb,
};
use mc_fog_types::view::{RngRecord, TxOutSearchResultCode};
use mc_transaction_core::{Block, BlockID, BLOCK_VERSION};
use mc_util_from_random::FromRandom;
use rand_core::{CryptoRng, RngCore};

// Helper: Get num blocks processed or panic
pub fn get_num_blocks(db: &impl RecoveryDb) -> u64 {
    db.get_highest_known_block_index()
        .unwrap()
        .map(|index| index + 1)
        .unwrap_or(0)
}

// Exercise new recovery db apis and check the results
// - Add random blocks and get tx's using new get txs API, check for NotFound
//   result with junk queries
// - Also add random rng records for a random user, check that they see the new
//   rng records as expected depending on cursor value
pub fn recovery_db_smoke_tests_new_apis<DB: RecoveryDb>(
    rng: &mut (impl RngCore + CryptoRng),
    db: &DB,
) {
    let start_height = get_num_blocks(db);
    let ingress_key = CompressedRistrettoPublic::from(RistrettoPublic::from_random(rng));
    db.new_ingress_key(&ingress_key, start_height).unwrap();

    const SEEDS_PER_ROUND: usize = 3;

    let mut start_from_user_event_id = 0;

    for trials in 0..10 {
        let block_index = get_num_blocks(db);
        assert_eq!(
            start_height + trials,
            block_index,
            "unexpected block index: found: {} expected {}",
            block_index,
            start_height + trials
        );

        // Test that they have no rng records when the cursor value is up-to-date
        let (user_events, _next_start_from_user_event_id) =
            db.search_user_events(start_from_user_event_id).unwrap();
        let has_rng_events = user_events
            .iter()
            .any(|event| matches!(event, FogUserEvent::NewRngRecord(_)));
        assert!(!has_rng_events);

        // Make some test rng record rows by creating new ingest invocations.
        let kex_rng_pubkeys: Vec<KexRngPubkey> = (0..SEEDS_PER_ROUND)
            .map(|_| random_kex_rng_pubkey(rng))
            .collect();

        let invoc_ids_with_kex_rng_pubkeys: Vec<_> = kex_rng_pubkeys
            .iter()
            .map(|kex_rng_pubkey| {
                let invoc_id = db
                    .new_ingest_invocation(None, &ingress_key, kex_rng_pubkey, block_index)
                    .unwrap();

                (invoc_id, kex_rng_pubkey.clone())
            })
            .collect();

        // Test that the user can see them
        {
            let (user_events, next_start_from_user_event_id) =
                db.search_user_events(start_from_user_event_id).unwrap();
            let num_rng_events = user_events
                .iter()
                .filter(|event| matches!(event, FogUserEvent::NewRngRecord(_)))
                .count();
            assert_eq!(
                num_rng_events, SEEDS_PER_ROUND,
                "unexpected number of rng events: found {} expected {}",
                num_rng_events, SEEDS_PER_ROUND
            );

            assert_rng_record_rows_were_recovered(
                &user_events[..],
                &invoc_ids_with_kex_rng_pubkeys[..],
                block_index,
            );

            // Test that the next cursor value for the user is correct.
            assert_eq!(
                next_start_from_user_event_id as u64,
                (trials + 1) * SEEDS_PER_ROUND as u64,
                "unexpected next_start_from_user_event_id value: found {} expected {}",
                next_start_from_user_event_id,
                (trials + 1) * SEEDS_PER_ROUND as u64
            );
        }

        // Make a new block with 10 transactions, and smoke test the get_tx_outs api
        test_recovery_db_txs_new_apis(
            &invoc_ids_with_kex_rng_pubkeys[0].0,
            rng,
            block_index,
            10,
            db,
        );

        // Test that the user can still see those rng records at
        // start_from_user_event_id.
        {
            let (user_events, next_start_from_user_event_id) =
                db.search_user_events(start_from_user_event_id).unwrap();
            assert_rng_record_rows_were_recovered(
                &user_events[..],
                &invoc_ids_with_kex_rng_pubkeys[..],
                block_index,
            );

            // On next trial, start from where this one ended.
            start_from_user_event_id = next_start_from_user_event_id;
        }

        // Test that the user cannot see those rng records at the updated
        // start_from_user_event_id
        {
            let (user_events, next_start_from_user_event_id) =
                db.search_user_events(start_from_user_event_id).unwrap();
            assert_eq!(user_events.len(), 0);
            assert_eq!(
                next_start_from_user_event_id, start_from_user_event_id,
                "expected next_start_from_user_event_id not to be different: found {} expected {}",
                next_start_from_user_event_id, start_from_user_event_id
            );
        }
    }

    // Test that if user tries full recovery (cursor = 0) they get 10 rounds worth
    // of rng records
    let (user_events, _next_start_from_user_event_id) = db.search_user_events(0).unwrap();
    let num_rng_events = user_events
        .iter()
        .filter(|event| matches!(event, FogUserEvent::NewRngRecord(_)))
        .count();

    assert_eq!(
        num_rng_events,
        10 * SEEDS_PER_ROUND,
        "unexpected number of rng events: found {} expected {}",
        num_rng_events,
        3 * SEEDS_PER_ROUND
    );
}

// Basic tests that missed blocks reporting works as expected
pub fn recovery_db_missed_blocks_reporting(
    rng: &mut (impl RngCore + CryptoRng),
    db: &(impl RecoveryDb + ReportDb),
) {
    let ingress_key = CompressedRistrettoPublic::from(RistrettoPublic::from_random(rng));
    db.new_ingress_key(&ingress_key, 0).unwrap();

    db.report_lost_ingress_key(ingress_key).unwrap();
    let status = db.get_ingress_key_status(&ingress_key).unwrap().unwrap();
    assert!(status.lost);

    let ingress_key = CompressedRistrettoPublic::from(RistrettoPublic::from_random(rng));
    db.new_ingress_key(&ingress_key, 10).unwrap();
    db.set_report(
        &ingress_key,
        "",
        &ReportData {
            pubkey_expiry: 20,
            ingest_invocation_id: None,
            report: Default::default(),
        },
    )
    .unwrap();

    db.report_lost_ingress_key(ingress_key).unwrap();
    let status = db.get_ingress_key_status(&ingress_key).unwrap().unwrap();
    assert!(status.lost);
    assert_eq!(status.start_block, 10);
    assert_eq!(status.pubkey_expiry, 20);

    let missed_block_ranges = db.get_missed_block_ranges().unwrap();
    assert!(
        missed_block_ranges
            .iter()
            .any(|range| range.start_block == 10 && range.end_block == 20),
        "Didn't find a missed block range that we expected to find"
    );

    // Make another key, this one overlapping the previous missed range
    let ingress_key = CompressedRistrettoPublic::from(RistrettoPublic::from_random(rng));
    db.new_ingress_key(&ingress_key, 15).unwrap();
    db.set_report(
        &ingress_key,
        "",
        &ReportData {
            pubkey_expiry: 25,
            ingest_invocation_id: None,
            report: Default::default(),
        },
    )
    .unwrap();

    db.report_lost_ingress_key(ingress_key).unwrap();
    let status = db.get_ingress_key_status(&ingress_key).unwrap().unwrap();
    assert!(status.lost);
    assert_eq!(status.start_block, 15);
    assert_eq!(status.pubkey_expiry, 25);

    let missed_block_ranges = db.get_missed_block_ranges().unwrap();
    assert!(
        missed_block_ranges
            .iter()
            .any(|range| range.start_block == 10 && range.end_block == 20),
        "Didn't find a missed block range that we expected to find"
    );
    assert!(
        missed_block_ranges
            .iter()
            .any(|range| range.start_block == 15 && range.end_block == 25),
        "Didn't find a missed block range that we expected to find"
    );
}

// Basic tests that rng records decommissioning works as expected
pub fn recovery_db_rng_records_decommissioning<DB: RecoveryDb>(
    rng: &mut (impl RngCore + CryptoRng),
    db: &DB,
) {
    let ingress_key = CompressedRistrettoPublic::from_random(rng);
    db.new_ingress_key(&ingress_key, 0).unwrap();

    // We start without any rng record events.
    let (user_events, _next_start_from_user_event_id) = db.search_user_events(0).unwrap();
    let has_rng_events = user_events
        .iter()
        .any(|event| matches!(event, FogUserEvent::NewRngRecord(_)));
    assert!(!has_rng_events);

    // Add an ingest invocation.
    let kex_rng_pubkey1 = random_kex_rng_pubkey(rng);
    let invoc_id1 = db
        .new_ingest_invocation(None, &ingress_key, &kex_rng_pubkey1, 0)
        .unwrap();

    // Test that user has rng record event now
    let test_rows0 = vec![kex_rng_pubkey1];

    let (user_events, next_start_from_user_event_id) = db.search_user_events(0).unwrap();
    let rng_records: Vec<RngRecord> = user_events
        .iter()
        .filter_map(|event| {
            if let FogUserEvent::NewRngRecord(rng_record) = event {
                Some(rng_record.clone())
            } else {
                None
            }
        })
        .collect();
    assert_eq!(rng_records.len(), 1);
    assert_eq!(
        invoc_id1,
        IngestInvocationId::from(rng_records[0].ingest_invocation_id),
    );
    assert_eq!(test_rows0[0], rng_records[0].pubkey);
    assert_eq!(0, rng_records[0].start_block);

    // Test that user has no new rngs after cursor update
    let (user_events, _next_start_from_user_event_id) = db
        .search_user_events(next_start_from_user_event_id)
        .unwrap();
    assert_eq!(user_events, vec![]);

    // Add a second invocation
    let kex_rng_pubkey2 = random_kex_rng_pubkey(rng);
    let invoc_id2 = db
        .new_ingest_invocation(
            None,
            &ingress_key,
            &kex_rng_pubkey2,
            10, // start block 10
        )
        .unwrap();

    // Check that if starting at next_start_from_user_event_id we only see the
    // second rng
    let test_rows1 = vec![kex_rng_pubkey2];

    let (user_events, _next_start_from_user_event_id) = db
        .search_user_events(next_start_from_user_event_id)
        .unwrap();
    let rng_records: Vec<RngRecord> = user_events
        .iter()
        .filter_map(|event| {
            if let FogUserEvent::NewRngRecord(rng_record) = event {
                Some(rng_record.clone())
            } else {
                None
            }
        })
        .collect();
    assert_eq!(rng_records.len(), 1);
    assert_eq!(
        invoc_id2,
        IngestInvocationId::from(rng_records[0].ingest_invocation_id),
    );
    assert_eq!(test_rows1[0], rng_records[0].pubkey);
    assert_eq!(10, rng_records[0].start_block);

    // Check that if starting at 0 we see both rngs
    let (user_events, _next_start_from_user_event_id) = db.search_user_events(0).unwrap();
    let rng_records: Vec<RngRecord> = user_events
        .iter()
        .filter_map(|event| {
            if let FogUserEvent::NewRngRecord(rng_record) = event {
                Some(rng_record.clone())
            } else {
                None
            }
        })
        .collect();
    assert_eq!(rng_records.len(), 2);

    assert_eq!(
        invoc_id1,
        IngestInvocationId::from(rng_records[0].ingest_invocation_id),
    );
    assert_eq!(test_rows0[0], rng_records[0].pubkey);
    assert_eq!(0, rng_records[0].start_block);

    assert_eq!(
        invoc_id2,
        IngestInvocationId::from(rng_records[1].ingest_invocation_id),
    );
    assert_eq!(test_rows1[0], rng_records[1].pubkey);
    assert_eq!(10, rng_records[1].start_block);

    // Check ingestable ranges - we should see two for each of our invocations.
    let ingestable_ranges = db.get_ingestable_ranges().unwrap();
    assert_eq!(ingestable_ranges.len(), 2);

    assert_eq!(ingestable_ranges[0].id, invoc_id1);
    assert_eq!(ingestable_ranges[0].start_block, 0);
    assert_eq!(ingestable_ranges[0].decommissioned, false);
    assert_eq!(ingestable_ranges[0].last_ingested_block, None);

    assert_eq!(ingestable_ranges[1].id, invoc_id2);
    assert_eq!(ingestable_ranges[1].start_block, 10);
    assert_eq!(ingestable_ranges[1].decommissioned, false);
    assert_eq!(ingestable_ranges[1].last_ingested_block, None);

    // Add two blocks to invoc_id1, advancing its last_ingested_block.
    let (meta, test_rows) = random_block(rng, 0, 10);
    db.add_block_data(&invoc_id1, &meta, 0, &test_rows).unwrap();

    let (meta, test_rows) = random_block(rng, 1, 10);
    db.add_block_data(&invoc_id1, &meta, 0, &test_rows).unwrap();

    let ingestable_ranges = db.get_ingestable_ranges().unwrap();
    assert_eq!(ingestable_ranges.len(), 2);

    assert_eq!(ingestable_ranges[0].id, invoc_id1);
    assert_eq!(ingestable_ranges[0].start_block, 0);
    assert_eq!(ingestable_ranges[0].decommissioned, false);
    assert_eq!(ingestable_ranges[0].last_ingested_block, Some(1));

    assert_eq!(ingestable_ranges[1].id, invoc_id2);
    assert_eq!(ingestable_ranges[1].start_block, 10);
    assert_eq!(ingestable_ranges[1].decommissioned, false);
    assert_eq!(ingestable_ranges[1].last_ingested_block, None);

    // Decommission invoc_id1
    db.decommission_ingest_invocation(&invoc_id1).unwrap();

    let ingestable_ranges = db.get_ingestable_ranges().unwrap();
    assert_eq!(ingestable_ranges.len(), 2);

    assert_eq!(ingestable_ranges[0].id, invoc_id1);
    assert_eq!(ingestable_ranges[0].start_block, 0);
    assert_eq!(ingestable_ranges[0].decommissioned, true);
    assert_eq!(ingestable_ranges[0].last_ingested_block, Some(1));

    assert_eq!(ingestable_ranges[1].id, invoc_id2);
    assert_eq!(ingestable_ranges[1].start_block, 10);
    assert_eq!(ingestable_ranges[1].decommissioned, false);
    assert_eq!(ingestable_ranges[1].last_ingested_block, None);

    // Check if we can see an event for that.
    let (user_events, _next_start_from_user_event_id) = db.search_user_events(0).unwrap();
    let decommissioned_invocs: Vec<_> = user_events
        .iter()
        .filter_map(|event| {
            if let FogUserEvent::DecommissionIngestInvocation(details) = event {
                Some(details.clone())
            } else {
                None
            }
        })
        .collect();
    assert_eq!(decommissioned_invocs.len(), 1);
    assert_eq!(
        IngestInvocationId::from(decommissioned_invocs[0].ingest_invocation_id),
        invoc_id1
    );
    assert_eq!(1, decommissioned_invocs[0].last_ingested_block);

    // Add some blocks to invoc_id2, decommission and test that we can see the data
    // we expect.
    for block_index in 10..13 {
        let (meta, test_rows) = random_block(rng, block_index, 10);
        db.add_block_data(&invoc_id2, &meta, 0, &test_rows).unwrap();
    }

    let ingestable_ranges = db.get_ingestable_ranges().unwrap();
    assert_eq!(ingestable_ranges.len(), 2);

    assert_eq!(ingestable_ranges[0].id, invoc_id1);
    assert_eq!(ingestable_ranges[0].start_block, 0);
    assert_eq!(ingestable_ranges[0].decommissioned, true);
    assert_eq!(ingestable_ranges[0].last_ingested_block, Some(1));

    assert_eq!(ingestable_ranges[1].id, invoc_id2);
    assert_eq!(ingestable_ranges[1].start_block, 10);
    assert_eq!(ingestable_ranges[1].decommissioned, false);
    assert_eq!(ingestable_ranges[1].last_ingested_block, Some(12));

    // Decommission by replacing it with a newer ingest invocation.
    let invoc_id3 = db
        .new_ingest_invocation(
            Some(invoc_id2),
            &ingress_key,
            &random_kex_rng_pubkey(rng),
            100, // start block 100
        )
        .unwrap();

    let ingestable_ranges = db.get_ingestable_ranges().unwrap();
    assert_eq!(ingestable_ranges.len(), 3);

    assert_eq!(ingestable_ranges[0].id, invoc_id1);
    assert_eq!(ingestable_ranges[0].start_block, 0);
    assert_eq!(ingestable_ranges[0].decommissioned, true);
    assert_eq!(ingestable_ranges[0].last_ingested_block, Some(1));

    assert_eq!(ingestable_ranges[1].id, invoc_id2);
    assert_eq!(ingestable_ranges[1].start_block, 10);
    assert_eq!(ingestable_ranges[1].decommissioned, true);
    assert_eq!(ingestable_ranges[1].last_ingested_block, Some(12));

    assert_eq!(ingestable_ranges[2].id, invoc_id3);
    assert_eq!(ingestable_ranges[2].start_block, 100);
    assert_eq!(ingestable_ranges[2].decommissioned, false);
    assert_eq!(ingestable_ranges[2].last_ingested_block, None);

    let (user_events, _next_start_from_user_event_id) = db.search_user_events(0).unwrap();
    let decommissioned_invocs: Vec<_> = user_events
        .iter()
        .filter_map(|event| {
            if let FogUserEvent::DecommissionIngestInvocation(details) = event {
                Some(details.clone())
            } else {
                None
            }
        })
        .collect();
    assert_eq!(decommissioned_invocs.len(), 2);

    assert_eq!(
        IngestInvocationId::from(decommissioned_invocs[0].ingest_invocation_id),
        invoc_id1
    );
    assert_eq!(1, decommissioned_invocs[0].last_ingested_block);

    assert_eq!(
        IngestInvocationId::from(decommissioned_invocs[1].ingest_invocation_id),
        invoc_id2
    );
    assert_eq!(12, decommissioned_invocs[1].last_ingested_block);
}

// Basic tests that creating, checking on, and retiring ingress keys works as
// expected
pub fn test_recovery_db_ingress_keys<DB: RecoveryDb>(
    mut rng: &mut (impl RngCore + CryptoRng),
    db: &DB,
) {
    let ingress_key1 = CompressedRistrettoPublic::from(RistrettoPublic::from_random(&mut rng));

    assert_eq!(db.get_ingress_key_status(&ingress_key1).unwrap(), None);

    assert!(db.new_ingress_key(&ingress_key1, 1).unwrap());

    assert_eq!(
        db.get_ingress_key_status(&ingress_key1).unwrap(),
        Some(IngressPublicKeyStatus {
            start_block: 1,
            pubkey_expiry: 0,
            retired: false,
            lost: false,
        })
    );

    let ingress_key2 = CompressedRistrettoPublic::from(RistrettoPublic::from_random(&mut rng));

    assert_eq!(db.get_ingress_key_status(&ingress_key2).unwrap(), None);

    assert!(db.new_ingress_key(&ingress_key2, 10).unwrap());

    assert_eq!(
        db.get_ingress_key_status(&ingress_key2).unwrap(),
        Some(IngressPublicKeyStatus {
            start_block: 10,
            pubkey_expiry: 0,
            retired: false,
            lost: false,
        })
    );

    assert!(!db.new_ingress_key(&ingress_key1, 2).unwrap());
    assert!(!db.new_ingress_key(&ingress_key2, 10).unwrap());

    assert_eq!(
        db.get_ingress_key_status(&ingress_key1).unwrap(),
        Some(IngressPublicKeyStatus {
            start_block: 1,
            pubkey_expiry: 0,
            retired: false,
            lost: false,
        })
    );

    assert_eq!(
        db.get_ingress_key_status(&ingress_key2).unwrap(),
        Some(IngressPublicKeyStatus {
            start_block: 10,
            pubkey_expiry: 0,
            retired: false,
            lost: false,
        })
    );

    db.retire_ingress_key(&ingress_key1, true).unwrap();

    assert_eq!(
        db.get_ingress_key_status(&ingress_key1).unwrap(),
        Some(IngressPublicKeyStatus {
            start_block: 1,
            pubkey_expiry: 0,
            retired: true,
            lost: false,
        })
    );

    db.retire_ingress_key(&ingress_key1, false).unwrap();

    assert_eq!(
        db.get_ingress_key_status(&ingress_key1).unwrap(),
        Some(IngressPublicKeyStatus {
            start_block: 1,
            pubkey_expiry: 0,
            retired: false,
            lost: false,
        })
    );

    // Now check if get_last_scanned_block_index is working
    assert_eq!(
        db.get_last_scanned_block_index(&ingress_key1).unwrap(),
        None
    );

    // Add an ingest invocation.
    let kex_rng_pubkey1 = random_kex_rng_pubkey(&mut rng);
    let invoc_id1 = db
        .new_ingest_invocation(None, &ingress_key1, &kex_rng_pubkey1, 0)
        .unwrap();

    // Add a block
    let (meta, test_rows) = random_block(rng, 1, 20);
    db.add_block_data(&invoc_id1, &meta, 0, &test_rows).unwrap();

    assert_eq!(
        db.get_last_scanned_block_index(&ingress_key1).unwrap(),
        Some(1)
    );

    let (meta, test_rows) = random_block(rng, 2, 20);
    db.add_block_data(&invoc_id1, &meta, 0, &test_rows).unwrap();

    assert_eq!(
        db.get_last_scanned_block_index(&ingress_key1).unwrap(),
        Some(2)
    );
}

// Lower level test routines

// Exercise recovery db apis for writing and reading tx_rows
fn test_recovery_db_txs_new_apis(
    ingest_invocation_id: &IngestInvocationId,
    rng: &mut impl RngCore,
    block_index: u64,
    num_txs: usize,
    db: &impl RecoveryDb,
) {
    let (meta, test_rows) = random_block(rng, block_index, num_txs);
    db.add_block_data(ingest_invocation_id, &meta, 0, &test_rows)
        .unwrap();

    let mut search_keys: Vec<Vec<u8>> =
        test_rows.iter().map(|row| row.search_key.clone()).collect();

    // Try a random search key also and test that it is not found
    let mut random_search_key = vec![0u8; search_keys[0].len()];
    rng.fill_bytes(&mut random_search_key[..]);
    search_keys.push(random_search_key.clone());

    let results = db.get_tx_outs(0, &search_keys[..]).unwrap();

    for row in test_rows {
        assert!(results.iter().any(|res| &res.search_key[..]
            == AsRef::<[u8]>::as_ref(&row.search_key)
            && res.ciphertext == row.payload
            && res.result_code == TxOutSearchResultCode::Found as u32));
    }

    assert!(results.iter().any(|res| res.search_key == random_search_key
        && res.result_code == TxOutSearchResultCode::NotFound as u32));
}

// Helpers for testing FogUserNewEvents structures
fn assert_rng_record_rows_were_recovered(
    events: &[FogUserEvent],
    invoc_ids_with_kex_rng_pubkeys: &[(IngestInvocationId, KexRngPubkey)],
    start_block: u64,
) {
    for (invoc_id, kex_rng_pubkey) in invoc_ids_with_kex_rng_pubkeys {
        assert!(events.iter().any(|event| {
            if let FogUserEvent::NewRngRecord(rng_record) = event {
                IngestInvocationId::from(rng_record.ingest_invocation_id) == *invoc_id
                    && rng_record.pubkey == *kex_rng_pubkey
                    && rng_record.start_block == start_block
            } else {
                false
            }
        }));
    }
}

// Helpers for sampling random structures
pub fn random_block(
    rng: &mut impl RngCore,
    block_index: u64,
    num_txs: usize,
) -> (Block, Vec<ETxOutRecord>) {
    let block = Block::new(
        BLOCK_VERSION,
        &BlockID::default(),
        block_index,
        0,
        &Default::default(),
        &Default::default(),
    );
    let test_rows: Vec<ETxOutRecord> = (0..num_txs).map(|_| random_tx_row(rng)).collect();
    (block, test_rows)
}

pub fn random_tx_row(rng: &mut impl RngCore) -> ETxOutRecord {
    let mut result: ETxOutRecord = Default::default();
    result.search_key.resize(16, 0);
    result.payload.resize(64, 0);
    rng.fill_bytes(&mut result.search_key[..]);
    rng.fill_bytes(&mut result.payload[..]);
    result
}

pub fn random_kex_rng_pubkey(rng: &mut impl RngCore) -> KexRngPubkey {
    KexRngPubkey {
        public_key: random_32_bytes(rng).to_vec(),
        version: rng.next_u32(),
    }
}

pub fn random_32_bytes(rng: &mut impl RngCore) -> [u8; 32] {
    let mut temp = [0u8; 32];
    rng.fill_bytes(&mut temp);
    temp
}
