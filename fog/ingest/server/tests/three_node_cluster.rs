// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Tests involving activation and retiry of a three node ingest cluster

use mc_attest_net::{Client as AttestClient, RaClient};
use mc_common::{
    logger::{log, o, test_with_logger, Logger},
    ResponderId,
};
use mc_crypto_keys::{CompressedRistrettoPublic, Ed25519Pair, RistrettoPublic};
use mc_fog_ingest_server::{
    error::IngestServiceError,
    server::{IngestServer, IngestServerConfig},
    state_file::StateFile,
};
use mc_fog_recovery_db_iface::{IngestInvocationId, RecoveryDb};
use mc_fog_sql_recovery_db::{test_utils::SqlRecoveryDbTestContext, SqlRecoveryDb};
use mc_fog_test_infra::get_enclave_path;
use mc_fog_uri::{FogIngestUri, IngestPeerUri};
use mc_ledger_db::{Ledger, LedgerDB};
use mc_transaction_core::{
    encrypted_fog_hint::EncryptedFogHint,
    membership_proofs::Range,
    ring_signature::KeyImage,
    tx::{TxOut, TxOutMembershipElement, TxOutMembershipHash},
    Amount, Block, BlockContents, BlockData, BlockSignature, BLOCK_VERSION,
};
use mc_util_from_random::FromRandom;
use mc_watcher::watcher_db::WatcherDB;
use rand_core::{CryptoRng, RngCore, SeedableRng};
use rand_hc::Hc128Rng;
use std::{
    collections::BTreeSet,
    convert::TryFrom,
    path::Path,
    str::FromStr,
    time::{Duration, Instant, SystemTime},
};
use tempdir::TempDir;
use url::Url;

const OMAP_CAPACITY: u64 = 4096;
const BASE_PORT: u16 = 4997;

// Helper which makes URIs and responder id for i'th server
fn make_uris(idx: u16) -> (ResponderId, FogIngestUri, IngestPeerUri) {
    let base_port = BASE_PORT + 10 * idx;

    let local_node_id = ResponderId::from_str(&format!("0.0.0.0:{}", base_port + 5)).unwrap();
    let client_listen_uri =
        FogIngestUri::from_str(&format!("insecure-fog-ingest://0.0.0.0:{}/", base_port + 4))
            .unwrap();
    let peer_listen_uri =
        IngestPeerUri::from_str(&format!("insecure-igp://0.0.0.0:{}/", base_port + 5)).unwrap();

    (local_node_id, client_listen_uri, peer_listen_uri)
}

// Helper which makes i'th server and temp dir for its stuff (deleted when
// objects are dropped)
fn make_node(
    idx: u16,
    peer_idxs: impl Iterator<Item = u16>,
    db: SqlRecoveryDb,
    watcher_path: &Path,
    ledger_db_path: &Path,
    logger: Logger,
) -> (IngestServer<AttestClient, SqlRecoveryDb>, TempDir) {
    let logger = logger.new(o!("mc.node_id" => idx.to_string()));

    let (local_node_id, client_listen_uri, peer_listen_uri) = make_uris(idx);

    let peers: BTreeSet<IngestPeerUri> = peer_idxs.map(|idx| make_uris(idx).2).collect();

    let state_tmp = TempDir::new("ingest_state").expect("Could not make tempdir for ingest state");
    let state_file = state_tmp.path().join("mc-ingest-state");

    let config = IngestServerConfig {
        ias_spid: Default::default(),
        local_node_id,
        client_listen_uri,
        peer_listen_uri,
        peers,
        fog_report_id: Default::default(),
        max_transactions: 10_000,
        pubkey_expiry_window: 10,
        peer_checkup_period: Some(Duration::from_secs(5)),
        watcher_timeout: Duration::from_secs(5),
        state_file: Some(StateFile::new(state_file)),
        enclave_path: get_enclave_path(mc_fog_ingest_enclave::ENCLAVE_FILE),
        omap_capacity: OMAP_CAPACITY,
    };

    // Open the Watcher DB
    let watcher = WatcherDB::open_ro(watcher_path, logger.clone()).unwrap();

    // Open the ledger db
    let ledger_db = LedgerDB::open(ledger_db_path).unwrap();

    let ra_client = AttestClient::new("").expect("Could not create IAS client");
    let mut node = IngestServer::new(config, ra_client, db, watcher, ledger_db, logger);
    node.start().expect("couldn't start node");

    (node, state_tmp)
}

// Add an arbitrary block to ledger and a timestamp for it
fn add_test_block<T: RngCore + CryptoRng>(ledger: &mut LedgerDB, watcher: &WatcherDB, rng: &mut T) {
    // Make the new block and append to database
    let num_blocks = ledger.num_blocks().expect("Could not compute num_blocks");
    assert_ne!(0, num_blocks);
    let tx_source_url = Url::from_str("https://localhost").unwrap();

    let last_block = ledger
        .get_block(num_blocks - 1)
        .expect("Could not get last block");

    let key_images = vec![KeyImage::from(rng.next_u64())];

    let block_contents = BlockContents::new(key_images, random_output(rng));

    // Fake proofs
    let root_element = TxOutMembershipElement {
        range: Range::new(0, num_blocks as u64).unwrap(),
        hash: TxOutMembershipHash::from([0u8; 32]),
    };

    let block = Block::new_with_parent(BLOCK_VERSION, &last_block, &root_element, &block_contents);

    let signer = Ed25519Pair::from_random(rng);

    let mut block_sig = BlockSignature::from_block_and_keypair(&block, &signer).unwrap();
    block_sig.set_signed_at(
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    );

    ledger
        .append_block(&block, &block_contents, None)
        .expect("Could not append block");

    let block_data = BlockData::new(block, block_contents, Some(block_sig.clone()));

    watcher
        .add_block_data(&tx_source_url, &block_data)
        .expect("Could not add block data to watcher");

    watcher
        .add_block_signature(&tx_source_url, num_blocks, block_sig, "archive".to_string())
        .expect("Could not add block signature to watcher");
}

// Make a random output for a block
fn random_output<T: RngCore + CryptoRng>(rng: &mut T) -> Vec<TxOut> {
    vec![TxOut {
        amount: Amount::default(),
        target_key: RistrettoPublic::from_random(rng).into(),
        public_key: RistrettoPublic::from_random(rng).into(),
        e_fog_hint: EncryptedFogHint::default(),
        e_memo: None,
    }]
}

// Wait for recovery db to match ledger
fn wait_for_sync(ledger: &LedgerDB, recovery_db: &SqlRecoveryDb, logger: &Logger) {
    let start = Instant::now();
    loop {
        let recovery_db_count = recovery_db
            .get_highest_known_block_index()
            .unwrap()
            .unwrap_or_default()
            + 1;
        let ledger_db_count = ledger.num_blocks().unwrap();
        log::info!(
            logger,
            "recovery_db: {}, ledger_db: {}",
            recovery_db_count,
            ledger_db_count
        );
        if recovery_db_count >= ledger_db_count {
            break;
        }
        if Instant::now().duration_since(start) > Duration::from_secs(60) {
            panic!("Timed out waiting for active node to process data");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

// Test that a three node cluster that starts with all nodes in the idle state,
// and then one of them is activated, seems to behave corretly as we add test
// blocks. Then retire it and confirm that they all transition to idle.
// Then try to activate one of them again, and confirm that it goes immediately
// to idle because the key is retired in the DB.
#[test_with_logger]
fn three_node_cluster_activation_retiry(logger: Logger) {
    let mut rng: Hc128Rng = SeedableRng::from_seed([0u8; 32]);

    let db_test_context = SqlRecoveryDbTestContext::new(logger.clone());
    let recovery_db = db_test_context.get_db_instance();

    let blockchain_path =
        TempDir::new("blockchain").expect("Could not make tempdir for blockchain state");

    // Set up the Watcher DB - create a new watcher DB for each phase
    let watcher_path = blockchain_path.path().join("watcher");
    std::fs::create_dir(&watcher_path).expect("couldn't create dir");
    WatcherDB::create(&watcher_path).unwrap();
    // Open the watcher db
    let tx_source_url = Url::from_str("https://localhost").unwrap();
    let watcher = mc_watcher::watcher_db::WatcherDB::open_rw(
        &watcher_path,
        &[tx_source_url.clone()],
        logger.clone(),
    )
    .expect("Could not create watcher_db");

    // Set up an empty ledger db.
    let ledger_db_path = blockchain_path.path().join("ledger_db");
    std::fs::create_dir(&ledger_db_path).expect("couldn't create dir");
    LedgerDB::create(&ledger_db_path).unwrap();
    let mut ledger = LedgerDB::open(&ledger_db_path).unwrap();

    // make origin block before starting any fog servers
    let origin_txo = random_output(&mut rng);
    let origin_contents = BlockContents {
        key_images: Default::default(),
        outputs: origin_txo.clone(),
    };
    let origin_block = Block::new_origin_block(&origin_txo);
    ledger
        .append_block(&origin_block, &origin_contents, None)
        .expect("failed writing initial transactions");

    // there will be 3 peers in the cluster
    let peer_indices = vec![0u16, 1u16, 2u16];

    // Do three repetitions of the whole thing
    for _ in 0..3 {
        let (node0, _node0dir) = make_node(
            0,
            peer_indices.iter().cloned(),
            db_test_context.get_db_instance(),
            &watcher_path,
            &ledger_db_path,
            logger.clone(),
        );
        let (node1, _node1dir) = make_node(
            1,
            peer_indices.iter().cloned(),
            db_test_context.get_db_instance(),
            &watcher_path,
            &ledger_db_path,
            logger.clone(),
        );
        let (node2, _node2dir) = make_node(
            2,
            peer_indices.iter().cloned(),
            db_test_context.get_db_instance(),
            &watcher_path,
            &ledger_db_path,
            logger.clone(),
        );

        assert!(!node0.is_active());
        assert!(!node1.is_active());
        assert!(!node2.is_active());

        let node0_key = node0.get_ingest_summary().get_ingress_pubkey().clone();
        let node1_key = node1.get_ingest_summary().get_ingress_pubkey().clone();
        let node2_key = node2.get_ingest_summary().get_ingress_pubkey().clone();

        assert_ne!(node0_key, node1_key);
        assert_ne!(node0_key, node2_key);

        // Give RPC etc. time to start
        std::thread::sleep(Duration::from_millis(1000));

        node0.activate().expect("node0 failed to activate");

        assert!(node0.is_active());
        assert!(!node1.is_active());
        assert!(!node2.is_active());

        assert_eq!(
            node0_key,
            node0.get_ingest_summary().get_ingress_pubkey().clone(),
            "node0 key changed after activating, unexpectedly!"
        );

        let node1_key = node1.get_ingest_summary().get_ingress_pubkey().clone();
        let node2_key = node2.get_ingest_summary().get_ingress_pubkey().clone();

        assert_eq!(node0_key, node1_key);
        assert_eq!(node0_key, node2_key);

        assert!(
            node1.activate().is_err(),
            "node1 should not have been able to activate"
        );
        assert!(
            node2.activate().is_err(),
            "node2 should not have been able to activate"
        );

        assert!(node0.is_active());
        assert!(!node1.is_active());
        assert!(!node2.is_active());

        for _ in 0..10 {
            add_test_block(&mut ledger, &watcher, &mut rng);
        }

        // Wait 10s for active node to have processed everything
        wait_for_sync(&ledger, &recovery_db, &logger);

        assert!(node0.is_active());
        assert!(!node1.is_active());
        assert!(!node2.is_active());

        node0.retire().unwrap();

        assert!(
            node0.is_active(),
            "Node 0 should still be in the active state, but its key is in the retiring state"
        );
        assert!(!node1.is_active());
        assert!(!node2.is_active());

        for _ in 0..10 {
            add_test_block(&mut ledger, &watcher, &mut rng);
        }

        // Wait 10s for active node to have processed everything
        wait_for_sync(&ledger, &recovery_db, &logger);

        // We now hit the pubkey expiry, so when the active node hits the next block, it
        // will switch off instead of processing it. Because it won't process
        // it, wait_for_sync won't terminate, so we just put a sleep instead.
        add_test_block(&mut ledger, &watcher, &mut rng);
        std::thread::sleep(Duration::from_secs(1));

        assert!(!node0.is_active(), "Node zero should become inactive after it hits the pubkey expiry value after we retire the key");
        assert!(!node1.is_active());
        assert!(!node2.is_active());

        let node0_key = CompressedRistrettoPublic::try_from(&node0_key).unwrap();

        match node0.activate() {
            Ok(_) => {
                panic!("Node 0 should not have been able to activate, the key is retired now");
            }
            Err(IngestServiceError::KeyAlreadyRetired(key)) => {
                assert_eq!(key, node0_key);
            }
            Err(err) => {
                panic!("Unexpected error when trying to activate node0, should have got KeyAlreadyRetired: {}", err);
            }
        };

        match node1.activate() {
            Ok(_) => {
                panic!("Node 1 should not have been able to activate, the key is retired now");
            }
            Err(IngestServiceError::KeyAlreadyRetired(key)) => {
                assert_eq!(key, node0_key);
            }
            Err(err) => {
                panic!("Unexpected error when trying to activate node1, should have got KeyAlreadyRetired: {}", err);
            }
        };

        match node2.activate() {
            Ok(_) => {
                panic!("Node 2 should not have been able to activate, the key is retired now");
            }
            Err(IngestServiceError::KeyAlreadyRetired(key)) => {
                assert_eq!(key, node0_key);
            }
            Err(err) => {
                panic!("Unexpected error when trying to activate node2, should have got KeyAlreadyRetired: {}", err);
            }
        };

        assert!(!node0.is_active());
        assert!(!node1.is_active());
        assert!(!node2.is_active());

        drop(node0);
        drop(node1);
        drop(node2);

        std::thread::sleep(Duration::from_secs(5));
    }
}

// "Fencing" is a term used in k8s go leader election docu, which they say
// means, that we prevent two leaders from existing simultaneously without fail.
//
// This test has to do with, creating a situation where two leaders are active,
// and checking that the database constraint causes exactly one of them to
// become idle when they attempt to write the same block.
//
// The "activate" function does some (racy) checks by asking peers if they are
// active before we ourselves become active, in the course of creating key
// backups. In order to bypass that, we make the two nodes not peers -- the
// database doesn't care if they think they are peers or not.
#[test_with_logger]
fn three_node_cluster_fencing(logger: Logger) {
    let mut rng: Hc128Rng = SeedableRng::from_seed([0u8; 32]);

    let db_test_context = SqlRecoveryDbTestContext::new(logger.clone());
    let recovery_db = db_test_context.get_db_instance();

    let blockchain_path =
        TempDir::new("blockchain").expect("Could not make tempdir for blockchain state");

    // Set up the Watcher DB - create a new watcher DB for each phase
    let watcher_path = blockchain_path.path().join("watcher");
    std::fs::create_dir(&watcher_path).expect("couldn't create dir");
    WatcherDB::create(&watcher_path).unwrap();
    // Open the watcher db
    let tx_source_url = Url::from_str("https://localhost").unwrap();
    let watcher = mc_watcher::watcher_db::WatcherDB::open_rw(
        &watcher_path,
        &[tx_source_url.clone()],
        logger.clone(),
    )
    .expect("Could not create watcher_db");

    // Set up an empty ledger db.
    let ledger_db_path = blockchain_path.path().join("ledger_db");
    std::fs::create_dir(&ledger_db_path).expect("couldn't create dir");
    LedgerDB::create(&ledger_db_path).unwrap();
    let mut ledger = LedgerDB::open(&ledger_db_path).unwrap();

    // make origin block before
    let origin_txo = random_output(&mut rng);
    let origin_contents = BlockContents {
        key_images: Default::default(),
        outputs: origin_txo.clone(),
    };
    let origin_block = Block::new_origin_block(&origin_txo);
    ledger
        .append_block(&origin_block, &origin_contents, None)
        .expect("failed writing initial transactions");

    // Do three repetitions of the whole thing
    for _ in 0..3 {
        // Note: These nodes are not peers, and so do not check eachother when
        // activating
        let (mut node7, _node7dir) = make_node(
            7,
            vec![7u16].into_iter(),
            db_test_context.get_db_instance(),
            &watcher_path,
            &ledger_db_path,
            logger.clone(),
        );
        let (mut node8, _node8dir) = make_node(
            8,
            vec![8u16].into_iter(),
            db_test_context.get_db_instance(),
            &watcher_path,
            &ledger_db_path,
            logger.clone(),
        );
        let (mut node9, _node9dir) = make_node(
            9,
            vec![9u16].into_iter(),
            db_test_context.get_db_instance(),
            &watcher_path,
            &ledger_db_path,
            logger.clone(),
        );

        assert!(!node7.is_active());
        assert!(!node8.is_active());
        assert!(!node9.is_active());

        let node7_key = node7.get_ingest_summary().get_ingress_pubkey().clone();
        let node8_key = node8.get_ingest_summary().get_ingress_pubkey().clone();
        let node9_key = node9.get_ingest_summary().get_ingress_pubkey().clone();

        assert_ne!(node7_key, node8_key);
        assert_ne!(node7_key, node9_key);

        // Give RPC etc. time to start
        std::thread::sleep(Duration::from_millis(1000));

        // This is a way to sync the ingress key of 7 to 8 and 9, without peering them
        node8.sync_keys_from_remote(&make_uris(7).2).unwrap();
        node9.sync_keys_from_remote(&make_uris(7).2).unwrap();

        let node7_key = node7.get_ingest_summary().get_ingress_pubkey().clone();
        let node8_key = node8.get_ingest_summary().get_ingress_pubkey().clone();
        let node9_key = node9.get_ingest_summary().get_ingress_pubkey().clone();

        assert_eq!(node7_key, node8_key);
        assert_eq!(node7_key, node9_key);

        let ingress_key = CompressedRistrettoPublic::try_from(&node7_key).unwrap();

        for _reps in 0..2 {
            // Now activate them all, which should work (without raciness) since they can't
            // see eachother, and there are no blocks yet besides origin block
            assert!(
                node7.activate().is_ok(),
                "node7 should have been able to activate"
            );
            assert!(
                node8.activate().is_ok(),
                "node8 should have been able to activate"
            );
            assert!(
                node9.activate().is_ok(),
                "node9 should have been able to activate"
            );

            assert!(node7.is_active());
            assert!(node8.is_active());
            assert!(node9.is_active());

            add_test_block(&mut ledger, &watcher, &mut rng);

            // Wait at most 10s for someone to win the race
            wait_for_sync(&ledger, &recovery_db, &logger);

            // Wait 1s for everyone else to realize they lost
            std::thread::sleep(Duration::from_secs(1));

            let mut num_active = 0;
            let mut active_summary = None;
            if node7.is_active() {
                log::info!(logger, "node7 was active");
                num_active += 1;
                active_summary = Some(node7.get_ingest_summary());
            }
            if node8.is_active() {
                log::info!(logger, "node8 was active");
                num_active += 1;
                active_summary = Some(node8.get_ingest_summary());
            }
            if node9.is_active() {
                log::info!(logger, "node9 was active");
                num_active += 1;
                active_summary = Some(node9.get_ingest_summary());
            }

            assert_eq!(
                num_active, 1,
                "There was not only one leader when the dust settled!"
            );

            // There should be a block written only by the node that won the race.
            let active_summary = active_summary.unwrap();
            let active_iid = IngestInvocationId::from(active_summary.get_ingest_invocation_id());

            let num_blocks = ledger.num_blocks().unwrap();

            let invocation_id = recovery_db
                .get_invocation_id_by_block_and_key(ingress_key, num_blocks - 1)
                .unwrap()
                .unwrap();

            assert_eq!(active_iid, invocation_id);
        }

        // At this point we will have one active node and two inactive ones. The active
        // one won the race and the two others have lost it. We will stop the
        // active one, forcing one of the inactive ones to be the winner and by
        // that we will validate that losing the race once does not doom you to
        // always losing it or failing to write a new block. We are taking this
        // extra step since it is possible that the same node won the race in
        // all the loop iterations above, and we'd like to ensure that a node that has
        // lost the race is able to later on win it.
        let active_node_num = if node7.is_active() {
            log::info!(logger, "node7 was active");
            node7.stop();

            // Activate node 8
            assert!(
                node8.activate().is_ok(),
                "node8 should have been able to activate"
            );
            assert!(node8.is_active());
            assert!(!node9.is_active());

            8
        } else if node8.is_active() {
            log::info!(logger, "node8 was active");
            node8.stop();

            // Activate node 9
            assert!(
                node9.activate().is_ok(),
                "node9 should have been able to activate"
            );
            assert!(node9.is_active());
            assert!(!node7.is_active());

            9
        } else if node9.is_active() {
            log::info!(logger, "node9 was active");
            node9.stop();

            // Activate node 8
            assert!(
                node8.activate().is_ok(),
                "node8 should have been able to activate"
            );
            assert!(node8.is_active());
            assert!(!node7.is_active());

            8
        } else {
            panic!("no node was active");
        };

        // Write a block, the active node, that was previously inactive because it lost
        // the race, should manage to write a block.
        add_test_block(&mut ledger, &watcher, &mut rng);
        wait_for_sync(&ledger, &recovery_db, &logger);
        std::thread::sleep(Duration::from_millis(100));

        let num_blocks = ledger.num_blocks().unwrap();

        let node_iid = {
            let node = match active_node_num {
                8 => &node8,
                9 => &node9,
                _ => panic!("Invalid active_node_num"),
            };
            assert!(node.is_active());

            let node_summary = node.get_ingest_summary();
            assert_eq!(node_summary.get_next_block_index(), num_blocks);

            IngestInvocationId::from(node_summary.get_ingest_invocation_id())
        };

        let invocation_id = recovery_db
            .get_invocation_id_by_block_and_key(ingress_key, num_blocks - 1)
            .unwrap();
        assert_eq!(invocation_id, Some(node_iid));

        // Stop all nodes.
        drop(node7);
        drop(node8);
        drop(node9);

        std::thread::sleep(Duration::from_secs(3));
    }
}
