// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Ledger Sync test app

use mc_attest_verifier::{MrSignerVerifier, Verifier, DEBUG_ENCLAVE};
use mc_blockchain_test_utils::get_blocks;
use mc_blockchain_types::BlockVersion;
use mc_common::{logger::log, ResponderId};
use mc_connection::{ConnectionManager, HardcodedCredentialsProvider, ThickClient};
use mc_consensus_scp::{test_utils::test_node_id, QuorumSet};
use mc_ledger_db::{Ledger, LedgerDB};
use mc_ledger_sync::{LedgerSync, LedgerSyncService, PollingNetworkState};
use mc_util_uri::ConsensusClientUri as ClientUri;
use std::{path::PathBuf, str::FromStr, sync::Arc};
use tempdir::TempDir;

const NETWORK: &str = "test";

fn _make_ledger_long(ledger: &mut LedgerDB) {
    use rand::{rngs::StdRng, SeedableRng};

    let num_blocks = ledger.num_blocks().unwrap();
    let last_block = ledger.get_block(num_blocks - 1).unwrap();
    assert_eq!(last_block.cumulative_txo_count, ledger.num_txos().unwrap());

    let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

    let results = get_blocks(
        BlockVersion::ZERO,
        20,
        1,
        2,
        1000,
        1000,
        last_block,
        &mut rng,
    );

    for block_data in results {
        let block = block_data.block();
        println!("block with index {} and ID {}", block.index, block.id);
        ledger
            .append_block_data(&block_data)
            .expect("failed to append block");
        assert_eq!(block.cumulative_txo_count, ledger.num_txos().unwrap());
    }
}

fn main() {
    let (logger, _global_logger_guard) =
        mc_common::logger::create_app_logger(mc_common::logger::o!());
    log::info!(logger, "starting, network = {}", NETWORK);

    // Get a ledger database to work on.
    let ledger_dir =
        TempDir::new("ledger_sync_test_app").expect("Could not get test_ledger tempdir");
    let ledger_path = ledger_dir.path().to_path_buf();
    let ledger_path_str = ledger_dir
        .path()
        .to_str()
        .expect("Could not get ledger_path_str")
        .to_string();
    log::info!(logger, "ledger_path_str = {}", ledger_path_str);

    // Hack to make the ledger longer
    if false {
        // let mut ledger = LedgerDB::open(format!("../../target/sample_data/{}/ledger",
        // NETWORK)).expect("Failed opening local LedgerDB");
        let mut ledger = LedgerDB::open(&PathBuf::from("../../target/sample_data/ledger"))
            .expect("Failed opening local LedgerDB");
        _make_ledger_long(&mut ledger);
        return;
    }

    std::fs::copy(
        "../../target/sample_data/ledger/data.mdb",
        format!("{}/data.mdb", ledger_path_str),
    )
    .expect("failed copying ledger");

    let ledger = LedgerDB::open(&ledger_path).expect("Failed opening local LedgerDB");
    log::info!(
        logger,
        "num_blocks = {}, num_txos = {}",
        ledger.num_blocks().unwrap(),
        ledger.num_txos().unwrap()
    );

    // Set up connections.
    let grpc_env = Arc::new(
        grpcio::EnvBuilder::new()
            .name_prefix("Test-RPC".to_string())
            .build(),
    );

    let mut mr_signer_verifier =
        MrSignerVerifier::from(mc_consensus_enclave_measurement::sigstruct());
    mr_signer_verifier.allow_hardening_advisory("INTEL-SA-00334");

    let mut verifier = Verifier::default();
    verifier.mr_signer(mr_signer_verifier).debug(DEBUG_ENCLAVE);

    log::debug!(logger, "Verifier: {:?}", verifier);

    let peers = vec!["1", "2", "3", "4"]
        .into_iter()
        .map(|node_id| {
            let node_uri =
                ClientUri::from_str(&format!("mc://node{}.{}.mobilecoin.com/", node_id, NETWORK))
                    .expect("failed parsing URI");

            ThickClient::new(
                node_uri.clone(),
                verifier.clone(),
                grpc_env.clone(),
                HardcodedCredentialsProvider::from(&node_uri),
                logger.clone(),
            )
            .expect("Could not construct ThickClient")
        })
        .collect();

    let conn_manager = ConnectionManager::new(peers, logger.clone());

    // Create network state.
    let node_1 = test_node_id(1);
    let node_2 = test_node_id(2);
    let node_3 = test_node_id(3);
    let node_4 = test_node_id(4);
    let quorum_set: QuorumSet<ResponderId> = QuorumSet::new_with_node_ids(
        3,
        vec![
            node_1.responder_id,
            node_2.responder_id,
            node_3.responder_id,
            node_4.responder_id,
        ],
    );
    let mut network_state =
        PollingNetworkState::new(quorum_set, conn_manager.clone(), logger.clone());

    // Create ledger sync service.

    /*
    let transactions_fetcher =
        mc_ledger_sync::ConnectionManagerTransactionsFetcher::new(conn_manager.clone(), logger.clone());
    */
    let transactions_fetcher = mc_ledger_sync::ReqwestTransactionsFetcher::new(
        vec![
            String::from(
                "https://s3-us-west-1.amazonaws.com/mobilecoin.chain/node2.test.mobilecoin.com/",
            ),
            String::from(
                "https://s3-us-west-1.amazonaws.com/mobilecoin.chain/node3.test.mobilecoin.com/",
            ),
            String::from(
                "https://s3-us-west-1.amazonaws.com/mobilecoin.chain/node4.test.mobilecoin.com/",
            ),
        ],
        logger.clone(),
    )
    .expect("failed creating ReqwestTransactionsFetcher");

    let mut sync_service = LedgerSyncService::new(
        ledger.clone(),
        conn_manager,
        transactions_fetcher,
        logger.clone(),
    );
    loop {
        if !sync_service.is_behind(&network_state) {
            network_state.poll();
        }
        log::info!(
            logger,
            "ledger sync service is_behind: {:?}",
            sync_service.is_behind(&network_state)
        );

        if sync_service.is_behind(&network_state) {
            let _ = sync_service.attempt_ledger_sync(&network_state, 10);
        } else {
            log::debug!(
                logger,
                "Sleeping, num_blocks = {}...",
                ledger.num_blocks().unwrap()
            );
            std::thread::sleep(std::time::Duration::from_secs(10));
        }
    }
}
