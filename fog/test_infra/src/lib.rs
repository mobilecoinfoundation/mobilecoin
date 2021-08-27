// Copyright (c) 2018-2021 The MobileCoin Foundation

#![allow(non_snake_case)]

pub mod db_tests;
pub mod mock_client;
pub mod mock_users;

use mc_crypto_keys::{Ed25519Pair, RistrettoPublic};
use mc_fog_ingest_client::FogIngestGrpcClient;
use mc_fog_view_protocol::FogViewConnection;
use mc_ledger_db::{Ledger, LedgerDB};
use mc_transaction_core::{
    ring_signature::KeyImage, Block, BlockContents, BlockSignature, BLOCK_VERSION,
};
use mc_util_from_random::FromRandom;
use mc_watcher::watcher_db::WatcherDB;
use mc_watcher_api::TimestampResultCode;
use mock_users::UserPool;
use rand_core::{CryptoRng, RngCore};
use std::{convert::TryFrom, env, path::PathBuf};

/// Function for turning string constants into run-time enclave paths
///
/// Try to find the libenclave.signed.so file searching in whatever places make
/// sense for our infrastructure.
pub fn get_enclave_path(filename: &str) -> PathBuf {
    // First try searching right next to the target, this is for circle-ci
    let maybe_result = env::current_exe()
        .expect("Could not get current exe")
        .with_file_name(filename);
    // Try statting the file
    if std::fs::metadata(maybe_result.clone()).is_ok() {
        return maybe_result;
    }

    // During cargo test, the enclave.so won't be there, so we search in target
    // instead as a fallback
    let project_root = {
        let mut result = env::current_exe().expect("Could not get current exe");
        while result.file_name().expect("No Filename for result") != "target" {
            result = result.parent().expect("No parent for result").to_path_buf();
        }
        result
            .parent()
            .expect("Now no parent for result")
            .to_path_buf()
    };
    project_root
        .join("target")
        .join(mc_util_build_info::profile())
        .join(filename)
}

/// Generate a random test block, submit it, and see if all users recovered
/// their Txs as expected
///
/// # Arguments
/// * users: Users to make transactions for
/// * I: IngestEndpoint where we will send tx's
/// * V: ViewEndpoint where we will try to find tx's
/// * rng: RngCore
/// * num_tx: Number of transactions in this block
/// * global_txo_count: Total number of txos in the ledger already
///
/// Returns: New global_txo_count
pub fn test_block<T: RngCore + CryptoRng, C: FogViewConnection>(
    users: &mut UserPool,
    ingest: &FogIngestGrpcClient,
    view: &mut C,
    watcher: WatcherDB,
    ledger_db: &mut LedgerDB,
    rng: &mut T,
    num_tx: usize,
    block_index: u64,
    global_txo_count: usize,
) -> usize {
    let compressed_acct_pubkey = ingest
        .get_pubkey()
        .expect("Could not get acct server public key");
    let acct_pubkey = RistrettoPublic::try_from(&compressed_acct_pubkey)
        .expect("Could not decompress acct server public key");

    // Get tx counts for all users
    let checkpoint = users.get_checkpoint();
    // Make a random collection of transactions
    let test_block = users.random_test_block(num_tx, &acct_pubkey, rng);
    // Get a random timestamp
    let (timestamp, timestamp_result_code) = if block_index > 0 {
        (rng.next_u64(), TimestampResultCode::TimestampFound)
    } else {
        (u64::MAX, TimestampResultCode::BlockIndexOutOfBounds)
    };
    // Get the corresponding inputs to ingest and expected outputs from view
    let (txos, expected_result) = mock_users::test_block_to_inputs_and_expected_outputs(
        block_index,
        global_txo_count,
        &test_block,
        timestamp,
    );
    let num_new_txos = txos.len();

    // Add the timestamp information to watcher for this block index - note watcher
    // does not allow signatures for block 0.
    if block_index > 0 {
        for src_url in watcher.get_config_urls().unwrap().iter() {
            let block = Block {
                // Dummy block - we don't work with blocks in this test framework
                index: block_index,
                ..Default::default()
            };
            let mut block_signature =
                BlockSignature::from_block_and_keypair(&block, &Ed25519Pair::from_random(rng))
                    .expect("Could not create block signature from keypair");
            block_signature.set_signed_at(timestamp);
            watcher
                .add_block_signature(
                    src_url,
                    block_index,
                    block_signature,
                    format!("00/{}", block_index),
                )
                .expect("Could not add block signature");
        }
    }
    // Sanity check that watcher is behaving correctly
    assert_eq!(
        watcher
            .highest_common_block()
            .expect("Could not get highest common block"),
        block_index,
    );
    assert_eq!(
        watcher
            .get_block_timestamp(block_index)
            .expect("Could not get block timestamp"),
        (timestamp, timestamp_result_code)
    );

    // Make them into a block, and ingest it. This is done by appending a block to
    // the ledger and having it be polled by ingest.
    let (block, block_contents) = if block_index == 0 {
        let block_contents = BlockContents::new(vec![], txos.clone());
        let block = Block::new_origin_block(&txos);
        (block, block_contents)
    } else {
        let block_contents = BlockContents::new(vec![KeyImage::from(block_index)], txos);
        let parent_block = ledger_db
            .get_block(block_index - 1)
            .unwrap_or_else(|err| panic!("Failed getting block {}: {:?}", block_index - 1, err));
        let block = Block::new_with_parent(
            BLOCK_VERSION,
            &parent_block,
            &Default::default(),
            &block_contents,
        );
        (block, block_contents)
    };
    ledger_db
        .append_block(&block, &block_contents, None)
        .unwrap_or_else(|err| panic!("failed appending block {:?}: {:?}", block, err));

    // Make the users poll for transactions, until their num blocks matches
    // ledger_db, or we time out
    {
        let mut retries = 60;
        loop {
            let user_num_blocks = users.poll(view);
            if user_num_blocks
                .iter()
                .all(|val| (u64::from(*val)) > block_index)
            {
                break;
            }
            retries -= 1;
            if retries == 0 {
                panic!("users did not converge to ledger_db.num_blocks before we ran out of retry attempts");
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    }

    // Check if all the transactions that were sent were recovered
    let result = users.compute_delta(&checkpoint);
    if result == expected_result {
        return global_txo_count + num_new_txos;
    }

    panic!(
        "polling failed to yield expected result {:?}, obtained {:?}",
        expected_result, result
    );
}

/// Throw all the user phones in the pool and see if they can recover them via
/// the standard polling API
pub fn test_polling_recovery<C: FogViewConnection>(users: &mut UserPool, view: &mut C) {
    // Get a checkpoint against time zero
    let zero_checkpoint = users.get_zero_checkpoint();
    // Get a delta against time zero (i.e. all transactions)
    let expected_result = users.compute_delta(&zero_checkpoint);
    // Throw all the phones in a pool
    users.trash_user_phones();
    // Make the users poll for transactions
    users.poll(view);
    // Check if the same set of transactions has been recovered
    {
        let result = users.compute_delta(&zero_checkpoint);
        assert_eq!(result, expected_result);
    }
}
