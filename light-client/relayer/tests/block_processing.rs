// Copyright (c) 2018-2023 The MobileCoin Foundation

use mc_account_keys::{burn_address, AccountKey, PublicAddress};
use mc_blockchain_types::{Block, BlockContents, BlockData, BlockMetadata, BlockMetadataContents};
use mc_common::logger::{log, test_with_logger, Logger};
use mc_crypto_keys::Ed25519Pair;
use mc_ledger_db::{test_utils::initialize_ledger, Ledger, LedgerDB};
use mc_light_client_relayer::{Config, Relayer, TestSender, TestVerifier};
use mc_transaction_core::{
    encrypted_fog_hint::EncryptedFogHint, ring_signature::KeyImage, tx::TxOut, Amount, BlockVersion,
};
use mc_transaction_extra::BurnRedemptionMemo;
use mc_util_from_random::FromRandom;
use mc_watcher::{watcher_db::WatcherDB, Url};
use rand::{rngs::StdRng, SeedableRng};
use std::{str::FromStr, time::Duration};
use tempfile::TempDir;

const BLOCK_VERSION: BlockVersion = BlockVersion::MAX;

fn append_tx_outs_as_block(
    ledger: &mut LedgerDB,
    tx_outs: &[TxOut],
    signers: Vec<Ed25519Pair>,
) -> (Block, BlockContents, Vec<BlockMetadata>) {
    let block_contents = BlockContents {
        outputs: tx_outs.to_owned(),
        key_images: vec![KeyImage::from(123)],
        ..Default::default()
    };

    let last_block = ledger.get_block(ledger.num_blocks().unwrap() - 1).unwrap();
    let block = Block::new_with_parent(
        BLOCK_VERSION,
        &last_block,
        &Default::default(),
        &block_contents,
    );

    // Sign this block with all the signer identities
    let block_metadata: Vec<BlockMetadata> = signers
        .iter()
        .map(|signer| {
            let bmc = BlockMetadataContents::new(
                block.id.clone(),
                Default::default(),
                Default::default(),
                Default::default(),
            );
            BlockMetadata::from_contents_and_keypair(bmc, signer).unwrap()
        })
        .collect();

    ledger
        .append_block(
            &block,
            &block_contents,
            None,
            Some(&block_metadata[0].clone()),
        )
        .unwrap();
    (block, block_contents, block_metadata)
}

#[test_with_logger]
fn test_relayer_processing(logger: Logger) {
    let mut rng: StdRng = SeedableRng::from_seed([216u8; 32]);

    let blockchain_path = TempDir::new()
        .expect("Could not make tempdir for blockchain state")
        .into_path();

    let watcher_db_path = {
        // Set up the Watcher db.
        let watcher_db_path = blockchain_path.join("watcher");
        std::fs::create_dir(&watcher_db_path).expect("failed to create watcher dir");
        WatcherDB::create(&watcher_db_path).expect("failed to create WarcherDB");
        watcher_db_path
    };

    // Set up an empty ledger db.
    let ledger_db_path = {
        let ledger_db_path = blockchain_path.join("ledger_db");
        std::fs::create_dir(&ledger_db_path).expect("failed to create ledger dir");
        LedgerDB::create(&ledger_db_path).expect("failed to create LedgerDB");
        ledger_db_path
    };

    let mut ledger = LedgerDB::open(&ledger_db_path).unwrap();
    let tx_source_urls: Vec<Url> = (0..5)
        .filter_map(|idx| Url::parse(&format!("https://node{idx}.localhost")).ok())
        .collect();

    let watcher = WatcherDB::open_rw(&watcher_db_path, &tx_source_urls, logger.clone())
        .expect("Could not create watcher_db");

    // Initialize ledger
    let sender = AccountKey::random(&mut rng);
    let num_blocks = 1;
    initialize_ledger(BLOCK_VERSION, &mut ledger, num_blocks, &sender, &mut rng);

    // Make node signer identities
    let signers: Vec<Ed25519Pair> = (0..5).map(|_| Ed25519Pair::from_random(&mut rng)).collect();

    let config = Config {
        start_block_index: 1,
        min_signatures: 4,
        ledger_db: ledger_db_path,
        watcher_db: watcher_db_path,
        admin_listen_uri: None,
    };

    log::info!(logger, "Starting relayer");
    let sender = TestSender {
        logger: logger.clone(),
        sent: Default::default(),
    };

    let verifier = TestVerifier {
        logger: logger.clone(),
    };

    let mut relayer = Relayer::new(
        config,
        ledger.clone(),
        watcher.clone(),
        sender.clone(),
        verifier,
        logger.clone(),
    );

    // Do happy path testing where there is a burn txo
    let burn_txo = TxOut::new_with_memo(
        BLOCK_VERSION,
        Amount::new(100, 2.into()),
        &burn_address(),
        &FromRandom::from_random(&mut rng),
        EncryptedFogHint::fake_onetime_hint(&mut rng),
        |_ctxt| Ok(BurnRedemptionMemo::new([7u8; 64]).into()),
    )
    .unwrap(); // TODO: Use real format here?

    let random_txo = TxOut::new(
        BLOCK_VERSION,
        Amount::new(100, 2.into()),
        &PublicAddress::from_random(&mut rng),
        &FromRandom::from_random(&mut rng),
        EncryptedFogHint::fake_onetime_hint(&mut rng),
    )
    .unwrap();

    log::info!(logger, "Adding block");

    let (block, block_contents, block_metadata) =
        append_tx_outs_as_block(&mut ledger, &[burn_txo.clone(), random_txo], signers);

    log::info!(logger, "Adding block to watcher");

    // Add this stuff to the watcher
    for (idx, block_metadata) in block_metadata.iter().enumerate() {
        let block_data = BlockData::new(
            block.clone(),
            block_contents.clone(),
            None,
            Some(block_metadata.clone()),
        );

        let url = Url::from_str(&format!("https://node{idx}.localhost")).unwrap();

        watcher.add_block_data(&url, &block_data).unwrap();
    }

    let mut retries = 100;
    loop {
        if retries == 0 {
            panic!("relayer message not received");
        } else {
            let records = sender.sent.lock().unwrap();
            if records.len() > 0 {
                assert_eq!(records.len(), 1);
                let burn_record = records[0].clone();
                assert_eq!(burn_record.tx_outs, vec![burn_txo]);
                assert_eq!(burn_record.block.id, block.id);
                assert_eq!(burn_record.block.contents_hash, block.contents_hash);
                assert_eq!(burn_record.block_contents, block_contents);

                let burn_record_signatures_count = burn_record.signatures.len();
                let block_signatures_count = block_metadata.len();
                assert_eq!(burn_record_signatures_count, block_signatures_count);
                for item in burn_record.signatures.iter() {
                    assert!(block_metadata.contains(item));
                }
                break;
            }
        }
        retries -= 1;
        std::thread::sleep(Duration::from_millis(100));
    }
    relayer.stop().unwrap();
}
