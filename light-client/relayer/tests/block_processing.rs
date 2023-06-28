// Copyright (c) 2018-2023 The MobileCoin Foundation

use mc_account_keys::{burn_address, AccountKey, PublicAddress};
use mc_blockchain_types::{Block, BlockContents, BlockData, BlockMetadata, BlockMetadataContents};
use mc_common::logger::{log, test_with_logger, Logger};
use mc_crypto_keys::Ed25519Pair;
use mc_ledger_db::{test_utils::initialize_ledger, Ledger, LedgerDB};
use mc_light_client_relayer::{Config, Relayer, Sender};
use mc_transaction_core::{encrypted_fog_hint::EncryptedFogHint, tx::TxOut, Amount, BlockVersion};
use mc_transaction_extra::BurnRedemptionMemo;
use mc_util_from_random::FromRandom;
use mc_watcher::{watcher_db::WatcherDB, Url};
use rand::{rngs::StdRng, SeedableRng};
use std::{
    str::FromStr,
    sync::{Arc, Mutex},
    time::Duration,
};
use tempfile::TempDir;

const BLOCK_VERSION: BlockVersion = BlockVersion::MAX;

/// Data sent to the Mock Sender
#[derive(Clone)]
pub struct SentData {
    pub tx_outs: Vec<TxOut>,
    pub block: Block,
    pub block_contents: BlockContents,
    pub block_metadata: Vec<BlockMetadata>,
}

/// A mock sender injected into the relayer for the test
#[derive(Clone, Default)]
pub struct MockSender {
    pub sent: Arc<Mutex<Vec<SentData>>>,
}

impl Sender for MockSender {
    fn send(
        &mut self,
        tx_outs: Vec<TxOut>,
        block: &Block,
        block_contents: &BlockContents,
        block_metadata: Vec<BlockMetadata>,
    ) {
        self.sent.lock().unwrap().push(SentData {
            tx_outs,
            block: block.clone(),
            block_contents: block_contents.clone(),
            block_metadata,
        });
    }
}

fn append_tx_outs_as_block(ledger: &mut LedgerDB, tx_outs: &[TxOut]) -> (Block, BlockContents) {
    let block_contents = BlockContents {
        outputs: tx_outs.to_owned(),
        ..Default::default()
    };

    let last_block = ledger.get_block(ledger.num_blocks().unwrap() - 1).unwrap();
    let block = Block::new_with_parent(
        BLOCK_VERSION,
        &last_block,
        &Default::default(),
        &block_contents,
    );
    ledger
        .append_block(&block, &block_contents, None, None)
        .unwrap();
    (block, block_contents)
}

// Note: We could improve this by also watching prometheus counters
fn block_until_new_message_sent(mock_sender: &MockSender, logger: &Logger) {
    log::info!(logger, "Waiting for message");
    let mut retries = 100;
    let start_msgs = mock_sender.sent.lock().unwrap().len();
    loop {
        if mock_sender.sent.lock().unwrap().len() > start_msgs {
            break;
        }
        if retries == 0 {
            panic!("relayer message not received");
        }
        retries -= 1;
        std::thread::sleep(Duration::from_millis(100));
    }
    log::info!(logger, "Got message");
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
    let tx_source_url = Url::from_str("https://localhost").unwrap();
    let watcher = WatcherDB::open_rw(&watcher_db_path, &[tx_source_url], logger.clone())
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

    let mock_sender = MockSender::default();

    log::info!(logger, "Starting relayer");

    let mut relayer = Relayer::new(
        config,
        ledger.clone(),
        watcher.clone(),
        mock_sender.clone(),
        logger.clone(),
    );
    std::thread::scope(|s| {
        // Spawn a thread doing the relayer work
        s.spawn(|| relayer.entry_point());

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

        let (block, block_contents) =
            append_tx_outs_as_block(&mut ledger, &[burn_txo.clone(), random_txo]);

        log::info!(logger, "Signing block");

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

        log::info!(logger, "Adding block to watcher");

        // Add this stuff to the watcher
        for (idx, block_metadata) in block_metadata.iter().enumerate() {
            let block_data = BlockData::new(
                block.clone(),
                block_contents.clone(),
                None,
                Some(block_metadata.clone()),
            );

            let url = Url::from_str(&format!("fake{}.com", idx)).unwrap();

            watcher.add_block_data(&url, &block_data).unwrap();
        }

        // At this point the relayer should pick this up
        block_until_new_message_sent(&mock_sender, &logger);

        let latest_sent = {
            let sent = mock_sender.sent.lock().unwrap();
            assert_eq!(sent.len(), 1);
            sent[0].clone()
        };

        assert_eq!(latest_sent.tx_outs, vec![burn_txo]);
        assert_eq!(latest_sent.block.id, block.id);
        assert_eq!(latest_sent.block.contents_hash, block.contents_hash);
        assert_eq!(latest_sent.block_contents, block_contents);
        assert_eq!(latest_sent.block_metadata, block_metadata);
    });
}
