// Copyright (c) 2018-2020 MobileCoin Inc.

//! Persistent storage for the blockchain.
#![warn(unused_extern_crates)]
#![feature(test)]

#[cfg(test)]
extern crate test;

use core::convert::TryInto;
use lmdb::{
    Database, DatabaseFlags, Environment, EnvironmentFlags, RoTransaction, RwTransaction,
    Transaction, WriteFlags,
};
use mcserial::{deserialize, serialize};
use std::{path::PathBuf, sync::Arc};
use transaction::{hash_block_contents, Block, BlockID, BlockSignature, RedactedTx, BLOCK_VERSION};

mod error;
mod ledger_trait;
pub mod tx_out_store;

#[cfg(any(test, feature = "test_utils"))]
pub mod test_utils;

pub use error::Error;
pub use ledger_trait::Ledger;
use transaction::{
    ring_signature::KeyImage,
    tx::{TxOut, TxOutMembershipProof},
};
use tx_out_store::TxOutStore;

const MAX_LMDB_FILE_SIZE: usize = 1_099_511_627_776; // 1 TB

// LMDB Database names.
pub const COUNTS_DB_NAME: &str = "ledger_db:counts";
pub const BLOCKS_DB_NAME: &str = "ledger_db:blocks";
pub const BLOCK_SIGNATURES_DB_NAME: &str = "ledger_db:block_signatures";
pub const KEY_IMAGES_DB_NAME: &str = "ledger_db:key_images";
pub const KEY_IMAGES_BY_BLOCK_DB_NAME: &str = "ledger_db:key_images_by_block";
pub const TRANSACTIONS_BY_BLOCK_DB_NAME: &str = "ledger_db:transactions_by_block";

// Keys used by the `counts` database.
const NUM_BLOCKS_KEY: &str = "num_blocks";
const NUM_TXS_KEY: &str = "num_txs";

#[derive(Clone)]
pub struct LedgerDB {
    env: Arc<Environment>,

    /// Aggregate counts about the ledger.
    /// * `NUM_BLOCKS_KEY` --> number of blocks in the ledger.
    /// * `NUM_TXS_KEY` --> number of txs in the ledger.
    counts: Database,

    /// Blocks by block number. `block number -> Block`
    blocks: Database,

    /// Block signatures by number. `block number -> BlockSignature`
    block_signatures: Database,

    /// Transactions by block. `block number -> Vec<TxStored>`
    transactions_by_block: Database,

    /// Key Images
    key_images: Database,

    /// Key Images by Block
    key_images_by_block: Database,

    /// Storage abstraction for TxOuts.
    tx_out_store: TxOutStore,

    /// Location on filesystem.
    path: PathBuf,
}

/// LedgerDB is an append-only log (or chain) of blocks of transactions.
impl Ledger for LedgerDB {
    /// Appends a block and its associated transactions to the blockchain.
    ///
    /// # Arguments
    /// * `block` - A block.
    /// * `transactions` - The ith element of `transactions` corresponds to the ith element of `block.tx_hashes`.
    fn append_block(
        &mut self,
        block: &Block,
        transactions: &[RedactedTx],
        signature: Option<&BlockSignature>,
    ) -> Result<(), Error> {
        // Note: This function must update every LMDB database managed by LedgerDB.
        let mut db_transaction = self.env.begin_rw_txn()?;

        self.validate_append_block(block, transactions)?;

        let key_images = transactions
            .iter()
            .flat_map(|redacted_tx| redacted_tx.key_images.clone())
            .collect::<Vec<_>>();

        self.write_key_images(block.index, &key_images, &mut db_transaction)?;

        for tx_stored in transactions {
            for tx_out in &tx_stored.outputs {
                self.tx_out_store.push(tx_out, &mut db_transaction)?;
            }
        }

        // Update counts
        let num_txs: u64 = key_bytes_to_u64(&db_transaction.get(self.counts, &NUM_TXS_KEY)?);
        db_transaction.put(
            self.counts,
            &NUM_TXS_KEY,
            &u64_to_key_bytes(num_txs + transactions.len() as u64),
            WriteFlags::empty(),
        )?;

        self.write_transactions_by_block(block.index, transactions, &mut db_transaction)?;
        self.write_block(block, signature, &mut db_transaction)?;
        db_transaction.commit()?;
        Ok(())
    }

    /// Get the total number of Blocks in the ledger.
    fn num_blocks(&self) -> Result<u64, Error> {
        let db_transaction = self.env.begin_ro_txn()?;
        Ok(key_bytes_to_u64(
            &db_transaction.get(self.counts, &NUM_BLOCKS_KEY)?,
        ))
    }

    /// Get the total number of transactions in the ledger.
    fn num_txs(&self) -> Result<u64, Error> {
        let db_transaction = self.env.begin_ro_txn()?;
        Ok(key_bytes_to_u64(
            &db_transaction.get(self.counts, &NUM_TXS_KEY)?,
        ))
    }

    /// Get the total number of TxOuts in the ledger.
    fn num_txos(&self) -> Result<u64, Error> {
        let db_transaction = self.env.begin_ro_txn()?;
        self.tx_out_store.num_tx_outs(&db_transaction)
    }

    /// Gets a Block by its index in the blockchain.
    fn get_block(&self, block_number: u64) -> Result<Block, Error> {
        let db_transaction = self.env.begin_ro_txn()?;
        let key = u64_to_key_bytes(block_number);
        let block_bytes = db_transaction.get(self.blocks, &key)?;
        let block = deserialize(&block_bytes)?;
        Ok(block)
    }

    /// Gets a block signature by its index in the blockchain.
    fn get_block_signature(&self, block_number: u64) -> Result<BlockSignature, Error> {
        let db_transaction = self.env.begin_ro_txn()?;
        let key = u64_to_key_bytes(block_number);
        let signature_bytes = db_transaction.get(self.block_signatures, &key)?;
        let signature = deserialize(&signature_bytes)?;
        Ok(signature)
    }

    /// Returns the index of the TxOut with the given hash.
    fn get_tx_out_index_by_hash(&self, tx_out_hash: &[u8; 32]) -> Result<u64, Error> {
        let db_transaction: RoTransaction = self.env.begin_ro_txn()?;
        self.tx_out_store
            .get_tx_out_index_by_hash(tx_out_hash, &db_transaction)
    }

    /// Gets a TxOut by its index in the ledger.
    fn get_tx_out_by_index(&self, index: u64) -> Result<TxOut, Error> {
        let db_transaction = self.env.begin_ro_txn()?;
        self.tx_out_store
            .get_tx_out_by_index(index, &db_transaction)
    }

    /// Gets all transactions associated with a given Block.
    fn get_transactions_by_block(&self, block_number: u64) -> Result<Vec<RedactedTx>, Error> {
        let db_transaction = self.env.begin_ro_txn()?;
        let key = u64_to_key_bytes(block_number);
        let bytes = db_transaction.get(self.transactions_by_block, &key)?;
        let transactions: Vec<RedactedTx> = deserialize(bytes)?;
        Ok(transactions)
    }

    /// Returns true if the Ledger contains the given KeyImage.
    fn check_key_image(&self, key_image: &KeyImage) -> Result<Option<u64>, Error> {
        let db_transaction = self.env.begin_ro_txn()?;
        match db_transaction.get(self.key_images, &key_image) {
            Ok(db_bytes) => {
                assert_eq!(db_bytes.len(), 8, "Expected exactly 8 le bytes (u64 block height) to be stored with key image, found {}", db_bytes.len());
                let mut u64_buf = [0u8; 8];
                u64_buf.copy_from_slice(db_bytes);
                Ok(Some(u64::from_le_bytes(u64_buf)))
            }
            Err(lmdb::Error::NotFound) => Ok(None),
            Err(e) => Err(Error::LmdbError(e)),
        }
    }

    /// Gets the KeyImages used by transactions in a single Block.
    fn get_key_images_by_block(&self, block_number: u64) -> Result<Vec<KeyImage>, Error> {
        let db_transaction = self.env.begin_ro_txn()?;
        let key_images: Vec<KeyImage> = deserialize(
            db_transaction.get(self.key_images_by_block, &u64_to_key_bytes(block_number))?,
        )?;
        Ok(key_images)
    }

    /// Gets a proof of memberships for TxOuts with indexes `indexes`.
    fn get_tx_out_proof_of_memberships(
        &self,
        indexes: &[u64],
    ) -> Result<Vec<TxOutMembershipProof>, Error> {
        let db_transaction = self.env.begin_ro_txn()?;
        indexes
            .iter()
            .map(|index| {
                self.tx_out_store
                    .get_merkle_proof_of_membership(*index, &db_transaction)
            })
            .collect()
    }
}

impl LedgerDB {
    /// Opens an existing Ledger Database in the given path.
    pub fn open(path: PathBuf) -> Result<LedgerDB, Error> {
        let env = Environment::new()
            .set_max_dbs(20)
            .set_map_size(MAX_LMDB_FILE_SIZE)
            // TODO - needed because currently our test cloud machines have slow disks.
            .set_flags(EnvironmentFlags::NO_SYNC)
            .open(&path)?;

        let counts = env.open_db(Some(COUNTS_DB_NAME))?;
        let blocks = env.open_db(Some(BLOCKS_DB_NAME))?;
        let block_signatures = env.open_db(Some(BLOCK_SIGNATURES_DB_NAME))?;
        let key_images = env.open_db(Some(KEY_IMAGES_DB_NAME))?;
        let key_images_by_block = env.open_db(Some(KEY_IMAGES_BY_BLOCK_DB_NAME))?;
        let transactions_by_block = env.open_db(Some(TRANSACTIONS_BY_BLOCK_DB_NAME))?;

        let tx_out_store = TxOutStore::new(&env)?;

        Ok(LedgerDB {
            env: Arc::new(env),
            path,
            counts,
            blocks,
            block_signatures,
            key_images,
            key_images_by_block,
            transactions_by_block,
            tx_out_store,
        })
    }

    /// Creates a fresh Ledger Database in the given path.
    pub fn create(path: PathBuf) -> Result<(), Error> {
        let env = Environment::new()
            .set_max_dbs(20)
            .set_map_size(MAX_LMDB_FILE_SIZE)
            .open(&path)
            .unwrap_or_else(|_| {
                panic!(
                    "Could not create environment for ledger_db. Check that path exists {:?}",
                    path
                )
            });

        let counts = env.create_db(Some(COUNTS_DB_NAME), DatabaseFlags::empty())?;
        env.create_db(Some(BLOCKS_DB_NAME), DatabaseFlags::empty())?;
        env.create_db(Some(BLOCK_SIGNATURES_DB_NAME), DatabaseFlags::empty())?;
        env.create_db(Some(KEY_IMAGES_DB_NAME), DatabaseFlags::empty())?;
        env.create_db(Some(KEY_IMAGES_BY_BLOCK_DB_NAME), DatabaseFlags::empty())?;
        env.create_db(Some(TRANSACTIONS_BY_BLOCK_DB_NAME), DatabaseFlags::empty())?;

        TxOutStore::create(&env)?;

        let mut db_transaction = env.begin_rw_txn()?;

        db_transaction.put(
            counts,
            &NUM_BLOCKS_KEY,
            &u64_to_key_bytes(0),
            WriteFlags::empty(),
        )?;

        db_transaction.put(
            counts,
            &NUM_TXS_KEY,
            &u64_to_key_bytes(0),
            WriteFlags::empty(),
        )?;

        db_transaction.commit()?;
        Ok(())
    }

    /// Write a `Block`.
    fn write_block(
        &self,
        block: &Block,
        signature: Option<&BlockSignature>,
        db_transaction: &mut RwTransaction,
    ) -> Result<(), lmdb::Error> {
        // TODO: validate block.
        // * Is the block's index correct?
        // * Is the block's parent_id correct?
        // * Is the block's ID the hash of its contents?

        // Update total number of blocks.
        let num_blocks_before: u64 =
            key_bytes_to_u64(&db_transaction.get(self.counts, &NUM_BLOCKS_KEY)?);
        db_transaction.put(
            self.counts,
            &NUM_BLOCKS_KEY,
            &u64_to_key_bytes(num_blocks_before + 1),
            WriteFlags::empty(),
        )?;

        db_transaction.put(
            self.blocks,
            &u64_to_key_bytes(block.index),
            &serialize(block).unwrap_or_else(|_| panic!("Could not serialize block {:?}", block)),
            WriteFlags::empty(),
        )?;

        if let Some(signature) = signature {
            db_transaction.put(
                self.block_signatures,
                &u64_to_key_bytes(block.index),
                &serialize(signature).unwrap_or_else(|_| {
                    panic!("Could not serialize block signature {:?}", signature)
                }),
                WriteFlags::empty(),
            )?;
        }

        Ok(())
    }

    fn write_key_images(
        &self,
        block_index: u64,
        key_images: &[KeyImage],
        db_transaction: &mut RwTransaction,
    ) -> Result<(), Error> {
        // Update Key Images
        for key_image in key_images {
            if self.contains_key_image(key_image)? {
                return Err(Error::KeyImageAlreadySpent);
            }
            db_transaction.put(
                self.key_images,
                &key_image,
                &block_index.to_le_bytes(),
                WriteFlags::empty(),
            )?;
        }
        db_transaction.put(
            self.key_images_by_block,
            &u64_to_key_bytes(block_index),
            &serialize(&key_images)?,
            WriteFlags::empty(),
        )?;
        Ok(())
    }

    fn write_transactions_by_block(
        &self,
        block_index: u64,
        transactions: &[RedactedTx],
        db_transaction: &mut RwTransaction,
    ) -> Result<(), lmdb::Error> {
        db_transaction.put(
            self.transactions_by_block,
            &u64_to_key_bytes(block_index),
            &serialize(&transactions.to_vec())
                .unwrap_or_else(|_| panic!("Could not serialize chunk {:?}", transactions)),
            WriteFlags::empty(),
        )?;
        Ok(())
    }

    /// Checks if a block can be appended to the db
    fn validate_append_block(
        &self,
        block: &Block,
        transactions: &[RedactedTx],
    ) -> Result<(), Error> {
        // We don't want empty blocks
        if transactions.is_empty() {
            return Err(Error::NoTransactions);
        }

        // Check that version is correct
        if block.version != BLOCK_VERSION {
            return Err(Error::InvalidBlock);
        }

        // Check if block is being appended at the correct place
        let num_blocks = self.num_blocks()?;
        if num_blocks == 0 {
            if block.index != 0 || block.parent_id != BlockID::default() {
                return Err(Error::InvalidBlock);
            }
        } else {
            let last_block = self.get_block(num_blocks - 1)?;
            if block.index != num_blocks || block.parent_id != last_block.id {
                return Err(Error::InvalidBlock);
            }
        }

        // Check that the block contents match the hash
        if block.contents_hash != hash_block_contents(&transactions) {
            return Err(Error::InvalidBlockContents);
        }

        // Check that none of the key images were previously spent
        for redacted_tx in transactions.iter() {
            for key_image in redacted_tx.key_images.iter() {
                if self.contains_key_image(key_image)? {
                    return Err(Error::KeyImageAlreadySpent);
                }
            }
        }

        // Validate block id

        if !block.is_block_id_valid() {
            return Err(Error::InvalidBlockID);
        }

        // All good
        Ok(())
    }
}

// Specifies how we serialize the u64 chunk number in lmdb
// The lexicographical sorting of the numbers, done by lmdb, must match the
// numeric order of the chunks. Thus we use Big Endian byte order here
pub fn u64_to_key_bytes(value: u64) -> [u8; 8] {
    value.to_be_bytes()
}

pub fn key_bytes_to_u64(bytes: &[u8]) -> u64 {
    assert_eq!(8, bytes.len());
    u64::from_be_bytes(bytes.try_into().unwrap())
}

#[cfg(test)]
mod ledger_db_test {
    use super::*;
    use common::HashMap;
    use core::convert::TryFrom;
    use keys::{FromRandom, RistrettoPrivate, RistrettoPublic};
    use rand::{rngs::StdRng, SeedableRng};
    use rand_core::RngCore;
    use tempdir::TempDir;
    use test::Bencher;
    use transaction::{
        account_keys::{AccountKey, PublicAddress},
        onetime_keys::{compute_key_image, recover_onetime_private_key},
    };
    use transaction_std::{BlockBuilder, InputCredentials, TransactionBuilder};
    use transaction_test_utils::get_outputs;

    /// Creates a LedgerDB instance.
    fn create_db() -> LedgerDB {
        let temp_dir = TempDir::new("test").unwrap();
        let path = temp_dir.path().to_path_buf();
        LedgerDB::create(path.clone()).unwrap();
        LedgerDB::open(path).unwrap()
    }

    /// Populates the LedgerDB with initial data, and returns the Block entities that were written.
    ///
    /// # Arguments
    /// * `n_blocks` - number of blocks of transactions to write to `db`.
    /// * `n_txs_per_block` - number of transactions per block.
    ///
    fn populate_db(db: &mut LedgerDB, n_blocks: u64, n_txs_per_block: u64) -> Vec<Block> {
        let initial_amount: u64 = 5_000 * 1_000_000_000_000;

        // Generate 1 public / private addresses and create transactions.
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let account_key = AccountKey::random(&mut rng);

        let mut parent_block: Option<Block> = None;
        let mut blocks: Vec<Block> = Vec::new();

        for block_index in 0..n_blocks {
            let redacted_transactions: Vec<_> = (0..n_txs_per_block)
                .map(|_i| {
                    // Each transaction has a single output.
                    let tx_out = TxOut::new(
                        initial_amount,
                        &account_key.default_subaddress(),
                        &RistrettoPrivate::from_random(&mut rng),
                        Default::default(),
                        &mut rng,
                    )
                    .unwrap();

                    RedactedTx {
                        outputs: vec![tx_out],
                        key_images: vec![],
                    }
                })
                .collect();

            let block = match parent_block {
                None => Block::new_origin_block(&redacted_transactions),
                Some(parent) => Block::new(
                    BLOCK_VERSION,
                    &parent.id,
                    block_index,
                    parent.cumulative_txo_count + redacted_transactions.len() as u64,
                    &Default::default(),
                    &redacted_transactions,
                ),
            };
            assert_eq!(block_index, block.index);

            db.append_block(&block, &redacted_transactions, None)
                .expect("failed writing initial transactions");
            blocks.push(block.clone());
            parent_block = Some(block);
        }

        // Verify that db now contains n transactions.
        assert_eq!(db.num_blocks().unwrap(), n_blocks as u64);
        assert_eq!(db.num_txs().unwrap(), (n_blocks * n_txs_per_block) as u64);

        blocks
    }

    #[test]
    // Test initial conditions of a new LedgerDB instance.
    fn test_ledger_db_initialization() {
        let ledger_db = create_db();
        assert_eq!(ledger_db.num_blocks().unwrap(), 0);
        assert_eq!(ledger_db.num_txos().unwrap(), 0);
    }

    #[test]
    // Appending a block should correctly update each LMDB database.
    fn test_append_block() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let mut ledger_db = create_db();

        // === Create and append the origin block. ===
        // Here, the origin block contains a single transaction that "mints" a single output
        // that belongs to the `origin_account_key`.
        let origin_account_key = AccountKey::random(&mut rng);

        let tx_out = TxOut::new(
            1000,
            &origin_account_key.default_subaddress(),
            &RistrettoPrivate::from_random(&mut rng),
            Default::default(),
            &mut rng,
        )
        .unwrap();

        let redacted_tx = RedactedTx {
            outputs: vec![tx_out],
            key_images: vec![],
        };

        let origin_transactions = vec![redacted_tx];
        let origin_block = Block::new_origin_block(&origin_transactions);

        ledger_db
            .append_block(&origin_block, &origin_transactions, None)
            .unwrap();
        assert_eq!(1, ledger_db.num_blocks().unwrap());
        assert_eq!(origin_block, ledger_db.get_block(0).unwrap());
        assert_eq!(1, ledger_db.num_txos().unwrap());

        let origin_tx_out: &TxOut = origin_transactions.get(0).unwrap().outputs.get(0).unwrap();
        let origin_tx_public_key = RistrettoPublic::try_from(&origin_tx_out.public_key).unwrap();

        assert_eq!(*origin_tx_out, ledger_db.get_tx_out_by_index(0).unwrap());

        assert_eq!(1, ledger_db.num_txs().unwrap());

        assert_eq!(
            origin_transactions,
            ledger_db.get_transactions_by_block(0).unwrap()
        );

        let key_images = ledger_db.get_key_images_by_block(0).unwrap();
        assert_eq!(key_images.len(), 0);

        // === Create and append a non-origin block. ===
        // Create a transaction that spends the TxOut in the origin block and sends its value to
        // several recipients.

        let recipient_a = AccountKey::random(&mut rng);
        let recipient_b = AccountKey::random(&mut rng);
        let recipient_c = AccountKey::random(&mut rng);
        let recipient_d = AccountKey::random(&mut rng);

        let mut transaction_builder = TransactionBuilder::new();
        transaction_builder.set_fee(0);

        // Add input.
        let mut ring: Vec<TxOut> = Vec::new();
        ring.push(origin_tx_out.clone());

        let membership_proofs: Vec<TxOutMembershipProof> = ring
            .iter()
            .map(|_tx_out| {
                // These membership proofs aren't important for this unit test, because
                // membership proofs are normally discarded before a block is written to the
                // ledger. However, the TransactionBuilder requires a membership proof
                // for each ring element.
                TxOutMembershipProof::new(0, 0, HashMap::default())
            })
            .collect();

        let onetime_private_key = recover_onetime_private_key(
            &origin_tx_public_key,
            origin_account_key.view_private_key(),
            &origin_account_key.default_subaddress_spend_key(),
        );

        let input_credentials = InputCredentials::new(
            ring,
            membership_proofs,
            0,
            onetime_private_key,
            *origin_account_key.view_private_key(),
            &mut rng,
        )
        .unwrap();

        transaction_builder.add_input(input_credentials);

        // Add outputs that sum to 1000.
        transaction_builder
            .add_output(100, &recipient_a.default_subaddress(), None, &mut rng)
            .unwrap();
        transaction_builder
            .add_output(200, &recipient_b.default_subaddress(), None, &mut rng)
            .unwrap();
        transaction_builder
            .add_output(300, &recipient_c.default_subaddress(), None, &mut rng)
            .unwrap();
        transaction_builder
            .add_output(400, &recipient_d.default_subaddress(), None, &mut rng)
            .unwrap();

        let tx = transaction_builder.build(&mut rng).unwrap();

        let (block_one, block_one_transactions) =
            BlockBuilder::new(Some(origin_block.clone()), Default::default())
                .add_transaction(tx.clone())
                .build();

        let tx_outs: Vec<TxOut> = block_one_transactions
            .iter()
            .flat_map(|tx_stored| &tx_stored.outputs)
            .cloned()
            .collect();

        ledger_db
            .append_block(&block_one, &block_one_transactions, None)
            .unwrap();

        assert_eq!(2, ledger_db.num_blocks().unwrap());
        // The origin block should still be in the ledger:
        assert_eq!(origin_block, ledger_db.get_block(0).unwrap());
        // The new block should be in the ledger:
        assert_eq!(block_one, ledger_db.get_block(1).unwrap());
        assert_eq!(5, ledger_db.num_txos().unwrap());

        for (i, tx_out) in tx_outs.iter().enumerate() {
            // The first tx_out is the origin block, tx_outs are for the following block hence the
            // + 1
            assert_eq!(
                ledger_db.get_tx_out_by_index((i + 1) as u64).unwrap(),
                *tx_out
            );
        }

        // The origin's TxOut should still be in the ledger:
        assert_eq!(*origin_tx_out, ledger_db.get_tx_out_by_index(0).unwrap());
        // Each TxOut from the current block should be in the ledger:
        assert_eq!(
            *tx_outs.get(0).unwrap(),
            ledger_db.get_tx_out_by_index(1).unwrap()
        );
        assert_eq!(
            *tx_outs.get(1).unwrap(),
            ledger_db.get_tx_out_by_index(2).unwrap()
        );
        assert_eq!(
            *tx_outs.get(2).unwrap(),
            ledger_db.get_tx_out_by_index(3).unwrap()
        );
        assert_eq!(
            *tx_outs.get(3).unwrap(),
            ledger_db.get_tx_out_by_index(4).unwrap()
        );

        assert_eq!(1, block_one_transactions.len());
        assert_eq!(2, ledger_db.num_txs().unwrap());

        assert_eq!(
            block_one_transactions,
            ledger_db.get_transactions_by_block(1).unwrap()
        );

        let key_images: Vec<KeyImage> = tx.key_images();
        assert_eq!(1, key_images.len());

        assert!(ledger_db
            .contains_key_image(key_images.get(0).unwrap())
            .unwrap());

        let block_one_key_images = ledger_db.get_key_images_by_block(1).unwrap();
        assert_eq!(key_images, block_one_key_images);
    }

    #[test]
    #[ignore]
    // A block that attempts a double spend should be rejected.
    fn test_reject_double_spend() {
        unimplemented!();
    }

    #[test]
    // `num_blocks` should return the correct number of blocks.
    fn test_num_blocks() {
        let mut ledger_db = create_db();
        assert_eq!(ledger_db.num_blocks().unwrap(), 0);
        let n_blocks: u64 = 7;
        populate_db(&mut ledger_db, n_blocks, 1);
        assert_eq!(ledger_db.num_blocks().unwrap(), n_blocks);
    }

    #[test]
    // Getting a block by index should return the correct block, if it exists.
    fn test_get_block_by_index() {
        let mut ledger_db = create_db();
        let n_blocks = 43;
        let expected_blocks = populate_db(&mut ledger_db, n_blocks, 1);

        for block_index in 0..n_blocks {
            let block = ledger_db
                .get_block(block_index as u64)
                .unwrap_or_else(|_| panic!("Could not get block {:?}", block_index));

            let expected_block: Block = expected_blocks.get(block_index as usize).unwrap().clone();
            assert_eq!(block, expected_block);
        }
    }

    #[test]
    // Getting a block by its index should return an error if the block doesn't exist.
    fn test_get_block_by_index_doesnt_exist() {
        let mut ledger_db = create_db();
        let n_blocks = 43;
        populate_db(&mut ledger_db, n_blocks, 1);

        let out_of_range = 999;

        match ledger_db.get_block(out_of_range) {
            Ok(_block) => panic!("Should not return a block."),
            Err(Error::NotFound) => {
                // This is expected.
            }
            Err(e) => panic!("Unexpected error {:?}", e),
        }
    }

    #[test]
    // `get_transactions_by_block` should return all transactions in the block.
    fn test_get_transactions_by_block() {
        // Setup: Block 0 contains 2 transactions, and Block 2 contains 1 transaction.
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let mut ledger_db = create_db();
        let account_key = AccountKey::random(&mut rng);

        let redacted_transactions: Vec<RedactedTx> = (0..3)
            .map(|_i| {
                let tx_out = TxOut::new(
                    10,
                    &account_key.default_subaddress(),
                    &RistrettoPrivate::from_random(&mut rng),
                    Default::default(),
                    &mut rng,
                )
                .unwrap();
                RedactedTx {
                    outputs: vec![tx_out],
                    key_images: vec![],
                }
            })
            .collect();

        // Block 0 contains two transactions.
        let block_zero_transactions: Vec<_> = redacted_transactions[0..2].iter().cloned().collect();
        assert_eq!(block_zero_transactions.len(), 2);
        let block_zero = Block::new_origin_block(&block_zero_transactions);

        ledger_db
            .append_block(&block_zero, &block_zero_transactions, None)
            .expect("failed writing block 0");

        assert_eq!(ledger_db.num_blocks().unwrap(), 1);

        // Block 1 contains one transaction.
        let block_one_transactions = vec![redacted_transactions[2].clone()];
        assert_eq!(block_one_transactions.len(), 1);
        let block_one = Block::new(
            BLOCK_VERSION,
            &block_zero.id,
            1,
            3,
            &Default::default(),
            &block_one_transactions,
        );

        ledger_db
            .append_block(&block_one, &block_one_transactions, None)
            .expect("failed writing block 1");

        assert_eq!(ledger_db.num_blocks().unwrap(), 2);

        // Get transactions for Block 0.
        {
            let transactions = ledger_db.get_transactions_by_block(0).unwrap();
            assert_eq!(transactions.len(), 2);
            assert_eq!(transactions, block_zero_transactions);
        }

        // Get transactions for Block 1.
        {
            let transactions = ledger_db.get_transactions_by_block(1).unwrap();
            assert_eq!(transactions.len(), 1);
            assert_eq!(transactions, block_one_transactions);
        }

        // `get_transactions_by_block` should return an Error if the block doesn't exist.
        match ledger_db.get_transactions_by_block(17283) {
            Ok(_transactions) => panic!("Returned transactions for a block that does not exist."),
            Err(Error::NotFound) => {
                // This is expected.
            }
            Err(e) => panic!("Unexpected error {:?}", e),
        }
    }

    // A helper method for generating a block that contains a transaction consuming N inputs.
    // Returns the key images spent
    fn generate_key_image_test_block(
        ledger_db: &mut LedgerDB,
        input_accounts: Vec<AccountKey>,
        recipient_account: AccountKey,
    ) -> Vec<KeyImage> {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

        // Value of each TxOut.
        let value = 65536;

        // Mint an initial collection of outputs so that we have something to spend
        let minted_outputs: Vec<TxOut> = {
            let mut recipient_and_amounts: Vec<(PublicAddress, u64)> = Vec::new();
            for input_account in &input_accounts {
                recipient_and_amounts.push((input_account.default_subaddress().clone(), value));
            }
            get_outputs(&recipient_and_amounts, &mut rng)
        };

        // Create a transaction that spends two of the above outputs
        let mut transaction_builder = TransactionBuilder::new();

        transaction_builder.set_fee(0);

        let ring: Vec<TxOut> = minted_outputs.clone();
        let membership_proofs: Vec<TxOutMembershipProof> = ring
            .iter()
            .map(|_tx_out| {
                // These membership proofs aren't important for this unit test, because
                // membership proofs are normally discarded before a block is written to the
                // ledger. However, the TransactionBuilder requires a membership proof
                // for each ring element.
                TxOutMembershipProof::new(0, 0, HashMap::default())
            })
            .collect();

        let mut key_images: Vec<KeyImage> = Vec::new();

        // Use inputs
        for (idx, input_account) in input_accounts.iter().enumerate() {
            let public_key = RistrettoPublic::try_from(&minted_outputs[idx].public_key).unwrap();
            let onetime_private_key = recover_onetime_private_key(
                &public_key,
                input_account.view_private_key(),
                &input_account.default_subaddress_spend_key(),
            );

            let input_credentials = InputCredentials::new(
                ring.clone(),
                membership_proofs.clone(),
                idx,
                onetime_private_key,
                *input_account.view_private_key(),
                &mut rng,
            )
            .unwrap();

            transaction_builder.add_input(input_credentials);
            let key_image = compute_key_image(&onetime_private_key);
            key_images.push(key_image);
        }

        // Finish building the transaction.
        let output_value: u64 = input_accounts.len() as u64 * value;
        transaction_builder
            .add_output(
                output_value,
                &recipient_account.default_subaddress(),
                None,
                &mut rng,
            )
            .unwrap();

        let transaction = transaction_builder.build(&mut rng).unwrap();

        // `transaction` should have N inputs.
        assert_eq!(transaction.prefix.inputs.len(), input_accounts.len());

        // `transaction` should have a single output.
        assert_eq!(transaction.prefix.outputs.len(), 1);

        // Store into a block
        let num_blocks = ledger_db.num_blocks().unwrap();

        let parent_block = if num_blocks == 0 {
            None
        } else {
            Some(ledger_db.get_block(num_blocks - 1).unwrap())
        };

        let (block_zero, expected_transactions_zero) =
            BlockBuilder::new(parent_block, Default::default())
                .add_transaction(transaction)
                .build();

        ledger_db
            .append_block(&block_zero, &expected_transactions_zero, None)
            .expect("failed writing block 0");

        key_images
    }

    #[test]
    // `Ledger::contains_key_image` should find key images that exist.
    fn test_contains_key_image() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let mut ledger_db = create_db();
        let key_images = generate_key_image_test_block(
            &mut ledger_db,
            vec![
                AccountKey::random(&mut rng),
                AccountKey::random(&mut rng),
                AccountKey::random(&mut rng),
            ],
            AccountKey::random(&mut rng),
        );

        let key_image_a = key_images.get(0).unwrap();
        let key_image_b = key_images.get(1).unwrap();

        // The ledger should contain `key_image_a`.
        assert!(ledger_db.contains_key_image(&key_image_a).unwrap());

        // The ledger should contain `key_image_b`.
        assert!(ledger_db.contains_key_image(&key_image_b).unwrap());

        let key_image_c: KeyImage = KeyImage::from(3);

        // The ledger should not contain `key_image_c`.
        assert_eq!(false, ledger_db.contains_key_image(&key_image_c).unwrap());
    }

    #[test]
    // `get_key_images_by_block` should return the correct set of key images used in a single block.
    fn test_get_key_images_by_block() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let mut ledger_db = create_db();

        // Block 0
        let key_images = generate_key_image_test_block(
            &mut ledger_db,
            vec![
                AccountKey::random(&mut rng),
                AccountKey::random(&mut rng),
                AccountKey::random(&mut rng),
            ],
            AccountKey::random(&mut rng),
        );

        let key_image_a = key_images.get(0).unwrap();
        let key_image_b = key_images.get(1).unwrap();
        let key_image_c = key_images.get(2).unwrap();

        // Block 1
        let key_images = generate_key_image_test_block(
            &mut ledger_db,
            vec![AccountKey::random(&mut rng), AccountKey::random(&mut rng)],
            AccountKey::random(&mut rng),
        );

        let key_image_d = key_images.get(0).unwrap();
        let key_image_e = key_images.get(1).unwrap();

        // Block 2
        let key_images = generate_key_image_test_block(
            &mut ledger_db,
            vec![
                AccountKey::random(&mut rng),
                AccountKey::random(&mut rng),
                AccountKey::random(&mut rng),
                AccountKey::random(&mut rng),
            ],
            AccountKey::random(&mut rng),
        );

        let key_image_f = key_images.get(0).unwrap();
        let key_image_g = key_images.get(1).unwrap();
        let key_image_h = key_images.get(2).unwrap();
        let key_image_i = key_images.get(3).unwrap();

        // Key Images in block 0
        {
            let images_by_block_zero: Vec<KeyImage> = ledger_db.get_key_images_by_block(0).unwrap();
            assert_eq!(3, images_by_block_zero.len());
            assert!(images_by_block_zero
                .iter()
                .any(|image| image == key_image_a));
            assert!(images_by_block_zero
                .iter()
                .any(|image| image == key_image_b));
            assert!(images_by_block_zero
                .iter()
                .any(|image| image == key_image_c));

            assert!(images_by_block_zero
                .iter()
                .find(|&image| image == key_image_d)
                .is_none());
            assert!(images_by_block_zero
                .iter()
                .find(|&image| image == key_image_e)
                .is_none());
            assert!(images_by_block_zero
                .iter()
                .find(|&image| image == key_image_f)
                .is_none());
            assert!(images_by_block_zero
                .iter()
                .find(|&image| image == key_image_g)
                .is_none());
            assert!(images_by_block_zero
                .iter()
                .find(|&image| image == key_image_h)
                .is_none());
            assert!(images_by_block_zero
                .iter()
                .find(|&image| image == key_image_i)
                .is_none());
        }

        // Key Images in block 1
        {
            let images_by_block_one: Vec<KeyImage> = ledger_db.get_key_images_by_block(1).unwrap();
            assert_eq!(2, images_by_block_one.len());
            assert!(images_by_block_one.iter().any(|image| image == key_image_d));
            assert!(images_by_block_one.iter().any(|image| image == key_image_e));
        }

        // Key Images in block 2
        {
            let images_by_block_two: Vec<KeyImage> = ledger_db.get_key_images_by_block(2).unwrap();
            assert_eq!(4, images_by_block_two.len());
            assert!(images_by_block_two.iter().any(|image| image == key_image_f));
            assert!(images_by_block_two.iter().any(|image| image == key_image_g));
            assert!(images_by_block_two.iter().any(|image| image == key_image_h));
            assert!(images_by_block_two.iter().any(|image| image == key_image_i));
        }
    }

    #[test]
    /// Attempting to append an empty block should return Error::NoTransactions.
    fn test_append_empty_block() {
        let mut ledger_db = create_db();
        let (block, txs) = BlockBuilder::new(None, Default::default()).build();
        assert_eq!(
            ledger_db.append_block(&block, &txs, None),
            Err(Error::NoTransactions)
        );
    }

    #[test]
    /// Attempting to append an block of incorrect version should return Error::InvalidBlock.
    fn test_append_block_with_invalid_version() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let mut ledger_db = create_db();
        let account_key = AccountKey::random(&mut rng);

        let tx_out = TxOut::new(
            100,
            &account_key.default_subaddress(),
            &RistrettoPrivate::from_random(&mut rng),
            Default::default(),
            &mut rng,
        )
        .unwrap();

        let redacted_transactions = vec![RedactedTx {
            outputs: vec![tx_out],
            key_images: vec![],
        }];

        let mut block = Block::new_origin_block(&redacted_transactions);

        block.version = 1337;
        assert_eq!(
            ledger_db.append_block(&block, &redacted_transactions, None),
            Err(Error::InvalidBlock)
        );
    }

    #[test]
    fn test_append_block_at_wrong_location() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let mut ledger_db = create_db();
        let account_key = AccountKey::random(&mut rng);

        // initialize a ledger with 3 blocks.
        let n_blocks = 3;
        let blocks = populate_db(&mut ledger_db, n_blocks, 2);
        assert_eq!(ledger_db.num_blocks().unwrap(), n_blocks);

        let tx_out = TxOut::new(
            100,
            &account_key.default_subaddress(),
            &RistrettoPrivate::from_random(&mut rng),
            Default::default(),
            &mut rng,
        )
        .unwrap();

        let redacted_transactions = vec![RedactedTx {
            outputs: vec![tx_out],
            key_images: vec![],
        }];

        // Appending a block to a previously written location should fail.
        let mut new_block = Block::new(
            BLOCK_VERSION,
            &blocks[0].id,
            1,
            3,
            &Default::default(),
            &redacted_transactions,
        );

        assert_eq!(
            ledger_db.append_block(&new_block, &redacted_transactions, None),
            Err(Error::InvalidBlock)
        );

        // Appending a non-contiguous location should fail.
        new_block.index = 3 * n_blocks;
        assert_eq!(
            ledger_db.append_block(&new_block, &redacted_transactions, None),
            Err(Error::InvalidBlock)
        );
    }

    #[test]
    /// Appending a block with a spent key image should return Error::KeyImageAlreadySpent.
    fn test_append_block_with_spent_key_image() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let mut ledger_db = create_db();
        let input_accounts: Vec<AccountKey> = vec![
            AccountKey::random(&mut rng),
            AccountKey::random(&mut rng),
            AccountKey::random(&mut rng),
        ];
        let recipient_account = AccountKey::random(&mut rng);

        let value = 10000;
        // Mint an initial collection of outputs so that we have something to spend.
        let minted_outputs: Vec<TxOut> = {
            let recipient_and_amounts: Vec<(PublicAddress, u64)> = input_accounts
                .iter()
                .map(|account| (account.default_subaddress(), value))
                .collect();
            get_outputs(&recipient_and_amounts, &mut rng)
        };

        // Create a transaction and a block that spends one of the outputs above.
        let transaction = {
            let ring: Vec<TxOut> = minted_outputs.clone();
            let membership_proofs: Vec<TxOutMembershipProof> = ring
                .iter()
                .map(|_tx_out| {
                    // These membership proofs aren't important for this unit test, because
                    // membership proofs are normally discarded before a block is written to the
                    // ledger. However, the TransactionBuilder requires a membership proof
                    // for each ring element.
                    TxOutMembershipProof::new(0, 0, HashMap::default())
                })
                .collect();

            let input_account = input_accounts.get(0).unwrap();
            let public_key = RistrettoPublic::try_from(&minted_outputs[0].public_key).unwrap();
            let onetime_private_key = recover_onetime_private_key(
                &public_key,
                input_account.view_private_key(),
                &input_account.default_subaddress_spend_key(),
            );

            let input_credentials = InputCredentials::new(
                ring,
                membership_proofs,
                0,
                onetime_private_key,
                *input_account.view_private_key(),
                &mut rng,
            )
            .unwrap();

            let mut transaction_builder = TransactionBuilder::new();
            transaction_builder.add_input(input_credentials);
            transaction_builder.set_fee(0);
            transaction_builder
                .add_output(
                    value,
                    &recipient_account.default_subaddress(),
                    None,
                    &mut rng,
                )
                .unwrap();

            transaction_builder.build(&mut rng).unwrap()
        };
        let (block_zero, txs) = BlockBuilder::new(None, Default::default())
            .add_transaction(transaction)
            .build();

        ledger_db
            .append_block(&block_zero, &txs, None)
            .expect("failed writing block 0");

        // Create a second transaction and a block that tries to spend the same output, it
        // should fail
        {
            let ring: Vec<TxOut> = minted_outputs.clone();
            let membership_proofs: Vec<TxOutMembershipProof> = ring
                .iter()
                .map(|_tx_out| {
                    // These membership proofs aren't important for this unit test, because
                    // membership proofs are normally discarded before a block is written to the
                    // ledger. However, the TransactionBuilder requires a membership proof
                    // for each ring element.
                    TxOutMembershipProof::new(0, 0, HashMap::default())
                })
                .collect();

            let input_account = input_accounts.get(0).unwrap();
            let public_key = RistrettoPublic::try_from(&minted_outputs[0].public_key).unwrap();
            let onetime_private_key = recover_onetime_private_key(
                &public_key,
                input_account.view_private_key(),
                &input_account.default_subaddress_spend_key(),
            );

            let input_credentials = InputCredentials::new(
                ring,
                membership_proofs,
                0,
                onetime_private_key,
                *input_account.view_private_key(),
                &mut rng,
            )
            .unwrap();
            let mut transaction_builder = TransactionBuilder::new();
            transaction_builder.add_input(input_credentials);
            transaction_builder.set_fee(0);
            transaction_builder
                .add_output(
                    value,
                    &recipient_account.default_subaddress(),
                    None,
                    &mut rng,
                )
                .unwrap();

            let transaction = transaction_builder.build(&mut rng).unwrap();
            let (block, txs) = BlockBuilder::new(Some(block_zero.clone()), Default::default())
                .add_transaction(transaction)
                .build();

            assert_eq!(
                ledger_db.append_block(&block, &txs, None),
                Err(Error::KeyImageAlreadySpent)
            );
        }

        // Spending a different output should work fine
        {
            let ring: Vec<TxOut> = minted_outputs.clone();
            let membership_proofs: Vec<TxOutMembershipProof> = ring
                .iter()
                .map(|_tx_out| {
                    // These membership proofs aren't important for this unit test, because
                    // membership proofs are normally discarded before a block is written to the
                    // ledger. However, the TransactionBuilder requires a membership proof
                    // for each ring element.
                    TxOutMembershipProof::new(0, 0, HashMap::default())
                })
                .collect();

            let input_account = input_accounts.get(1).unwrap();
            let public_key = RistrettoPublic::try_from(&minted_outputs[1].public_key).unwrap();
            let onetime_private_key = recover_onetime_private_key(
                &public_key,
                input_account.view_private_key(),
                &input_account.default_subaddress_spend_key(),
            );

            let input_credentials = InputCredentials::new(
                ring,
                membership_proofs,
                1,
                onetime_private_key,
                *input_account.view_private_key(),
                &mut rng,
            )
            .unwrap();

            let mut transaction_builder = TransactionBuilder::new();
            transaction_builder.add_input(input_credentials);
            transaction_builder.set_fee(0);
            transaction_builder
                .add_output(
                    value,
                    &recipient_account.default_subaddress(),
                    None,
                    &mut rng,
                )
                .unwrap();

            let transaction = transaction_builder.build(&mut rng).unwrap();
            let (block, txs) = BlockBuilder::new(Some(block_zero), Default::default())
                .add_transaction(transaction)
                .build();

            assert_eq!(ledger_db.append_block(&block, &txs, None), Ok(()));
        }
        // Sanity - we should have two blocks
        assert_eq!(ledger_db.num_blocks().unwrap(), 2);
    }

    #[test]
    // append_block rejects invalid blocks.
    fn test_append_invalid_blocks() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let mut ledger_db = create_db();
        let account_key = AccountKey::random(&mut rng);

        let tx_out = TxOut::new(
            100,
            &account_key.default_subaddress(),
            &RistrettoPrivate::from_random(&mut rng),
            Default::default(),
            &mut rng,
        )
        .unwrap();

        let redacted_transactions = vec![RedactedTx {
            outputs: vec![tx_out],
            key_images: vec![],
        }];

        let block_zero = Block::new_origin_block(&redacted_transactions);

        // append_block rejects a block with invalid id.
        {
            let mut block = block_zero.clone();
            block.id.0[0] += 1;
            assert_eq!(
                ledger_db.append_block(&block, &redacted_transactions, None),
                Err(Error::InvalidBlockID)
            );
        }

        // append_block rejects a block with invalid contents hash.
        {
            let mut block = block_zero.clone();
            block.contents_hash.0[0] += 1;
            assert_eq!(
                ledger_db.append_block(&block, &redacted_transactions, None),
                Err(Error::InvalidBlockContents)
            );
        }

        assert_eq!(
            ledger_db.append_block(&block_zero, &redacted_transactions, None),
            Ok(())
        );

        // append_block rejects a block with non-existent parent.
        {
            let tx_out = TxOut::new(
                100,
                &account_key.default_subaddress(),
                &RistrettoPrivate::from_random(&mut rng),
                Default::default(),
                &mut rng,
            )
            .unwrap();

            let redacted_transactions = vec![RedactedTx {
                outputs: vec![tx_out],
                key_images: vec![],
            }];

            let bytes = [14u8; 32];
            let bad_parent_id = BlockID::try_from(&bytes[..]).unwrap();

            // This block has a bad parent id.
            let block_one_bad = Block::new(
                BLOCK_VERSION,
                &bad_parent_id,
                1,
                1,
                &Default::default(),
                &redacted_transactions,
            );

            assert_eq!(
                ledger_db.append_block(&block_one_bad, &redacted_transactions, None),
                Err(Error::InvalidBlock)
            );

            // This block correctly has block zero as its parent.
            let block_one_good = Block::new(
                BLOCK_VERSION,
                &block_zero.id,
                1,
                1,
                &Default::default(),
                &redacted_transactions,
            );

            assert_eq!(
                ledger_db.append_block(&block_one_good, &redacted_transactions, None),
                Ok(())
            );
        }
    }

    // FIXME(MC-526): If these benches are not marked ignore, they get run during cargo test
    // and they are not compiled with optimizations which makes them take several minutes
    // I think they should probably be moved to `ledger_db/benches/...` ?
    #[bench]
    #[ignore]
    fn bench_num_blocks(b: &mut Bencher) {
        let mut ledger_db = create_db();
        let n_blocks = 150;
        let n_txs_per_block = 1;
        let _ = populate_db(&mut ledger_db, n_blocks, n_txs_per_block);

        b.iter(|| ledger_db.num_blocks().unwrap())
    }

    #[bench]
    #[ignore]
    fn bench_get_block(b: &mut Bencher) {
        let mut ledger_db = create_db();
        let n_blocks = 30;
        let n_txs_per_block = 1000;
        let _ = populate_db(&mut ledger_db, n_blocks, n_txs_per_block);
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

        b.iter(|| ledger_db.get_block(rng.next_u64() % n_blocks).unwrap())
    }
}
