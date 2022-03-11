// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Persistent storage for the blockchain.
#![warn(unused_extern_crates)]
#![feature(test)]

#[cfg(test)]
extern crate test;

mod error;
mod ledger_trait;
mod metrics;
mod mint_config_store;
mod mint_tx_store;

pub mod tx_out_store;

#[cfg(any(test, feature = "test_utils"))]
pub mod test_utils;

use core::convert::TryInto;
use lmdb::{
    Database, DatabaseFlags, Environment, EnvironmentFlags, RoTransaction, RwTransaction,
    Transaction, WriteFlags,
};
use mc_common::logger::global_log;
use mc_crypto_keys::CompressedRistrettoPublic;
use mc_transaction_core::{
    membership_proofs::Range,
    ring_signature::KeyImage,
    tx::{TxOut, TxOutMembershipElement, TxOutMembershipProof},
    Block, BlockContents, BlockData, BlockID, BlockIndex, BlockSignature, TokenId,
    MAX_BLOCK_VERSION,
};
use mc_util_lmdb::MetadataStoreSettings;
use mc_util_serial::{decode, encode, Message};
use mc_util_telemetry::{
    mark_span_as_active, start_block_span, telemetry_static_key, tracer, Key, Span,
};
use metrics::LedgerMetrics;
use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
    time::Instant,
};

pub use error::Error;
pub use ledger_trait::{Ledger, MockLedger};
pub use mc_util_lmdb::{MetadataStore, MetadataStoreError};
pub use mint_config_store::{ActiveMintConfig, MintConfigStore};
pub use mint_tx_store::MintTxStore;
pub use tx_out_store::TxOutStore;

pub const MAX_LMDB_FILE_SIZE: usize = 2usize.pow(40); // 1 TB
pub const MAX_LMDB_DATABASES: u32 = 27; // maximum number of databases in the lmdb file

// LMDB Database names.
pub const COUNTS_DB_NAME: &str = "ledger_db:counts";
pub const BLOCKS_DB_NAME: &str = "ledger_db:blocks";
pub const BLOCK_SIGNATURES_DB_NAME: &str = "ledger_db:block_signatures";
pub const KEY_IMAGES_DB_NAME: &str = "ledger_db:key_images";
pub const KEY_IMAGES_BY_BLOCK_DB_NAME: &str = "ledger_db:key_images_by_block";
pub const TX_OUTS_BY_BLOCK_DB_NAME: &str = "ledger_db:tx_outs_by_block";
pub const BLOCK_NUMBER_BY_TX_OUT_INDEX: &str = "ledger_db:block_number_by_tx_out_index";

/// Keys used by the `counts` database.
pub const NUM_BLOCKS_KEY: &str = "num_blocks";

/// OpenTelemetry keys
const TELEMETRY_BLOCK_INDEX_KEY: Key = telemetry_static_key!("block-index");
const TELEMETRY_NUM_KEY_IMAGES_KEY: Key = telemetry_static_key!("num-key-images");
const TELEMETRY_NUM_TXOS_KEY: Key = telemetry_static_key!("num-txos");

/// Metadata store settings that are used for version control.
#[derive(Clone, Default, Debug)]
pub struct LedgerDbMetadataStoreSettings;
impl MetadataStoreSettings for LedgerDbMetadataStoreSettings {
    // Default database version. This should be bumped when breaking changes are
    // introduced. If this is properly maintained, we could check during ledger
    // db opening for any incompatibilities, and either refuse to open or
    // perform a migration.
    #[allow(clippy::inconsistent_digit_grouping)]
    const LATEST_VERSION: u64 = 2022_02_22;

    /// The current crate version that manages the database.
    const CRATE_VERSION: &'static str = env!("CARGO_PKG_VERSION");

    /// LMDB Database name to use for storing the metadata information.
    const DB_NAME: &'static str = "ledger_db_metadata";
}

/// The value stored for each entry in the `tx_outs_by_block` database.
#[derive(Clone, Message)]
pub struct TxOutsByBlockValue {
    /// The first TxOut index for the block.
    #[prost(uint64, tag = "1")]
    pub first_tx_out_index: u64,

    /// The number of TxOuts in the block.
    #[prost(uint64, tag = "2")]
    pub num_tx_outs: u64,
}

/// A list of key images that can be prost-encoded. This is needed since that's
/// the only way to encode a Vec<KeyImage>.
#[derive(Clone, Message)]
pub struct KeyImageList {
    #[prost(message, repeated, tag = "1")]
    pub key_images: Vec<KeyImage>,
}

#[derive(Clone)]
pub struct LedgerDB {
    env: Arc<Environment>,

    /// Aggregate counts about the ledger.
    /// * `NUM_BLOCKS_KEY` --> number of blocks in the ledger.
    counts: Database,

    /// Blocks by block number. `block number -> Block`
    blocks: Database,

    /// Block signatures by number. `block number -> BlockSignature`
    block_signatures: Database,

    /// Key Images
    key_images: Database,

    /// Key Images by Block
    key_images_by_block: Database,

    /// Metadata - stores metadata information about the database.
    metadata_store: MetadataStore<LedgerDbMetadataStoreSettings>,

    /// Storage abstraction for TxOuts.
    tx_out_store: TxOutStore,

    /// TxOuts by block number. `block number -> (first TxOut index, number of
    /// TxOuts in block)`. This map allows retrieval of all TxOuts that were
    /// included in a given block number by querying `tx_out_store`.
    tx_outs_by_block: Database,

    /// TxOut global index -> block number.
    /// This map allows retrieval of the block a given TxOut belongs to.
    block_number_by_tx_out_index: Database,

    /// Storage abstraction for mint configurations.
    mint_config_store: MintConfigStore,

    /// Storage abstraction for mint transactions.
    mint_tx_store: MintTxStore,

    /// Location on filesystem.
    path: PathBuf,

    /// Metrics.
    metrics: LedgerMetrics,
}

/// LedgerDB is an append-only log (or chain) of blocks of transactions.
impl Ledger for LedgerDB {
    /// Appends a block and its associated transactions to the blockchain.
    ///
    /// # Arguments
    /// * `block` - A block.
    /// * `block_contents` - The contents of the block.
    /// * `signature` - This node's signature over the block.
    fn append_block(
        &mut self,
        block: &Block,
        block_contents: &BlockContents,
        signature: Option<BlockSignature>,
    ) -> Result<(), Error> {
        let start_time = Instant::now();

        let tracer = tracer!();

        let mut span = start_block_span(&tracer, "append_block", block.index);
        span.set_attribute(TELEMETRY_BLOCK_INDEX_KEY.i64(block.index as i64));
        span.set_attribute(
            TELEMETRY_NUM_KEY_IMAGES_KEY.i64(block_contents.key_images.len() as i64),
        );
        span.set_attribute(TELEMETRY_NUM_TXOS_KEY.i64(block_contents.outputs.len() as i64));
        let _active = mark_span_as_active(span);

        // Note: This function must update every LMDB database managed by LedgerDB.
        let mut db_transaction = self.env.begin_rw_txn()?;

        // Validate the block is safe to append.
        self.validate_append_block(block, block_contents, &db_transaction)?;

        // Write key images included in block.
        self.write_key_images(block.index, &block_contents.key_images, &mut db_transaction)?;

        // Write information about TxOuts included in block.
        self.write_tx_outs(block.index, &block_contents.outputs, &mut db_transaction)?;

        // Write MintTxs included in the block. We do this before writing the
        // configuration, since the assumption is that the new configuration is not yet
        // active at the time the MintTx has made its way to a block.
        self.mint_tx_store.write_mint_txs(
            block.index,
            &block_contents.mint_txs,
            &self.mint_config_store,
            &mut db_transaction,
        )?;

        // Write MintConfigTxs included in the block.
        self.mint_config_store.write_mint_config_txs(
            block.index,
            &block_contents.mint_config_txs,
            &mut db_transaction,
        )?;

        // Write block.
        self.write_block(block, signature.as_ref(), &mut db_transaction)?;

        // Commit.
        db_transaction.commit()?;

        // Update metrics.
        self.metrics.blocks_written_count.inc();
        self.metrics.num_blocks.inc();

        self.metrics
            .txo_written_count
            .inc_by(block_contents.outputs.len() as u64);
        self.metrics
            .num_txos
            .add(block_contents.outputs.len() as i64);

        self.metrics.observe_append_block_time(start_time);

        let file_size = self.db_file_size().unwrap_or(0);
        self.metrics.db_file_size.set(file_size as i64);

        Ok(())
    }

    /// Get the total number of Blocks in the ledger.
    fn num_blocks(&self) -> Result<u64, Error> {
        let db_transaction = self.env.begin_ro_txn()?;
        Ok(key_bytes_to_u64(
            db_transaction.get(self.counts, &NUM_BLOCKS_KEY)?,
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
        self.get_block_impl(&db_transaction, block_number)
    }

    /// Get the contents of a block.
    fn get_block_contents(&self, block_number: u64) -> Result<BlockContents, Error> {
        let db_transaction = self.env.begin_ro_txn()?;
        self.get_block_contents_impl(&db_transaction, block_number)
    }

    /// Gets a block signature by its index in the blockchain.
    fn get_block_signature(&self, block_number: u64) -> Result<BlockSignature, Error> {
        let db_transaction = self.env.begin_ro_txn()?;
        self.get_block_signature_impl(&db_transaction, block_number)
    }

    /// Gets a block and all of its associated data by its index in the
    /// blockchain.
    fn get_block_data(&self, block_number: u64) -> Result<BlockData, Error> {
        let db_transaction = self.env.begin_ro_txn()?;

        let block = self.get_block_impl(&db_transaction, block_number)?;
        let contents = self.get_block_contents_impl(&db_transaction, block_number)?;
        let signature = match self.get_block_signature_impl(&db_transaction, block_number) {
            Ok(sig) => Ok(Some(sig)),
            Err(Error::NotFound) => Ok(None),
            Err(err) => Err(err),
        }?;

        Ok(BlockData::new(block, contents, signature))
    }

    /// Gets block index by a TxOut global index.
    fn get_block_index_by_tx_out_index(&self, tx_out_index: u64) -> Result<u64, Error> {
        let db_transaction = self.env.begin_ro_txn()?;
        let key = u64_to_key_bytes(tx_out_index);
        let block_index_bytes = db_transaction.get(self.block_number_by_tx_out_index, &key)?;
        Ok(key_bytes_to_u64(block_index_bytes))
    }

    /// Returns the index of the TxOut with the given hash.
    fn get_tx_out_index_by_hash(&self, tx_out_hash: &[u8; 32]) -> Result<u64, Error> {
        let db_transaction: RoTransaction = self.env.begin_ro_txn()?;
        self.tx_out_store
            .get_tx_out_index_by_hash(tx_out_hash, &db_transaction)
    }

    /// Returns the index of the TxOut with the given public key.
    fn get_tx_out_index_by_public_key(
        &self,
        tx_out_public_key: &CompressedRistrettoPublic,
    ) -> Result<u64, Error> {
        let db_transaction: RoTransaction = self.env.begin_ro_txn()?;
        self.tx_out_store
            .get_tx_out_index_by_public_key(tx_out_public_key, &db_transaction)
    }

    /// Gets a TxOut by its index in the ledger.
    fn get_tx_out_by_index(&self, index: u64) -> Result<TxOut, Error> {
        let db_transaction = self.env.begin_ro_txn()?;
        self.tx_out_store
            .get_tx_out_by_index(index, &db_transaction)
    }

    /// Returns true if the Ledger contains the given TxOut public key.
    fn contains_tx_out_public_key(
        &self,
        public_key: &CompressedRistrettoPublic,
    ) -> Result<bool, Error> {
        let db_transaction = self.env.begin_ro_txn()?;
        self.contains_tx_out_public_key_impl(public_key, &db_transaction)
    }

    /// Returns true if the Ledger contains the given KeyImage.
    fn check_key_image(&self, key_image: &KeyImage) -> Result<Option<BlockIndex>, Error> {
        let db_transaction = self.env.begin_ro_txn()?;
        self.check_key_image_impl(key_image, &db_transaction)
    }

    /// Gets the KeyImages used by transactions in a single Block.
    fn get_key_images_by_block(&self, block_number: BlockIndex) -> Result<Vec<KeyImage>, Error> {
        let db_transaction = self.env.begin_ro_txn()?;
        let key_image_list: KeyImageList =
            decode(db_transaction.get(self.key_images_by_block, &u64_to_key_bytes(block_number))?)?;
        Ok(key_image_list.key_images)
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

    /// Get the tx out root membership element from the tx out Merkle Tree.
    fn get_root_tx_out_membership_element(&self) -> Result<TxOutMembershipElement, Error> {
        let db_transaction = self.env.begin_ro_txn()?;

        let num_txos = self.tx_out_store.num_tx_outs(&db_transaction)?;
        if num_txos == 0 {
            return Err(Error::NoOutputs);
        }

        let root_merkle_hash = self.tx_out_store.get_root_merkle_hash(&db_transaction)?;

        let range = Range::new(
            0,
            // This duplicates the range calculation logic inside get_root_merkle_hash
            num_txos
                .checked_next_power_of_two()
                .ok_or(Error::CapacityExceeded)?
                - 1,
        )?;
        Ok(TxOutMembershipElement::new(range, root_merkle_hash))
    }

    /// Get active mint configurations for a given token id.
    /// Returns an empty array of no mint configurations are active for the
    /// given token id.
    fn get_active_mint_configs(&self, token_id: TokenId) -> Result<Vec<ActiveMintConfig>, Error> {
        let db_transaction = self.env.begin_ro_txn()?;
        self.mint_config_store
            .get_active_mint_configs(token_id, &db_transaction)
    }

    /// Checks if the ledger contains a given MintConfigTx nonce.
    /// If so, returns the index of the block in which it entered the ledger.
    /// Ok(None) is returned when the nonce is not in the ledger.
    fn check_mint_config_tx_nonce(&self, nonce: &[u8]) -> Result<Option<BlockIndex>, Error> {
        let db_transaction = self.env.begin_ro_txn()?;
        self.mint_config_store
            .check_mint_config_tx_nonce(nonce, &db_transaction)
    }

    /// Checks if the ledger contains a given MintTx nonce.
    /// If so, returns the index of the block in which it entered the ledger.
    /// Ok(None) is returned when the nonce is not in the ledger.
    fn check_mint_tx_nonce(&self, nonce: &[u8]) -> Result<Option<BlockIndex>, Error> {
        let db_transaction = self.env.begin_ro_txn()?;
        self.mint_tx_store
            .check_mint_tx_nonce(nonce, &db_transaction)
    }
}

impl LedgerDB {
    /// Opens an existing Ledger Database in the given path.
    #[allow(clippy::unreadable_literal)]
    pub fn open(path: &Path) -> Result<LedgerDB, Error> {
        let env = Environment::new()
            .set_max_dbs(MAX_LMDB_DATABASES)
            .set_map_size(MAX_LMDB_FILE_SIZE)
            // TODO - needed because currently our test cloud machines have slow disks.
            .set_flags(EnvironmentFlags::NO_SYNC)
            .open(path)?;

        let metadata_store = MetadataStore::<LedgerDbMetadataStoreSettings>::new(&env)?;
        let db_txn = env.begin_ro_txn()?;
        let version = metadata_store.get_version(&db_txn)?;
        global_log::info!("Ledger db is currently at version: {:?}", version);
        db_txn.commit()?;

        version.is_compatible_with_latest()?;

        let counts = env.open_db(Some(COUNTS_DB_NAME))?;
        let blocks = env.open_db(Some(BLOCKS_DB_NAME))?;
        let block_signatures = env.open_db(Some(BLOCK_SIGNATURES_DB_NAME))?;
        let key_images = env.open_db(Some(KEY_IMAGES_DB_NAME))?;
        let key_images_by_block = env.open_db(Some(KEY_IMAGES_BY_BLOCK_DB_NAME))?;
        let tx_outs_by_block = env.open_db(Some(TX_OUTS_BY_BLOCK_DB_NAME))?;
        let block_number_by_tx_out_index = env.open_db(Some(BLOCK_NUMBER_BY_TX_OUT_INDEX))?;

        let tx_out_store = TxOutStore::new(&env)?;
        let mint_config_store = MintConfigStore::new(&env)?;
        let mint_tx_store = MintTxStore::new(&env)?;

        let metrics = LedgerMetrics::new(path);

        let ledger_db = LedgerDB {
            env: Arc::new(env),
            path: path.to_path_buf(),
            counts,
            blocks,
            block_signatures,
            key_images,
            key_images_by_block,
            tx_outs_by_block,
            block_number_by_tx_out_index,
            metadata_store,
            tx_out_store,
            mint_config_store,
            mint_tx_store,
            metrics,
        };

        // Get initial values for gauges.
        ledger_db.update_metrics()?;

        Ok(ledger_db)
    }

    /// Creates a fresh Ledger Database in the given path.
    pub fn create(path: &Path) -> Result<(), Error> {
        let env = Environment::new()
            .set_max_dbs(MAX_LMDB_DATABASES)
            .set_map_size(MAX_LMDB_FILE_SIZE)
            .open(path)?;

        let counts = env.create_db(Some(COUNTS_DB_NAME), DatabaseFlags::empty())?;
        env.create_db(Some(BLOCKS_DB_NAME), DatabaseFlags::empty())?;
        env.create_db(Some(BLOCK_SIGNATURES_DB_NAME), DatabaseFlags::empty())?;
        env.create_db(Some(KEY_IMAGES_DB_NAME), DatabaseFlags::empty())?;
        env.create_db(Some(KEY_IMAGES_BY_BLOCK_DB_NAME), DatabaseFlags::empty())?;
        env.create_db(Some(TX_OUTS_BY_BLOCK_DB_NAME), DatabaseFlags::empty())?;
        env.create_db(Some(BLOCK_NUMBER_BY_TX_OUT_INDEX), DatabaseFlags::empty())?;

        MetadataStore::<LedgerDbMetadataStoreSettings>::create(&env)?;
        TxOutStore::create(&env)?;
        MintConfigStore::create(&env)?;
        MintTxStore::create(&env)?;

        let mut db_transaction = env.begin_rw_txn()?;

        db_transaction.put(
            counts,
            &NUM_BLOCKS_KEY,
            &u64_to_key_bytes(0),
            WriteFlags::empty(),
        )?;

        db_transaction.commit()?;
        Ok(())
    }

    /// Force an update of the metric gauges. This is useful when the ledger db
    /// is being updated externally (for example by mobilecoind), but we
    /// still want to publish the correct metrics. Users can call this
    /// periodically to do that.
    pub fn update_metrics(&self) -> Result<(), Error> {
        let num_blocks = self.num_blocks()?;
        self.metrics.num_blocks.set(num_blocks as i64);

        let num_txos = self.num_txos()?;
        self.metrics.num_txos.set(num_txos as i64);

        let file_size = self.db_file_size().unwrap_or(0);
        self.metrics.db_file_size.set(file_size as i64);

        Ok(())
    }

    /// Write a `Block`.
    fn write_block(
        &self,
        block: &Block,
        signature: Option<&BlockSignature>,
        db_transaction: &mut RwTransaction,
    ) -> Result<(), lmdb::Error> {
        // Update total number of blocks.
        let num_blocks_before: u64 =
            key_bytes_to_u64(db_transaction.get(self.counts, &NUM_BLOCKS_KEY)?);
        db_transaction.put(
            self.counts,
            &NUM_BLOCKS_KEY,
            &u64_to_key_bytes(num_blocks_before + 1),
            WriteFlags::empty(),
        )?;

        db_transaction.put(
            self.blocks,
            &u64_to_key_bytes(block.index),
            &encode(block),
            WriteFlags::empty(),
        )?;

        if let Some(signature) = signature {
            db_transaction.put(
                self.block_signatures,
                &u64_to_key_bytes(block.index),
                &encode(signature),
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

        let key_image_list = KeyImageList {
            key_images: key_images.to_vec(),
        };
        db_transaction.put(
            self.key_images_by_block,
            &u64_to_key_bytes(block_index),
            &encode(&key_image_list),
            WriteFlags::empty(),
        )?;
        Ok(())
    }

    fn write_tx_outs(
        &self,
        block_index: u64,
        tx_outs: &[TxOut],
        db_transaction: &mut RwTransaction,
    ) -> Result<(), Error> {
        // The index of the next TxOut we would be writing, which is the first one for
        // this block, is determined by how many TxOuts are currently in the
        // ledger.
        let next_tx_out_index = self.tx_out_store.num_tx_outs(db_transaction)?;

        // Store information about the TxOuts included in this block.
        let bytes = encode(&TxOutsByBlockValue {
            first_tx_out_index: next_tx_out_index,
            num_tx_outs: tx_outs.len() as u64,
        });

        db_transaction.put(
            self.tx_outs_by_block,
            &u64_to_key_bytes(block_index),
            &bytes,
            WriteFlags::empty(),
        )?;

        // Write the actual TxOuts.
        let block_index_bytes = u64_to_key_bytes(block_index);

        for tx_out in tx_outs {
            if self.contains_tx_out_public_key(&tx_out.public_key)? {
                return Err(Error::DuplicateOutputPublicKey);
            }

            let tx_out_index = self.tx_out_store.push(tx_out, db_transaction)?;

            db_transaction.put(
                self.block_number_by_tx_out_index,
                &u64_to_key_bytes(tx_out_index),
                &block_index_bytes,
                WriteFlags::NO_OVERWRITE,
            )?;
        }

        // Done.
        Ok(())
    }

    /// Checks if a block can be appended to the db.
    fn validate_append_block(
        &self,
        block: &Block,
        block_contents: &BlockContents,
        db_transaction: &impl Transaction,
    ) -> Result<(), Error> {
        // Check version is correct
        // Check if block is being appended at the correct place.
        let num_blocks = self.num_blocks()?;
        if num_blocks == 0 {
            // This must be an origin block.

            // The origin block is version 0
            if block.version != 0 {
                return Err(Error::InvalidBlockVersion(block.version));
            }

            // The origin block is index '0' with default-initialized parent ID, by
            // convention
            if block.index != 0 {
                return Err(Error::InvalidBlockIndex(block.index));
            }
            if block.parent_id != BlockID::default() {
                return Err(Error::InvalidParentBlockID(block.id.clone()));
            }
        } else {
            let last_block = self.get_block(num_blocks - 1)?;

            // The block's version should be bounded by
            // [prev block version, max block version]
            if block.version < last_block.version || block.version > *MAX_BLOCK_VERSION {
                return Err(Error::InvalidBlockVersion(block.version));
            }

            // The block must have the correct index and parent.
            if block.index != num_blocks {
                return Err(Error::InvalidBlockIndex(block.index));
            }
            if block.parent_id != last_block.id {
                return Err(Error::InvalidParentBlockID(block.parent_id.clone()));
            }
        }

        // A block must have outputs, unless it has mint-config transactions:
        // - Origin block had outputs only outputs in it.
        // - Blocks before minting was introduced always had outputs in them.
        // - Blocks that have MintTxs in them will also have the minted TxOuts in them.
        // - Blocks with only MintConfigTxs are allowed to not have outputs.
        let has_mint_config_txs = !block_contents.mint_config_txs.is_empty();
        if block_contents.outputs.is_empty() && !has_mint_config_txs {
            return Err(Error::NoOutputs);
        }

        // Number of outputs must be >= number of mint transactions because each mint
        // transaction must produce a single output.
        if block_contents.outputs.len() < block_contents.mint_txs.len() {
            return Err(Error::TooFewOutputs);
        }

        // Non-origin blocks must have key images, unless it has minting-related
        // transactions. When we have minting transactions it implies we might've not
        // spent any pre-existing outputs and as such we will not have key images.
        let has_minting_txs =
            !block_contents.mint_config_txs.is_empty() || !block_contents.mint_txs.is_empty();
        if block.index != 0 && block_contents.key_images.is_empty() && !has_minting_txs {
            return Err(Error::NoKeyImages);
        }

        // Check that the block contents match the hash.
        if block.contents_hash != block_contents.hash() {
            return Err(Error::InvalidBlockContents);
        }

        // Check that none of the key images were previously spent.
        for key_image in &block_contents.key_images {
            if self
                .check_key_image_impl(key_image, db_transaction)?
                .is_some()
            {
                return Err(Error::KeyImageAlreadySpent);
            }
        }

        // Check that none of the output public keys appear in the ledger.
        for output in block_contents.outputs.iter() {
            if self.contains_tx_out_public_key_impl(&output.public_key, db_transaction)? {
                return Err(Error::DuplicateOutputPublicKey);
            }
        }

        // Validate block id.
        if !block.is_block_id_valid() {
            return Err(Error::InvalidBlockID(block.id.clone()));
        }

        // Check that none of the minting transaction nonces appear in the ledger.
        for mint_tx in block_contents.mint_txs.iter() {
            if self
                .mint_tx_store
                .check_mint_tx_nonce(&mint_tx.prefix.nonce, db_transaction)?
                .is_some()
            {
                return Err(Error::DuplicateMintTx);
            }
        }

        // Check that none of the mint-config-tx nonces appear in the ledger.
        for mint_config_tx in block_contents.mint_config_txs.iter() {
            if self
                .mint_config_store
                .check_mint_config_tx_nonce(&mint_config_tx.prefix.nonce, db_transaction)?
                .is_some()
            {
                return Err(Error::DuplicateMintConfigTx);
            }
        }

        // All good
        Ok(())
    }

    /// Get the database file size, in bytes.
    fn db_file_size(&self) -> std::io::Result<u64> {
        let mut filename = self.path.clone();
        filename.push("data.mdb");

        let metadata = fs::metadata(filename)?;
        Ok(metadata.len())
    }

    /// Implementatation of the `get_block` method that operates inside a given
    /// transaction.
    fn get_block_impl(
        &self,
        db_transaction: &impl Transaction,
        block_number: u64,
    ) -> Result<Block, Error> {
        let key = u64_to_key_bytes(block_number);
        let block_bytes = db_transaction.get(self.blocks, &key)?;
        let block = decode(block_bytes)?;
        Ok(block)
    }

    /// Implementation of the `get_block_contents` method that operates inside a
    /// given transaction.
    fn get_block_contents_impl(
        &self,
        db_transaction: &impl Transaction,
        block_number: u64,
    ) -> Result<BlockContents, Error> {
        // Get all TxOuts in block.
        let bytes = db_transaction.get(self.tx_outs_by_block, &u64_to_key_bytes(block_number))?;
        let value: TxOutsByBlockValue = decode(bytes)?;

        let outputs = (value.first_tx_out_index..(value.first_tx_out_index + value.num_tx_outs))
            .map(|tx_out_index| {
                self.tx_out_store
                    .get_tx_out_by_index(tx_out_index, db_transaction)
            })
            .collect::<Result<Vec<TxOut>, Error>>()?;

        // Get all KeyImages in block.
        let key_image_list: KeyImageList =
            decode(db_transaction.get(self.key_images_by_block, &u64_to_key_bytes(block_number))?)?;

        // Get all MintConfigTxs in block.
        let mint_config_txs = self
            .mint_config_store
            .get_mint_config_txs_by_block_index(block_number, db_transaction)?;

        // Get all MintTxs in block.
        let mint_txs = self
            .mint_tx_store
            .get_mint_txs_by_block_index(block_number, db_transaction)?;

        // Returns block contents.
        Ok(BlockContents {
            key_images: key_image_list.key_images,
            outputs,
            mint_config_txs,
            mint_txs,
        })
    }

    /// Implementation of the `get_block_signature` method that operates inside
    /// a given transaction.
    fn get_block_signature_impl(
        &self,
        db_transaction: &impl Transaction,
        block_number: u64,
    ) -> Result<BlockSignature, Error> {
        let key = u64_to_key_bytes(block_number);
        let signature_bytes = db_transaction.get(self.block_signatures, &key)?;
        let signature = decode(signature_bytes)?;
        Ok(signature)
    }

    /// Returns true if the Ledger contains the given TxOut public key.
    fn contains_tx_out_public_key_impl(
        &self,
        public_key: &CompressedRistrettoPublic,
        db_transaction: &impl Transaction,
    ) -> Result<bool, Error> {
        match self
            .tx_out_store
            .get_tx_out_index_by_public_key(public_key, db_transaction)
        {
            Ok(_) => Ok(true),
            Err(Error::NotFound) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Returns true if the Ledger contains the given KeyImage.
    fn check_key_image_impl(
        &self,
        key_image: &KeyImage,
        db_transaction: &impl Transaction,
    ) -> Result<Option<u64>, Error> {
        match db_transaction.get(self.key_images, &key_image) {
            Ok(db_bytes) => {
                assert_eq!(db_bytes.len(), 8, "Expected exactly 8 le bytes (u64 block height) to be stored with key image, found {}", db_bytes.len());
                let mut u64_buf = [0u8; 8];
                u64_buf.copy_from_slice(db_bytes);
                Ok(Some(u64::from_le_bytes(u64_buf)))
            }
            Err(lmdb::Error::NotFound) => Ok(None),
            Err(e) => Err(Error::Lmdb(e)),
        }
    }
}

// Specifies how we encode the u32/u64 chunk number in lmdb
// The lexicographical sorting of the numbers, done by lmdb, must match the
// numeric order of the chunks. Thus we use Big Endian byte order here
pub fn u64_to_key_bytes(value: u64) -> [u8; 8] {
    value.to_be_bytes()
}

pub fn key_bytes_to_u64(bytes: &[u8]) -> u64 {
    assert_eq!(8, bytes.len());
    u64::from_be_bytes(bytes.try_into().unwrap())
}

pub fn u32_to_key_bytes(value: u32) -> [u8; 4] {
    value.to_be_bytes()
}

#[cfg(test)]
mod ledger_db_test {
    use super::*;
    use crate::mint_config_store::tests::{
        generate_test_mint_config_tx, generate_test_mint_config_tx_and_signers,
        generate_test_mint_tx,
    };
    use core::convert::TryFrom;
    use mc_account_keys::AccountKey;
    use mc_crypto_keys::{Ed25519Pair, RistrettoPrivate};
    use mc_transaction_core::{
        compute_block_id, membership_proofs::compute_implied_merkle_root, tokens::Mob,
        BlockVersion, Token,
    };
    use mc_util_from_random::FromRandom;
    use rand::{rngs::StdRng, SeedableRng};
    use rand_core::{CryptoRng, RngCore};
    use tempdir::TempDir;
    use test::Bencher;

    // TODO: Should these tests run over several block versions?
    const BLOCK_VERSION: BlockVersion = BlockVersion::ONE;

    /// Creates a LedgerDB instance.
    fn create_db() -> LedgerDB {
        let temp_dir = TempDir::new("test").unwrap();
        let path = temp_dir.path();
        LedgerDB::create(path).unwrap();
        LedgerDB::open(path).unwrap()
    }

    /// Populates the LedgerDB with initial data, and returns the Block entities
    /// that were written.
    ///
    /// # Arguments
    /// * `db` - LedgerDb.
    /// * `num_blocks` - number of blocks  to write to `db`.
    /// * `n_txs_per_block` - number of transactions per block.
    fn populate_db(
        db: &mut LedgerDB,
        num_blocks: u64,
        num_outputs_per_block: u64,
    ) -> (Vec<Block>, Vec<BlockContents>) {
        let initial_amount: u64 = 5_000 * 1_000_000_000_000;

        // Generate 1 public / private addresses and create transactions.
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let account_key = AccountKey::random(&mut rng);

        let mut parent_block: Option<Block> = None;
        let mut blocks: Vec<Block> = Vec::new();
        let mut blocks_contents: Vec<BlockContents> = Vec::new();

        for block_index in 0..num_blocks {
            let outputs: Vec<TxOut> = (0..num_outputs_per_block)
                .map(|_i| {
                    let mut result = TxOut::new(
                        initial_amount,
                        Mob::ID,
                        &account_key.default_subaddress(),
                        &RistrettoPrivate::from_random(&mut rng),
                        Default::default(),
                    )
                    .unwrap();
                    // Origin block doesn't have memos
                    if block_index == 0 {
                        result.e_memo = None
                    };
                    result
                })
                .collect();

            // Non-origin blocks must have at least one key image.
            let key_images: Vec<KeyImage> = if block_index > 0 {
                vec![KeyImage::from(block_index)]
            } else {
                vec![]
            };

            let block_contents = BlockContents {
                key_images,
                outputs: outputs.clone(),
                ..Default::default()
            };

            let block = match parent_block {
                None => Block::new_origin_block(&outputs),
                Some(parent) => Block::new_with_parent(
                    BLOCK_VERSION,
                    &parent,
                    &Default::default(),
                    &block_contents,
                ),
            };
            assert_eq!(block_index, block.index);

            db.append_block(&block, &block_contents, None)
                .expect("failed writing initial transactions");
            blocks.push(block.clone());
            blocks_contents.push(block_contents);
            parent_block = Some(block);
        }

        // Verify that db now contains n transactions.
        assert_eq!(db.num_blocks().unwrap(), num_blocks as u64);

        (blocks, blocks_contents)
    }
    /// Generate a dummy txout for testing.
    fn get_test_tx_out(rng: &mut (impl RngCore + CryptoRng)) -> TxOut {
        let account_key = AccountKey::random(rng);
        TxOut::new(
            rng.next_u64(),
            &account_key.default_subaddress(),
            &RistrettoPrivate::from_random(rng),
            Default::default(),
        )
        .unwrap()
    }

    #[test]
    // Test initial conditions of a new LedgerDB instance.
    fn test_ledger_db_initialization() {
        let ledger_db = create_db();
        assert_eq!(ledger_db.num_blocks().unwrap(), 0);
        assert_eq!(ledger_db.num_txos().unwrap(), 0);
    }

    fn get_origin_block_and_contents(account_key: &AccountKey) -> (Block, BlockContents) {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

        let mut output = TxOut::new(
            1000,
            Mob::ID,
            &account_key.default_subaddress(),
            &RistrettoPrivate::from_random(&mut rng),
            Default::default(),
        )
        .unwrap();
        // Origin block transactions dont' have memos
        output.e_memo = None;

        let outputs = vec![output];
        let block = Block::new_origin_block(&outputs);
        let block_contents = BlockContents {
            outputs,
            ..Default::default()
        };

        (block, block_contents)
    }

    #[test]
    // Appending a block without any minting-related transactions should correctly
    // update each LMDB database.
    fn test_append_block_without_minting() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let mut ledger_db = create_db();

        // === Create and append the origin block. ===
        // The origin block contains a single output belonging to the
        // `origin_account_key`.

        let origin_account_key = AccountKey::random(&mut rng);
        let (origin_block, origin_block_contents) =
            get_origin_block_and_contents(&origin_account_key);

        ledger_db
            .append_block(&origin_block, &origin_block_contents, None)
            .unwrap();

        assert_eq!(1, ledger_db.num_blocks().unwrap());
        assert_eq!(origin_block, ledger_db.get_block(0).unwrap());
        assert_eq!(1, ledger_db.num_txos().unwrap());

        let origin_tx_out = origin_block_contents.outputs.get(0).unwrap().clone();
        assert_eq!(origin_tx_out, ledger_db.get_tx_out_by_index(0).unwrap());

        assert_eq!(
            origin_block_contents,
            ledger_db.get_block_contents(0).unwrap()
        );

        let key_images = ledger_db.get_key_images_by_block(0).unwrap();
        assert_eq!(key_images.len(), 0);

        let block_index = ledger_db.get_block_index_by_tx_out_index(0).unwrap();
        assert_eq!(block_index, 0);

        // === Create and append a non-origin block. ===

        let recipient_account_key = AccountKey::random(&mut rng);
        let outputs: Vec<TxOut> = (0..4)
            .map(|_i| {
                TxOut::new(
                    1000,
                    Mob::ID,
                    &recipient_account_key.default_subaddress(),
                    &RistrettoPrivate::from_random(&mut rng),
                    Default::default(),
                )
                .unwrap()
            })
            .collect();

        let key_images: Vec<KeyImage> = (0..5).map(|_i| KeyImage::from(rng.next_u64())).collect();

        let block_contents = BlockContents {
            key_images: key_images.clone(),
            outputs,
            ..Default::default()
        };
        let block = Block::new_with_parent(
            BLOCK_VERSION,
            &origin_block,
            &Default::default(),
            &block_contents,
        );

        ledger_db
            .append_block(&block, &block_contents, None)
            .unwrap();

        assert_eq!(2, ledger_db.num_blocks().unwrap());
        // The origin block should still be in the ledger:
        assert_eq!(origin_block, ledger_db.get_block(0).unwrap());
        // The new block should be in the ledger:
        assert_eq!(block, ledger_db.get_block(1).unwrap());
        assert_eq!(5, ledger_db.num_txos().unwrap());

        // The origin's TxOut should still be in the ledger:
        assert_eq!(origin_tx_out, ledger_db.get_tx_out_by_index(0).unwrap());

        // Each TxOut from the current block should be in the ledger.
        for (i, tx_out) in block_contents.outputs.iter().enumerate() {
            // The first tx_out is the origin block, tx_outs are for the following block
            // hence the + 1
            assert_eq!(
                ledger_db.get_tx_out_by_index((i + 1) as u64).unwrap(),
                *tx_out
            );

            // All tx outs are in the second block.
            let block_index = ledger_db
                .get_block_index_by_tx_out_index((i + 1) as u64)
                .unwrap();
            assert_eq!(block_index, 1);
        }

        assert!(ledger_db
            .contains_key_image(key_images.get(0).unwrap())
            .unwrap());

        let block_one_key_images = ledger_db.get_key_images_by_block(1).unwrap();
        assert_eq!(key_images, block_one_key_images);
    }

    #[test]
    // Appending a block with only MintConfigTxs should correctly update each
    // LMDB database.
    fn append_block_with_only_mint_config_tx() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let mut ledger_db = create_db();
        let token_id1 = TokenId::from(1);
        let token_id2 = TokenId::from(2);

        // === Create and append the origin block. ===
        // The origin block contains a single output belonging to the
        // `origin_account_key`.

        let origin_account_key = AccountKey::random(&mut rng);
        let (origin_block, origin_block_contents) =
            get_origin_block_and_contents(&origin_account_key);

        ledger_db
            .append_block(&origin_block, &origin_block_contents, None)
            .unwrap();

        let origin_tx_out = origin_block_contents.outputs.get(0).unwrap().clone();
        assert_eq!(origin_tx_out, ledger_db.get_tx_out_by_index(0).unwrap());

        assert_eq!(
            ledger_db.get_active_mint_configs(token_id1).unwrap(),
            vec![]
        );

        // === Append a block with only a single MintConfigTx. ===
        let mint_config_tx1 = generate_test_mint_config_tx(token_id1, &mut rng);

        let block_contents1 = BlockContents {
            mint_config_txs: vec![mint_config_tx1.clone()],
            ..Default::default()
        };

        let block1 = Block::new_with_parent(
            BLOCK_VERSION,
            &origin_block,
            &Default::default(),
            &block_contents1,
        );

        ledger_db
            .append_block(&block1, &block_contents1, None)
            .unwrap();

        assert_eq!(2, ledger_db.num_blocks().unwrap());
        // The origin block should still be in the ledger:
        assert_eq!(origin_block, ledger_db.get_block(0).unwrap());
        assert_eq!(1, ledger_db.num_txos().unwrap());
        // The new block should be in the ledger:
        assert_eq!(block1, ledger_db.get_block(1).unwrap());

        // The origin's TxOut should still be in the ledger:
        assert_eq!(origin_tx_out, ledger_db.get_tx_out_by_index(0).unwrap());

        // The new block contents should be in the ledger.
        assert_eq!(block_contents1, ledger_db.get_block_contents(1).unwrap());

        // The active mint configs should be updated.
        assert_eq!(
            ledger_db.get_active_mint_configs(token_id1).unwrap(),
            vec![
                ActiveMintConfig {
                    mint_config: mint_config_tx1.prefix.configs[0].clone(),
                    total_minted: 0,
                },
                ActiveMintConfig {
                    mint_config: mint_config_tx1.prefix.configs[1].clone(),
                    total_minted: 0,
                }
            ]
        );

        // Append another block with two MintConfigTxs, one of which is updating the
        // active config for token_id1.
        let mint_config_tx2 = generate_test_mint_config_tx(token_id1, &mut rng);
        let mint_config_tx3 = generate_test_mint_config_tx(token_id2, &mut rng);

        let block_contents2 = BlockContents {
            mint_config_txs: vec![mint_config_tx2.clone(), mint_config_tx3.clone()],
            ..Default::default()
        };

        let block2 = Block::new_with_parent(
            BLOCK_VERSION,
            &block1,
            &Default::default(),
            &block_contents2,
        );

        ledger_db
            .append_block(&block2, &block_contents2, None)
            .unwrap();

        assert_eq!(3, ledger_db.num_blocks().unwrap());

        // The previous blocks should still be in the ledger.
        assert_eq!(origin_block, ledger_db.get_block(0).unwrap());
        assert_eq!(block1, ledger_db.get_block(1).unwrap());
        assert_eq!(block_contents1, ledger_db.get_block_contents(1).unwrap());
        assert_eq!(1, ledger_db.num_txos().unwrap());

        // The new block contents should be in the ledger.
        assert_eq!(block_contents2, ledger_db.get_block_contents(2).unwrap());

        // The active mint configs should be updated.
        assert_eq!(
            ledger_db.get_active_mint_configs(token_id1).unwrap(),
            vec![
                ActiveMintConfig {
                    mint_config: mint_config_tx2.prefix.configs[0].clone(),
                    total_minted: 0,
                },
                ActiveMintConfig {
                    mint_config: mint_config_tx2.prefix.configs[1].clone(),
                    total_minted: 0,
                }
            ]
        );

        assert_eq!(
            ledger_db.get_active_mint_configs(token_id2).unwrap(),
            vec![
                ActiveMintConfig {
                    mint_config: mint_config_tx3.prefix.configs[0].clone(),
                    total_minted: 0,
                },
                ActiveMintConfig {
                    mint_config: mint_config_tx3.prefix.configs[1].clone(),
                    total_minted: 0,
                }
            ]
        );
    }

    #[test]
    #[should_panic(expected = "called `Result::unwrap()` on an `Err` value: DuplicateMintConfigTx")]
    // Appending a block that contains a previously-seen MintConfigTx should
    // fail.
    fn test_append_block_fails_for_duplicate_mint_config_txs() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let mut ledger_db = create_db();
        let token_id1 = TokenId::from(1);

        // === Create and append the origin block. ===
        // The origin block contains a single output belonging to the
        // `origin_account_key`.

        let origin_account_key = AccountKey::random(&mut rng);
        let (origin_block, origin_block_contents) =
            get_origin_block_and_contents(&origin_account_key);

        ledger_db
            .append_block(&origin_block, &origin_block_contents, None)
            .unwrap();

        // === Append a block with only a single MintConfigTx. ===
        let mint_config_tx1 = generate_test_mint_config_tx(token_id1, &mut rng);

        let block_contents1 = BlockContents {
            mint_config_txs: vec![mint_config_tx1.clone()],
            ..Default::default()
        };

        let block1 = Block::new_with_parent(
            BLOCK_VERSION,
            &origin_block,
            &Default::default(),
            &block_contents1,
        );

        ledger_db
            .append_block(&block1, &block_contents1, None)
            .unwrap();

        // Try appending a block that contains the same set mint config tx.
        let mint_config_tx2 = generate_test_mint_config_tx(token_id1, &mut rng);

        let block_contents2 = BlockContents {
            mint_config_txs: vec![mint_config_tx2.clone(), mint_config_tx1.clone()],
            ..Default::default()
        };

        let block2 = Block::new_with_parent(
            BLOCK_VERSION,
            &block1,
            &Default::default(),
            &block_contents2,
        );

        // This should fail.
        ledger_db
            .append_block(&block2, &block_contents2, None)
            .unwrap();
    }

    #[test]
    // Appending a block with MintTxs and outputs should correctly update each LMDB
    // database.
    fn append_block_with_mint_txs_and_outputs() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let mut ledger_db = create_db();
        let token_id1 = TokenId::from(1);

        // === Create and append the origin block. ===
        // The origin block contains a single output belonging to the
        // `origin_account_key`.

        let origin_account_key = AccountKey::random(&mut rng);
        let (origin_block, origin_block_contents) =
            get_origin_block_and_contents(&origin_account_key);

        ledger_db
            .append_block(&origin_block, &origin_block_contents, None)
            .unwrap();

        let origin_tx_out = origin_block_contents.outputs.get(0).unwrap().clone();
        assert_eq!(origin_tx_out, ledger_db.get_tx_out_by_index(0).unwrap());

        assert_eq!(
            ledger_db.get_active_mint_configs(token_id1).unwrap(),
            vec![]
        );

        // === Append a block wth a MintConfigTx transaction. This is needed since
        // the MintTx must be matched with an active mint config.
        let (mint_config_tx1, signers1) =
            generate_test_mint_config_tx_and_signers(token_id1, &mut rng);

        let block_contents1 = BlockContents {
            mint_config_txs: vec![mint_config_tx1.clone()],
            ..Default::default()
        };

        let block1 = Block::new_with_parent(
            BLOCK_VERSION,
            &origin_block,
            &Default::default(),
            &block_contents1,
        );

        ledger_db
            .append_block(&block1, &block_contents1, None)
            .unwrap();

        // === Append a block with only a single MintTx. ===
        let mint_tx1 = generate_test_mint_tx(token_id1, &signers1, 10, &mut rng);

        let block_contents2 = BlockContents {
            mint_txs: vec![mint_tx1.clone()],
            outputs: vec![get_test_tx_out(&mut rng)],
            ..Default::default()
        };

        let block2 = Block::new_with_parent(
            BLOCK_VERSION,
            &block1,
            &Default::default(),
            &block_contents2,
        );

        ledger_db
            .append_block(&block2, &block_contents2, None)
            .unwrap();

        assert_eq!(3, ledger_db.num_blocks().unwrap());
        assert_eq!(2, ledger_db.num_txos().unwrap());
        // The origin block should still be in the ledger:
        assert_eq!(origin_block, ledger_db.get_block(0).unwrap());
        // The new block should be in the ledger:
        assert_eq!(block2, ledger_db.get_block(2).unwrap());

        // The origin's TxOut should still be in the ledger:
        assert_eq!(origin_tx_out, ledger_db.get_tx_out_by_index(0).unwrap());

        // The new block contents should be in the ledger.
        assert_eq!(block_contents2, ledger_db.get_block_contents(2).unwrap());

        // The active mint configs should be updated.
        assert_eq!(
            ledger_db.get_active_mint_configs(token_id1).unwrap(),
            vec![
                ActiveMintConfig {
                    mint_config: mint_config_tx1.prefix.configs[0].clone(),
                    total_minted: mint_tx1.prefix.amount,
                },
                ActiveMintConfig {
                    mint_config: mint_config_tx1.prefix.configs[1].clone(),
                    total_minted: 0,
                }
            ]
        );

        // === Append another block with a MintTx, this one targetting the
        // second mint configuration.
        let mint_tx2 = generate_test_mint_tx(
            token_id1,
            &[
                Ed25519Pair::from(signers1[1].private_key()),
                Ed25519Pair::from(signers1[2].private_key()),
            ],
            20,
            &mut rng,
        );

        let block_contents3 = BlockContents {
            mint_txs: vec![mint_tx2.clone()],
            outputs: vec![get_test_tx_out(&mut rng)],
            ..Default::default()
        };

        let block3 = Block::new_with_parent(
            BLOCK_VERSION,
            &block2,
            &Default::default(),
            &block_contents3,
        );

        ledger_db
            .append_block(&block3, &block_contents3, None)
            .unwrap();

        assert_eq!(4, ledger_db.num_blocks().unwrap());
        assert_eq!(3, ledger_db.num_txos().unwrap());
        // The origin block should still be in the ledger:
        assert_eq!(origin_block, ledger_db.get_block(0).unwrap());
        // Previous blocks should still be in the ledger:
        assert_eq!(block1, ledger_db.get_block(1).unwrap());
        assert_eq!(block2, ledger_db.get_block(2).unwrap());

        assert_eq!(block_contents1, ledger_db.get_block_contents(1).unwrap());
        assert_eq!(block_contents2, ledger_db.get_block_contents(2).unwrap());
        // The new block should be in the ledger:
        assert_eq!(block3, ledger_db.get_block(3).unwrap());
        assert_eq!(block_contents3, ledger_db.get_block_contents(3).unwrap());

        // The active mint configs should be updated.
        assert_eq!(
            ledger_db.get_active_mint_configs(token_id1).unwrap(),
            vec![
                ActiveMintConfig {
                    mint_config: mint_config_tx1.prefix.configs[0].clone(),
                    total_minted: mint_tx1.prefix.amount,
                },
                ActiveMintConfig {
                    mint_config: mint_config_tx1.prefix.configs[1].clone(),
                    total_minted: mint_tx2.prefix.amount,
                }
            ]
        );

        // === Append a third block with a MintTx, tragetting the first active
        // mint config which should result in the total minted amount
        // increasing.
        let mint_tx3 = generate_test_mint_tx(
            token_id1,
            &[Ed25519Pair::from(signers1[0].private_key())],
            30,
            &mut rng,
        );

        let block_contents4 = BlockContents {
            mint_txs: vec![mint_tx3.clone()],
            outputs: vec![get_test_tx_out(&mut rng)],
            ..Default::default()
        };

        let block4 = Block::new_with_parent(
            BLOCK_VERSION,
            &block3,
            &Default::default(),
            &block_contents4,
        );

        ledger_db
            .append_block(&block4, &block_contents4, None)
            .unwrap();

        assert_eq!(5, ledger_db.num_blocks().unwrap());
        assert_eq!(4, ledger_db.num_txos().unwrap());
        // The origin block should still be in the ledger:
        assert_eq!(origin_block, ledger_db.get_block(0).unwrap());
        // Previous blocks should still be in the ledger:
        assert_eq!(block1, ledger_db.get_block(1).unwrap());
        assert_eq!(block2, ledger_db.get_block(2).unwrap());
        assert_eq!(block3, ledger_db.get_block(3).unwrap());

        assert_eq!(block_contents1, ledger_db.get_block_contents(1).unwrap());
        assert_eq!(block_contents2, ledger_db.get_block_contents(2).unwrap());
        assert_eq!(block_contents3, ledger_db.get_block_contents(3).unwrap());
        // The new block should be in the ledger:
        assert_eq!(block4, ledger_db.get_block(4).unwrap());
        assert_eq!(block_contents4, ledger_db.get_block_contents(4).unwrap());

        // The active mint configs should be updated.
        assert_eq!(
            ledger_db.get_active_mint_configs(token_id1).unwrap(),
            vec![
                ActiveMintConfig {
                    mint_config: mint_config_tx1.prefix.configs[0].clone(),
                    total_minted: mint_tx1.prefix.amount + mint_tx3.prefix.amount,
                },
                ActiveMintConfig {
                    mint_config: mint_config_tx1.prefix.configs[1].clone(),
                    total_minted: mint_tx2.prefix.amount,
                }
            ]
        );

        // === Append a fourth block with two MintTxs, tragetting the first active
        // mint config which should result in the total minted amount
        // increasing.
        let mint_tx4 = generate_test_mint_tx(
            token_id1,
            &[Ed25519Pair::from(signers1[0].private_key())],
            100,
            &mut rng,
        );

        let mint_tx5 = generate_test_mint_tx(
            token_id1,
            &[Ed25519Pair::from(signers1[0].private_key())],
            200,
            &mut rng,
        );

        let block_contents5 = BlockContents {
            mint_txs: vec![mint_tx4.clone(), mint_tx5.clone()],
            outputs: vec![get_test_tx_out(&mut rng), get_test_tx_out(&mut rng)],
            ..Default::default()
        };

        let block5 = Block::new_with_parent(
            BLOCK_VERSION,
            &block4,
            &Default::default(),
            &block_contents5,
        );

        ledger_db
            .append_block(&block5, &block_contents5, None)
            .unwrap();

        assert_eq!(6, ledger_db.num_blocks().unwrap());
        assert_eq!(6, ledger_db.num_txos().unwrap());
        // The origin block should still be in the ledger:
        assert_eq!(origin_block, ledger_db.get_block(0).unwrap());
        // Previous blocks should still be in the ledger:
        assert_eq!(block1, ledger_db.get_block(1).unwrap());
        assert_eq!(block2, ledger_db.get_block(2).unwrap());
        assert_eq!(block3, ledger_db.get_block(3).unwrap());
        assert_eq!(block4, ledger_db.get_block(4).unwrap());

        assert_eq!(block_contents1, ledger_db.get_block_contents(1).unwrap());
        assert_eq!(block_contents2, ledger_db.get_block_contents(2).unwrap());
        assert_eq!(block_contents3, ledger_db.get_block_contents(3).unwrap());
        assert_eq!(block_contents4, ledger_db.get_block_contents(4).unwrap());
        // The new block should be in the ledger:
        assert_eq!(block5, ledger_db.get_block(5).unwrap());
        assert_eq!(block_contents5, ledger_db.get_block_contents(5).unwrap());

        // The active mint configs should be updated.
        assert_eq!(
            ledger_db.get_active_mint_configs(token_id1).unwrap(),
            vec![
                ActiveMintConfig {
                    mint_config: mint_config_tx1.prefix.configs[0].clone(),
                    total_minted: mint_tx1.prefix.amount
                        + mint_tx3.prefix.amount
                        + mint_tx4.prefix.amount
                        + mint_tx5.prefix.amount,
                },
                ActiveMintConfig {
                    mint_config: mint_config_tx1.prefix.configs[1].clone(),
                    total_minted: mint_tx2.prefix.amount,
                }
            ]
        );

        // === Append a fifth with two MintTxs, tragetting both mint configs which
        // should result in the total minted amount increasing.
        let mint_tx6 = generate_test_mint_tx(
            token_id1,
            &[Ed25519Pair::from(signers1[0].private_key())],
            101,
            &mut rng,
        );

        let mint_tx7 = generate_test_mint_tx(
            token_id1,
            &[Ed25519Pair::from(signers1[1].private_key())],
            201,
            &mut rng,
        );

        let block_contents6 = BlockContents {
            mint_txs: vec![mint_tx6.clone(), mint_tx7.clone()],
            outputs: vec![get_test_tx_out(&mut rng), get_test_tx_out(&mut rng)],
            ..Default::default()
        };

        let block6 = Block::new_with_parent(
            BLOCK_VERSION,
            &block5,
            &Default::default(),
            &block_contents6,
        );

        ledger_db
            .append_block(&block6, &block_contents6, None)
            .unwrap();

        assert_eq!(7, ledger_db.num_blocks().unwrap());
        assert_eq!(8, ledger_db.num_txos().unwrap());
        // The origin block should still be in the ledger:
        assert_eq!(origin_block, ledger_db.get_block(0).unwrap());
        // Previous blocks should still be in the ledger:
        assert_eq!(block1, ledger_db.get_block(1).unwrap());
        assert_eq!(block2, ledger_db.get_block(2).unwrap());
        assert_eq!(block3, ledger_db.get_block(3).unwrap());
        assert_eq!(block4, ledger_db.get_block(4).unwrap());
        assert_eq!(block5, ledger_db.get_block(5).unwrap());

        assert_eq!(block_contents1, ledger_db.get_block_contents(1).unwrap());
        assert_eq!(block_contents2, ledger_db.get_block_contents(2).unwrap());
        assert_eq!(block_contents3, ledger_db.get_block_contents(3).unwrap());
        assert_eq!(block_contents4, ledger_db.get_block_contents(4).unwrap());
        assert_eq!(block_contents5, ledger_db.get_block_contents(5).unwrap());
        // The new block should be in the ledger:
        assert_eq!(block6, ledger_db.get_block(6).unwrap());
        assert_eq!(block_contents6, ledger_db.get_block_contents(6).unwrap());

        // The active mint configs should be updated.
        assert_eq!(
            ledger_db.get_active_mint_configs(token_id1).unwrap(),
            vec![
                ActiveMintConfig {
                    mint_config: mint_config_tx1.prefix.configs[0].clone(),
                    total_minted: mint_tx1.prefix.amount
                        + mint_tx3.prefix.amount
                        + mint_tx4.prefix.amount
                        + mint_tx5.prefix.amount
                        + mint_tx6.prefix.amount,
                },
                ActiveMintConfig {
                    mint_config: mint_config_tx1.prefix.configs[1].clone(),
                    total_minted: mint_tx2.prefix.amount + mint_tx7.prefix.amount,
                }
            ]
        );
    }

    #[test]
    // Appending a block that contains a mix of outputs, key images and mint
    // transactions should work as expected.
    fn test_append_block_containing_outputs_key_images_and_mint_txs() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let mut ledger_db = create_db();
        let token_id1 = TokenId::from(1);
        let token_id2 = TokenId::from(2);

        // === Create and append the origin block. ===
        // The origin block contains a single output belonging to the
        // `origin_account_key`.

        let origin_account_key = AccountKey::random(&mut rng);
        let (origin_block, origin_block_contents) =
            get_origin_block_and_contents(&origin_account_key);

        ledger_db
            .append_block(&origin_block, &origin_block_contents, None)
            .unwrap();

        // === Create and append a non-origin block. ===
        let recipient_account_key = AccountKey::random(&mut rng);
        let outputs1: Vec<TxOut> = (0..4)
            .map(|_i| {
                TxOut::new(
                    1000,
                    &recipient_account_key.default_subaddress(),
                    &RistrettoPrivate::from_random(&mut rng),
                    Default::default(),
                )
                .unwrap()
            })
            .collect();

        let key_images1: Vec<KeyImage> = (0..5).map(|_i| KeyImage::from(rng.next_u64())).collect();
        let mint_config_tx1 = generate_test_mint_config_tx(token_id1, &mut rng);
        let (mint_config_tx2, signers2) =
            generate_test_mint_config_tx_and_signers(token_id2, &mut rng);

        let block_contents1 = BlockContents {
            key_images: key_images1,
            outputs: outputs1,
            mint_config_txs: vec![mint_config_tx1.clone(), mint_config_tx2.clone()],
            mint_txs: vec![], /* For this block we cant include any mint txs since we need an
                               * active configuration first. */
        };
        let block1 = Block::new_with_parent(
            BLOCK_VERSION,
            &origin_block,
            &Default::default(),
            &block_contents1,
        );

        ledger_db
            .append_block(&block1, &block_contents1, None)
            .unwrap();

        assert_eq!(2, ledger_db.num_blocks().unwrap());
        // The origin block should still be in the ledger:
        assert_eq!(origin_block, ledger_db.get_block(0).unwrap());
        // The new block should be in the ledger:
        assert_eq!(block1, ledger_db.get_block(1).unwrap());
        // The new block contents should be in the ledger:
        assert_eq!(block_contents1, ledger_db.get_block_contents(1).unwrap());

        // The active mint configs should be updated.
        assert_eq!(
            ledger_db.get_active_mint_configs(token_id1).unwrap(),
            vec![
                ActiveMintConfig {
                    mint_config: mint_config_tx1.prefix.configs[0].clone(),
                    total_minted: 0,
                },
                ActiveMintConfig {
                    mint_config: mint_config_tx1.prefix.configs[1].clone(),
                    total_minted: 0,
                }
            ]
        );

        assert_eq!(
            ledger_db.get_active_mint_configs(token_id2).unwrap(),
            vec![
                ActiveMintConfig {
                    mint_config: mint_config_tx2.prefix.configs[0].clone(),
                    total_minted: 0,
                },
                ActiveMintConfig {
                    mint_config: mint_config_tx2.prefix.configs[1].clone(),
                    total_minted: 0,
                }
            ]
        );

        // Each TxOut from the current block should be in the ledger.
        assert_eq!(5, ledger_db.num_txos().unwrap());

        for (i, tx_out) in block_contents1.outputs.iter().enumerate() {
            // The first tx_out is the origin block, tx_outs are for the following block
            // hence the + 1
            assert_eq!(
                ledger_db.get_tx_out_by_index((i + 1) as u64).unwrap(),
                *tx_out
            );

            // All tx outs are in the second block.
            let block_index = ledger_db
                .get_block_index_by_tx_out_index((i + 1) as u64)
                .unwrap();
            assert_eq!(block_index, 1);
        }

        // The key images should be in the ledger.
        assert!(ledger_db
            .contains_key_image(block_contents1.key_images.get(0).unwrap())
            .unwrap());

        let block1_key_images = ledger_db.get_key_images_by_block(1).unwrap();
        assert_eq!(block_contents1.key_images, block1_key_images);

        //  === Write another block - this one has a MintTx in addition to all
        // the other txs.
        let outputs2: Vec<TxOut> = (0..4)
            .map(|_i| {
                TxOut::new(
                    1000,
                    &recipient_account_key.default_subaddress(),
                    &RistrettoPrivate::from_random(&mut rng),
                    Default::default(),
                )
                .unwrap()
            })
            .collect();

        let key_images2: Vec<KeyImage> = (0..5).map(|_i| KeyImage::from(rng.next_u64())).collect();
        let mint_config_tx3 = generate_test_mint_config_tx(token_id1, &mut rng);
        let mint_tx1 = generate_test_mint_tx(token_id2, &signers2, 10, &mut rng);
        let mint_tx2 = generate_test_mint_tx(token_id2, &signers2, 20, &mut rng);

        let block_contents2 = BlockContents {
            key_images: key_images2,
            outputs: outputs2,
            mint_config_txs: vec![mint_config_tx3.clone()],
            mint_txs: vec![mint_tx1.clone(), mint_tx2.clone()],
        };
        let block2 = Block::new_with_parent(
            BLOCK_VERSION,
            &block1,
            &Default::default(),
            &block_contents2,
        );

        ledger_db
            .append_block(&block2, &block_contents2, None)
            .unwrap();

        assert_eq!(3, ledger_db.num_blocks().unwrap());
        // The previous blocks should still be in the ledger:
        assert_eq!(origin_block, ledger_db.get_block(0).unwrap());
        assert_eq!(
            origin_block_contents,
            ledger_db.get_block_contents(0).unwrap()
        );
        assert_eq!(block1, ledger_db.get_block(1).unwrap());
        assert_eq!(block_contents1, ledger_db.get_block_contents(1).unwrap());
        // The new block should be in the ledger:
        assert_eq!(block2, ledger_db.get_block(2).unwrap());
        assert_eq!(block_contents2, ledger_db.get_block_contents(2).unwrap());

        // The active mint configs should be updated.
        assert_eq!(
            ledger_db.get_active_mint_configs(token_id1).unwrap(),
            vec![
                ActiveMintConfig {
                    mint_config: mint_config_tx3.prefix.configs[0].clone(),
                    total_minted: 0,
                },
                ActiveMintConfig {
                    mint_config: mint_config_tx3.prefix.configs[1].clone(),
                    total_minted: 0,
                }
            ]
        );

        assert_eq!(
            ledger_db.get_active_mint_configs(token_id2).unwrap(),
            vec![
                ActiveMintConfig {
                    mint_config: mint_config_tx2.prefix.configs[0].clone(),
                    total_minted: 30,
                },
                ActiveMintConfig {
                    mint_config: mint_config_tx2.prefix.configs[1].clone(),
                    total_minted: 0,
                }
            ]
        );

        // Each TxOut from the current block should be in the ledger.
        assert_eq!(9, ledger_db.num_txos().unwrap());

        for (i, tx_out) in block_contents2.outputs.iter().enumerate() {
            assert_eq!(
                ledger_db.get_tx_out_by_index((i + 5) as u64).unwrap(),
                *tx_out
            );

            // All tx outs are in the second block.
            let block_index = ledger_db
                .get_block_index_by_tx_out_index((i + 5) as u64)
                .unwrap();
            assert_eq!(block_index, 2);
        }

        // The key images should be in the ledger.
        assert!(ledger_db
            .contains_key_image(block_contents2.key_images.get(0).unwrap())
            .unwrap());

        let block2_key_images = ledger_db.get_key_images_by_block(2).unwrap();
        assert_eq!(block_contents2.key_images, block2_key_images);
    }

    #[test]
    #[should_panic(expected = "called `Result::unwrap()` on an `Err` value: TooFewOutputs")]
    // Appending a block that contains more MintTxs than outputs should
    // fail.
    fn test_append_block_fails_if_not_enough_outputs() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let mut ledger_db = create_db();
        let token_id1 = TokenId::from(1);

        // === Create and append the origin block. ===
        // The origin block contains a single output belonging to the
        // `origin_account_key`.

        let origin_account_key = AccountKey::random(&mut rng);
        let (origin_block, origin_block_contents) =
            get_origin_block_and_contents(&origin_account_key);

        ledger_db
            .append_block(&origin_block, &origin_block_contents, None)
            .unwrap();

        // === Append a block wth a MintConfigTx transaction. This is needed since
        // the MintTx must be matched with an active mint config.
        let (mint_config_tx1, signers1) =
            generate_test_mint_config_tx_and_signers(token_id1, &mut rng);

        let block_contents1 = BlockContents {
            mint_config_txs: vec![mint_config_tx1.clone()],
            ..Default::default()
        };

        let block1 = Block::new_with_parent(
            BLOCK_VERSION,
            &origin_block,
            &Default::default(),
            &block_contents1,
        );

        ledger_db
            .append_block(&block1, &block_contents1, None)
            .unwrap();

        // === Append a block with two MintTxs but only a single TxOut. ===
        let mint_tx1 = generate_test_mint_tx(token_id1, &signers1, 10, &mut rng);
        let mint_tx2 = generate_test_mint_tx(token_id1, &signers1, 10, &mut rng);

        let block_contents2 = BlockContents {
            mint_txs: vec![mint_tx1, mint_tx2],
            outputs: vec![get_test_tx_out(&mut rng)],
            ..Default::default()
        };

        let block2 = Block::new_with_parent(
            BLOCK_VERSION,
            &block1,
            &Default::default(),
            &block_contents2,
        );

        // This should fail.
        ledger_db
            .append_block(&block2, &block_contents2, None)
            .unwrap();
    }

    #[test]
    #[should_panic(expected = "called `Result::unwrap()` on an `Err` value: DuplicateMintTx")]
    // Appending a block that contains a previously-seen MintTx should
    // fail.
    fn test_append_block_fails_for_duplicate_mint_txs() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let mut ledger_db = create_db();
        let token_id1 = TokenId::from(1);

        // === Create and append the origin block. ===
        // The origin block contains a single output belonging to the
        // `origin_account_key`.

        let origin_account_key = AccountKey::random(&mut rng);
        let (origin_block, origin_block_contents) =
            get_origin_block_and_contents(&origin_account_key);

        ledger_db
            .append_block(&origin_block, &origin_block_contents, None)
            .unwrap();

        // === Append a block wth a MintConfigTx transaction. This is needed since
        // the MintTx must be matched with an active mint config.
        let (mint_config_tx1, signers1) =
            generate_test_mint_config_tx_and_signers(token_id1, &mut rng);

        let block_contents1 = BlockContents {
            mint_config_txs: vec![mint_config_tx1.clone()],
            ..Default::default()
        };

        let block1 = Block::new_with_parent(
            BLOCK_VERSION,
            &origin_block,
            &Default::default(),
            &block_contents1,
        );

        ledger_db
            .append_block(&block1, &block_contents1, None)
            .unwrap();

        // === Append a block with only a single MintTx. ===
        let mint_tx1 = generate_test_mint_tx(token_id1, &signers1, 10, &mut rng);

        let block_contents2 = BlockContents {
            mint_txs: vec![mint_tx1.clone()],
            outputs: vec![get_test_tx_out(&mut rng)],
            ..Default::default()
        };

        let block2 = Block::new_with_parent(
            BLOCK_VERSION,
            &block1,
            &Default::default(),
            &block_contents2,
        );

        ledger_db
            .append_block(&block2, &block_contents2, None)
            .unwrap();

        // === Append another block that includes the previous MintTx.
        let mint_tx2 = generate_test_mint_tx(
            token_id1,
            &[
                Ed25519Pair::from(signers1[1].private_key()),
                Ed25519Pair::from(signers1[2].private_key()),
            ],
            20,
            &mut rng,
        );

        let block_contents3 = BlockContents {
            mint_txs: vec![mint_tx2.clone(), mint_tx1.clone()],
            outputs: vec![get_test_tx_out(&mut rng), get_test_tx_out(&mut rng)],
            ..Default::default()
        };

        let block3 = Block::new_with_parent(
            BLOCK_VERSION,
            &block2,
            &Default::default(),
            &block_contents3,
        );

        // This is expected to fail.
        ledger_db
            .append_block(&block3, &block_contents3, None)
            .unwrap();
    }

    #[test]
    #[should_panic(expected = "called `Result::unwrap()` on an `Err` value: NotFound")]
    // Appending a block that contains a MintTx that does not reference any active
    // configuration should fail.
    fn test_append_block_fails_for_mint_tx_not_signed_by_active_configuration() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let mut ledger_db = create_db();
        let token_id1 = TokenId::from(1);

        // === Create and append the origin block. ===
        // The origin block contains a single output belonging to the
        // `origin_account_key`.

        let origin_account_key = AccountKey::random(&mut rng);
        let (origin_block, origin_block_contents) =
            get_origin_block_and_contents(&origin_account_key);

        ledger_db
            .append_block(&origin_block, &origin_block_contents, None)
            .unwrap();

        // === Append a block wth a MintConfigTx transaction. This is needed since
        // the MintTx must be matched with an active mint config.
        let (mint_config_tx1, _signers1) =
            generate_test_mint_config_tx_and_signers(token_id1, &mut rng);

        let block_contents1 = BlockContents {
            mint_config_txs: vec![mint_config_tx1.clone()],
            ..Default::default()
        };

        let block1 = Block::new_with_parent(
            BLOCK_VERSION,
            &origin_block,
            &Default::default(),
            &block_contents1,
        );

        ledger_db
            .append_block(&block1, &block_contents1, None)
            .unwrap();

        // === Append a block with only a single MintTx signed by an unknown signer. ===
        let mint_tx1 = generate_test_mint_tx(
            token_id1,
            &[Ed25519Pair::from_random(&mut rng)],
            10,
            &mut rng,
        );

        let block_contents2 = BlockContents {
            mint_txs: vec![mint_tx1.clone()],
            outputs: vec![get_test_tx_out(&mut rng)],
            ..Default::default()
        };

        let block2 = Block::new_with_parent(
            BLOCK_VERSION,
            &block1,
            &Default::default(),
            &block_contents2,
        );

        // This should fail.
        ledger_db
            .append_block(&block2, &block_contents2, None)
            .unwrap();
    }

    #[test]
    // Appending a block with a MintTx that exceeds the minting limit should fail.
    fn append_block_with_mint_tx_exceeding_mint_limit_should_fail() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let mut ledger_db = create_db();
        let token_id1 = TokenId::from(1);

        // === Create and append the origin block. ===
        // The origin block contains a single output belonging to the
        // `origin_account_key`.

        let origin_account_key = AccountKey::random(&mut rng);
        let (origin_block, origin_block_contents) =
            get_origin_block_and_contents(&origin_account_key);

        ledger_db
            .append_block(&origin_block, &origin_block_contents, None)
            .unwrap();

        let origin_tx_out = origin_block_contents.outputs.get(0).unwrap().clone();
        assert_eq!(origin_tx_out, ledger_db.get_tx_out_by_index(0).unwrap());

        assert_eq!(
            ledger_db.get_active_mint_configs(token_id1).unwrap(),
            vec![]
        );

        // === Append a block wth a MintConfigTx transaction. This is needed since
        // the MintTx must be matched with an active mint config.
        let (mint_config_tx1, signers1) =
            generate_test_mint_config_tx_and_signers(token_id1, &mut rng);

        let block_contents1 = BlockContents {
            mint_config_txs: vec![mint_config_tx1.clone()],
            ..Default::default()
        };

        let block1 = Block::new_with_parent(
            BLOCK_VERSION,
            &origin_block,
            &Default::default(),
            &block_contents1,
        );

        ledger_db
            .append_block(&block1, &block_contents1, None)
            .unwrap();

        // === Append a block with only a single MintTx. ===
        let mint_tx1 = generate_test_mint_tx(
            token_id1,
            &signers1,
            mint_config_tx1.prefix.configs[0].mint_limit - 10,
            &mut rng,
        );

        let block_contents2 = BlockContents {
            mint_txs: vec![mint_tx1.clone()],
            outputs: vec![get_test_tx_out(&mut rng)],
            ..Default::default()
        };

        let block2 = Block::new_with_parent(
            BLOCK_VERSION,
            &block1,
            &Default::default(),
            &block_contents2,
        );

        ledger_db
            .append_block(&block2, &block_contents2, None)
            .unwrap();

        // === Append another block with a MintTx that will exceed the mint limit, we
        // should fail.
        let mint_tx2 = generate_test_mint_tx(
            token_id1,
            &[Ed25519Pair::from(signers1[0].private_key())], // Explicitly target the first config
            11,
            &mut rng,
        );

        let block_contents3 = BlockContents {
            mint_txs: vec![mint_tx2.clone()],
            outputs: vec![get_test_tx_out(&mut rng)],
            ..Default::default()
        };

        let block3 = Block::new_with_parent(
            BLOCK_VERSION,
            &block2,
            &Default::default(),
            &block_contents3,
        );

        assert_eq!(
            ledger_db.append_block(&block3, &block_contents3, None),
            Err(Error::MintLimitExceeded(
                mint_config_tx1.prefix.configs[0].mint_limit + 1,
                mint_config_tx1.prefix.configs[0].mint_limit
            ))
        );

        // Amount minted should not update.
        assert_eq!(
            ledger_db.get_active_mint_configs(token_id1).unwrap(),
            vec![
                ActiveMintConfig {
                    mint_config: mint_config_tx1.prefix.configs[0].clone(),
                    total_minted: mint_tx1.prefix.amount,
                },
                ActiveMintConfig {
                    mint_config: mint_config_tx1.prefix.configs[1].clone(),
                    total_minted: 0,
                }
            ]
        );

        // === Sanity: Allow the second mint configuration to match, which
        // should allow minting to succeeed.
        let mint_tx3 = generate_test_mint_tx(token_id1, &signers1, 11, &mut rng);

        let block_contents3 = BlockContents {
            mint_txs: vec![mint_tx3.clone()],
            outputs: vec![get_test_tx_out(&mut rng)],
            ..Default::default()
        };

        let block3 = Block::new_with_parent(
            BLOCK_VERSION,
            &block2,
            &Default::default(),
            &block_contents3,
        );

        ledger_db
            .append_block(&block3, &block_contents3, None)
            .unwrap();

        // Amount minted should not update.
        assert_eq!(
            ledger_db.get_active_mint_configs(token_id1).unwrap(),
            vec![
                ActiveMintConfig {
                    mint_config: mint_config_tx1.prefix.configs[0].clone(),
                    total_minted: mint_tx1.prefix.amount,
                },
                ActiveMintConfig {
                    mint_config: mint_config_tx1.prefix.configs[1].clone(),
                    total_minted: 11,
                }
            ]
        );
    }

    #[test]
    #[should_panic(expected = "called `Result::unwrap()` on an `Err` value: NoOutputs")]
    // Appending an empty block should fail.
    fn test_append_block_fails_when_block_is_empty() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let mut ledger_db = create_db();

        // === Create and append the origin block. ===
        // The origin block contains a single output belonging to the
        // `origin_account_key`.

        let origin_account_key = AccountKey::random(&mut rng);
        let (origin_block, origin_block_contents) =
            get_origin_block_and_contents(&origin_account_key);

        ledger_db
            .append_block(&origin_block, &origin_block_contents, None)
            .unwrap();

        // === Append a block with no contents. ===

        let block_contents1 = Default::default();

        let block1 = Block::new_with_parent(
            BLOCK_VERSION,
            &origin_block,
            &Default::default(),
            &block_contents1,
        );

        ledger_db
            .append_block(&block1, &block_contents1, None)
            .unwrap();
    }

    #[test]
    #[should_panic(expected = "called `Result::unwrap()` on an `Err` value: NoKeyImages")]
    // Appending a non-origin block should fail if the block contains no key images
    // and no minting transactions.
    fn test_append_block_fails_for_non_origin_non_minting_blocks_without_key_images() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let mut ledger_db = create_db();

        // === Create and append the origin block. ===
        // The origin block contains a single output belonging to the
        // `origin_account_key`.

        let origin_account_key = AccountKey::random(&mut rng);
        let (origin_block, origin_block_contents) =
            get_origin_block_and_contents(&origin_account_key);

        ledger_db
            .append_block(&origin_block, &origin_block_contents, None)
            .unwrap();

        // === Attempt to append a block without key images ===
        let recipient_account_key = AccountKey::random(&mut rng);
        let outputs: Vec<TxOut> = (0..4)
            .map(|_i| {
                TxOut::new(
                    1000,
                    Mob::ID,
                    &recipient_account_key.default_subaddress(),
                    &RistrettoPrivate::from_random(&mut rng),
                    Default::default(),
                )
                .unwrap()
            })
            .collect();

        let block_contents = BlockContents {
            outputs,
            ..Default::default()
        };
        let block = Block::new_with_parent(
            BLOCK_VERSION,
            &origin_block,
            &Default::default(),
            &block_contents,
        );

        // This is expected to fail.
        ledger_db
            .append_block(&block, &block_contents, None)
            .unwrap();
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
        let (expected_blocks, _) = populate_db(&mut ledger_db, n_blocks, 1);

        for block_index in 0..n_blocks {
            let block = ledger_db
                .get_block(block_index as u64)
                .unwrap_or_else(|_| panic!("Could not get block {:?}", block_index));

            let expected_block: Block = expected_blocks.get(block_index as usize).unwrap().clone();
            assert_eq!(block, expected_block);
        }
    }

    #[test]
    // Getting block contents by index should return the correct block contents, if
    // that exists.
    fn test_get_block_contents_by_index() {
        let mut ledger_db = create_db();
        let n_blocks = 43;
        let (_, expected_block_contents) = populate_db(&mut ledger_db, n_blocks, 1);

        for block_index in 0..n_blocks {
            let block_contents = ledger_db
                .get_block_contents(block_index as u64)
                .unwrap_or_else(|_| panic!("Could not get block contents {:?}", block_index));

            let expected_block_contents = expected_block_contents
                .get(block_index as usize)
                .unwrap()
                .clone();
            assert_eq!(block_contents, expected_block_contents);
        }
    }

    #[test]
    // Getting a block by its index should return an error if the block doesn't
    // exist.
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
    // Getting a block number by tx out index should return the correct block
    // number, if it exists.
    fn test_get_block_index_by_tx_out_index() {
        let mut ledger_db = create_db();
        let n_blocks = 43;
        let (_expected_blocks, expected_block_contents) = populate_db(&mut ledger_db, n_blocks, 1);

        for (block_index, block_contents) in expected_block_contents.iter().enumerate() {
            for tx_out in block_contents.outputs.iter() {
                let tx_out_index = ledger_db
                    .get_tx_out_index_by_public_key(&tx_out.public_key)
                    .expect("Failed getting tx out index");

                let block_index_by_tx_out = ledger_db
                    .get_block_index_by_tx_out_index(tx_out_index)
                    .expect("Failed getting block index by tx out index");
                assert_eq!(block_index as u64, block_index_by_tx_out);
            }
        }
    }

    #[test]
    // Getting a block index by a tx out index return an error if the tx out index
    // doesn't exist.
    fn test_get_block_index_by_tx_out_index_doesnt_exist() {
        let mut ledger_db = create_db();
        let n_blocks = 43;
        populate_db(&mut ledger_db, n_blocks, 1);

        let out_of_range = 999;

        match ledger_db.get_block_index_by_tx_out_index(out_of_range) {
            Ok(_block_index) => panic!("Should not return a block index."),
            Err(Error::NotFound) => {
                // This is expected.
            }
            Err(e) => panic!("Unexpected error {:?}", e),
        }
    }

    #[test]
    // `Ledger::contains_key_image` should find key images that exist.
    fn test_contains_key_image() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let mut ledger_db = create_db();

        // The origin block can't contain key images.
        let origin_account_key = AccountKey::random(&mut rng);
        let (origin_block, origin_block_contents) =
            get_origin_block_and_contents(&origin_account_key);
        ledger_db
            .append_block(&origin_block, &origin_block_contents, None)
            .unwrap();

        // Write the next block, containing several key images.
        let account_key = AccountKey::random(&mut rng);
        let num_key_images = 3;
        let key_images: Vec<KeyImage> = (0..num_key_images)
            .map(|_i| KeyImage::from(rng.next_u64()))
            .collect();

        let tx_out = TxOut::new(
            10,
            Mob::ID,
            &account_key.default_subaddress(),
            &RistrettoPrivate::from_random(&mut rng),
            Default::default(),
        )
        .unwrap();
        let outputs = vec![tx_out];

        let block_contents = BlockContents {
            key_images: key_images.clone(),
            outputs,
            ..Default::default()
        };
        let block = Block::new_with_parent(
            BlockVersion::ONE,
            &origin_block,
            &Default::default(),
            &block_contents,
        );

        ledger_db
            .append_block(&block, &block_contents, None)
            .unwrap();

        // The ledger should each key image.
        for key_image in &key_images {
            assert!(ledger_db.contains_key_image(&key_image).unwrap());
        }
    }

    #[test]
    // `get_key_images_by_block` should return the correct set of key images used in
    // a single block.
    fn test_get_key_images_by_block() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let mut ledger_db = create_db();

        // Populate the ledger with some initial blocks.
        let n_blocks = 3;
        populate_db(&mut ledger_db, n_blocks, 2);

        // Append a new block to the ledger.
        let account_key = AccountKey::random(&mut rng);
        let num_key_images = 3;
        let key_images: Vec<KeyImage> = (0..num_key_images)
            .map(|_i| KeyImage::from(rng.next_u64()))
            .collect();

        let tx_out = TxOut::new(
            10,
            Mob::ID,
            &account_key.default_subaddress(),
            &RistrettoPrivate::from_random(&mut rng),
            Default::default(),
        )
        .unwrap();
        let outputs = vec![tx_out];

        let block_contents = BlockContents {
            key_images: key_images.clone(),
            outputs,
            ..Default::default()
        };
        let parent = ledger_db.get_block(n_blocks - 1).unwrap();
        let block = Block::new_with_parent(
            BlockVersion::ONE,
            &parent,
            &Default::default(),
            &block_contents,
        );

        ledger_db
            .append_block(&block, &block_contents, None)
            .unwrap();

        let returned_key_images = ledger_db.get_key_images_by_block(block.index).unwrap();
        assert_eq!(key_images, returned_key_images);
    }

    #[test]
    /// Attempting to append an empty block should return Error::NoOutputs.
    fn test_append_empty_block() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let mut ledger_db = create_db();

        // The origin block can't contain key images.
        let origin_account_key = AccountKey::random(&mut rng);
        let (origin_block, origin_block_contents) =
            get_origin_block_and_contents(&origin_account_key);
        ledger_db
            .append_block(&origin_block, &origin_block_contents, None)
            .unwrap();

        // Write the next block, containing several key images but no outputs.
        let num_key_images = 3;
        let key_images: Vec<KeyImage> = (0..num_key_images)
            .map(|_i| KeyImage::from(rng.next_u64()))
            .collect();

        let block_contents = BlockContents {
            key_images,
            ..Default::default()
        };
        let block = Block::new_with_parent(
            BlockVersion::ONE,
            &origin_block,
            &Default::default(),
            &block_contents,
        );

        assert_eq!(
            ledger_db.append_block(&block, &block_contents, None),
            Err(Error::NoOutputs)
        );
    }

    #[test]
    /// Appending an block of incorrect version should return
    /// Error::InvalidBlockVersion.
    fn test_append_block_with_invalid_version() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let mut ledger_db = create_db();
        let account_key = AccountKey::random(&mut rng);

        let (mut block, block_contents) = get_origin_block_and_contents(&account_key);

        let wrong_version = 1337;
        block.version = wrong_version;
        // Recompute the block ID to reflect the modified version.
        block.id = compute_block_id(
            block.version,
            &block.parent_id,
            block.index,
            block.cumulative_txo_count,
            &block.root_element,
            &block.contents_hash,
        );

        assert_eq!(
            ledger_db.append_block(&block, &block_contents, None),
            Err(Error::InvalidBlockVersion(block.version))
        );
    }

    #[test]
    /// Appending blocks that have ever-increasing and continous version numbers
    /// should work as long as it is <= MAX_BLOCK_VERSION.
    /// Appending a block > MAX_BLOCK_VERSION should fail even if it is after a
    /// block with version == MAX_BLOCK_VERSION.
    /// Appending a block with a version < last block's version should fail.
    fn test_append_block_with_version_bumps() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let mut ledger_db = create_db();

        let origin_account_key = AccountKey::random(&mut rng);
        let (origin_block, origin_block_contents) =
            get_origin_block_and_contents(&origin_account_key);

        ledger_db
            .append_block(&origin_block, &origin_block_contents, None)
            .unwrap();

        let mut last_block = origin_block;

        // MAX_BLOCK_VERSION sets the current max block version
        for block_version in BlockVersion::iterator() {
            // In each iteration we add a few blocks with the same version.
            for _ in 0..3 {
                let recipient_account_key = AccountKey::random(&mut rng);
                let outputs: Vec<TxOut> = (0..4)
                    .map(|_i| {
                        TxOut::new(
                            1000,
                            Mob::ID,
                            &recipient_account_key.default_subaddress(),
                            &RistrettoPrivate::from_random(&mut rng),
                            Default::default(),
                        )
                        .unwrap()
                    })
                    .collect();

                let key_images: Vec<KeyImage> =
                    (0..5).map(|_i| KeyImage::from(rng.next_u64())).collect();

                let block_contents = BlockContents {
                    key_images,
                    outputs,
                    ..Default::default()
                };
                last_block = Block::new_with_parent(
                    block_version,
                    &last_block,
                    &Default::default(),
                    &block_contents,
                );

                ledger_db
                    .append_block(&last_block, &block_contents, None)
                    .unwrap();
            }

            // All blocks should've been written (+ origin block).
            assert_eq!(
                ledger_db.num_blocks().unwrap(),
                1 + (3 * (*block_version)) as u64
            );
        }

        // Last block version should be what we expect.
        let last_block = ledger_db
            .get_block(ledger_db.num_blocks().unwrap() - 1)
            .unwrap();
        assert_eq!(last_block.version, *MAX_BLOCK_VERSION);

        // Appending a block with version < previous block version should fail.
        {
            let recipient_account_key = AccountKey::random(&mut rng);
            let outputs: Vec<TxOut> = (0..4)
                .map(|_i| {
                    TxOut::new(
                        1000,
                        Mob::ID,
                        &recipient_account_key.default_subaddress(),
                        &RistrettoPrivate::from_random(&mut rng),
                        Default::default(),
                    )
                    .unwrap()
                })
                .collect();

            let key_images: Vec<KeyImage> =
                (0..5).map(|_i| KeyImage::from(rng.next_u64())).collect();

            let block_contents = BlockContents {
                key_images,
                outputs,
                ..Default::default()
            };
            assert_eq!(last_block.version, *MAX_BLOCK_VERSION);

            // Note: unsafe transmute is being used to skirt the invariant that BlockVersion
            // does not exceed MAX_BLOCK_VERSION
            let invalid_block = Block::new_with_parent(
                unsafe { core::mem::transmute(last_block.version + 1) },
                &last_block,
                &Default::default(),
                &block_contents,
            );
            assert_eq!(
                ledger_db.append_block(&invalid_block, &block_contents, None),
                Err(Error::InvalidBlockVersion(invalid_block.version))
            );

            if last_block.version > 0 {
                let invalid_block = Block::new_with_parent(
                    BlockVersion::try_from(last_block.version - 1).unwrap(),
                    &last_block,
                    &Default::default(),
                    &block_contents,
                );
                assert_eq!(
                    ledger_db.append_block(&invalid_block, &block_contents, None),
                    Err(Error::InvalidBlockVersion(invalid_block.version))
                );
            }
        }
    }

    #[test]
    fn test_append_block_at_wrong_location() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let mut ledger_db = create_db();
        let account_key = AccountKey::random(&mut rng);

        // initialize a ledger with 3 blocks.
        let n_blocks = 3;
        let (blocks, _) = populate_db(&mut ledger_db, n_blocks, 2);
        assert_eq!(ledger_db.num_blocks().unwrap(), n_blocks);

        let key_images = vec![KeyImage::from(rng.next_u64())];

        let tx_out = TxOut::new(
            100,
            Mob::ID,
            &account_key.default_subaddress(),
            &RistrettoPrivate::from_random(&mut rng),
            Default::default(),
        )
        .unwrap();

        let outputs = vec![tx_out];
        let block_contents = BlockContents {
            key_images,
            outputs,
            ..Default::default()
        };

        // Appending a block to a previously written location should fail.
        let mut new_block = Block::new(
            BLOCK_VERSION,
            &blocks[0].id,
            1,
            blocks[0].cumulative_txo_count,
            &Default::default(),
            &block_contents,
        );

        assert_eq!(
            ledger_db.append_block(&new_block, &block_contents, None),
            Err(Error::InvalidBlockIndex(new_block.index))
        );

        // Appending a non-contiguous location should fail.
        new_block.index = 3 * n_blocks;
        assert_eq!(
            ledger_db.append_block(&new_block, &block_contents, None),
            Err(Error::InvalidBlockIndex(new_block.index))
        );
    }

    #[test]
    /// Appending a block with a spent key image should return
    /// Error::KeyImageAlreadySpent.
    fn test_append_block_with_spent_key_image() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let mut ledger_db = create_db();

        // The origin block can't contain key images.
        let origin_account_key = AccountKey::random(&mut rng);
        let (origin_block, origin_block_contents) =
            get_origin_block_and_contents(&origin_account_key);
        ledger_db
            .append_block(&origin_block, &origin_block_contents, None)
            .unwrap();

        // Write the next block, containing several key images.
        let account_key = AccountKey::random(&mut rng);
        let num_key_images = 3;
        let block_one_key_images: Vec<KeyImage> = (0..num_key_images)
            .map(|_i| KeyImage::from(rng.next_u64()))
            .collect();

        let block_one_contents = {
            let tx_out = TxOut::new(
                10,
                Mob::ID,
                &account_key.default_subaddress(),
                &RistrettoPrivate::from_random(&mut rng),
                Default::default(),
            )
            .unwrap();
            let outputs = vec![tx_out];
            BlockContents {
                key_images: block_one_key_images.clone(),
                outputs,
                ..Default::default()
            }
        };

        let block_one = Block::new_with_parent(
            BLOCK_VERSION,
            &origin_block,
            &Default::default(),
            &block_one_contents,
        );

        ledger_db
            .append_block(&block_one, &block_one_contents, None)
            .unwrap();

        // The next block reuses a key image.
        let block_two_contents = {
            let tx_out = TxOut::new(
                33,
                Mob::ID,
                &account_key.default_subaddress(),
                &RistrettoPrivate::from_random(&mut rng),
                Default::default(),
            )
            .unwrap();
            let outputs = vec![tx_out];
            BlockContents {
                key_images: block_one_key_images.clone(),
                outputs,
                ..Default::default()
            }
        };

        let block_two = Block::new_with_parent(
            BLOCK_VERSION,
            &block_one,
            &Default::default(),
            &block_two_contents,
        );

        assert_eq!(
            ledger_db.append_block(&block_two, &block_two_contents, None),
            Err(Error::KeyImageAlreadySpent)
        );
    }

    #[test]
    /// Appending a block with a pre-existing output public key should return
    /// Error::DuplicateOutputPublicKey.
    fn test_append_block_with_duplicate_output_public_key() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let mut ledger_db = create_db();

        // Write a block to the ledger.
        let origin_account_key = AccountKey::random(&mut rng);
        let (origin_block, origin_block_contents) =
            get_origin_block_and_contents(&origin_account_key);
        ledger_db
            .append_block(&origin_block, &origin_block_contents, None)
            .unwrap();

        // The next block reuses a public key.
        let existing_tx_out = ledger_db.get_tx_out_by_index(0).unwrap();
        let account_key = AccountKey::random(&mut rng);

        let block_one_contents = {
            let mut tx_out = TxOut::new(
                33,
                Mob::ID,
                &account_key.default_subaddress(),
                &RistrettoPrivate::from_random(&mut rng),
                Default::default(),
            )
            .unwrap();
            tx_out.public_key = existing_tx_out.public_key.clone();
            let outputs = vec![tx_out];
            let key_images = vec![KeyImage::from(rng.next_u64())];
            BlockContents {
                key_images,
                outputs,
                ..Default::default()
            }
        };

        let block_one = Block::new_with_parent(
            BLOCK_VERSION,
            &origin_block,
            &Default::default(),
            &block_one_contents,
        );

        assert_eq!(
            ledger_db.append_block(&block_one, &block_one_contents, None),
            Err(Error::DuplicateOutputPublicKey)
        );
    }

    #[test]
    // append_block rejects invalid blocks.
    fn test_append_invalid_blocks() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let mut ledger_db = create_db();
        let account_key = AccountKey::random(&mut rng);

        let (origin_block, origin_block_contents) = get_origin_block_and_contents(&account_key);

        // append_block rejects a block with invalid id.
        {
            let mut block = origin_block.clone();
            block.id.0[0] += 1;
            assert_eq!(
                ledger_db.append_block(&block, &origin_block_contents, None),
                Err(Error::InvalidBlockID(block.id.clone()))
            );
        }

        // append_block rejects a block with invalid contents hash.
        {
            let mut block = origin_block.clone();
            block.contents_hash.0[0] += 1;
            assert_eq!(
                ledger_db.append_block(&block, &origin_block_contents, None),
                Err(Error::InvalidBlockContents)
            );
        }

        assert_eq!(
            ledger_db.append_block(&origin_block, &origin_block_contents, None),
            Ok(())
        );

        // append_block rejects a block with non-existent parent.
        {
            let tx_out = TxOut::new(
                100,
                Mob::ID,
                &account_key.default_subaddress(),
                &RistrettoPrivate::from_random(&mut rng),
                Default::default(),
            )
            .unwrap();

            let key_images = vec![KeyImage::from(rng.next_u64())];
            let outputs = vec![tx_out];
            let block_contents = BlockContents {
                key_images,
                outputs,
                ..Default::default()
            };

            let bytes = [14u8; 32];
            let bad_parent_id = BlockID::try_from(&bytes[..]).unwrap();

            // This block has a bad parent id.
            let block_one_bad = Block::new(
                BLOCK_VERSION,
                &bad_parent_id,
                1,
                origin_block.cumulative_txo_count,
                &Default::default(),
                &block_contents,
            );

            assert_eq!(
                ledger_db.append_block(&block_one_bad, &block_contents, None),
                Err(Error::InvalidParentBlockID(block_one_bad.parent_id.clone()))
            );

            // This block correctly has block zero as its parent.
            let block_one_good = Block::new(
                BLOCK_VERSION,
                &origin_block.id,
                1,
                origin_block.cumulative_txo_count,
                &Default::default(),
                &block_contents,
            );

            assert_eq!(
                ledger_db.append_block(&block_one_good, &block_contents, None),
                Ok(())
            );
        }
    }

    #[test]
    // ledger.num_txos agrees with the computed block header values
    fn double_check_num_txos() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let mut ledger_db = create_db();

        let origin_account_key = AccountKey::random(&mut rng);
        let (origin_block, origin_block_contents) =
            get_origin_block_and_contents(&origin_account_key);
        ledger_db
            .append_block(&origin_block, &origin_block_contents, None)
            .unwrap();

        // Make random recipients
        let accounts: Vec<AccountKey> = (0..20).map(|_i| AccountKey::random(&mut rng)).collect();
        let recipient_pub_keys = accounts
            .iter()
            .map(|account| account.default_subaddress())
            .collect::<Vec<_>>();

        // Get some random blocks
        let results: Vec<(Block, BlockContents)> = mc_transaction_core_test_utils::get_blocks(
            BLOCK_VERSION,
            &recipient_pub_keys[..],
            20,
            20,
            35,
            &origin_block,
            &mut rng,
        );

        for (block, block_contents) in &results {
            println!("block {} containing {:?}", block.index, block_contents);
            ledger_db.append_block(block, block_contents, None).unwrap();
            assert_eq!(block.cumulative_txo_count, ledger_db.num_txos().unwrap());
        }
    }

    #[test]
    // ledger_db.get_root_tx_out_membership_element returns the correct element
    fn get_root_tx_out_membership_element_returns_correct_element() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let mut ledger_db = create_db();

        let origin_account_key = AccountKey::random(&mut rng);
        let (origin_block, origin_block_contents) =
            get_origin_block_and_contents(&origin_account_key);
        ledger_db
            .append_block(&origin_block, &origin_block_contents, None)
            .unwrap();

        // Make random recipients
        let accounts: Vec<AccountKey> = (0..20).map(|_i| AccountKey::random(&mut rng)).collect();
        let recipient_pub_keys = accounts
            .iter()
            .map(|account| account.default_subaddress())
            .collect::<Vec<_>>();

        // Get some random blocks
        let results: Vec<(Block, BlockContents)> = mc_transaction_core_test_utils::get_blocks(
            BLOCK_VERSION,
            &recipient_pub_keys[..],
            20,
            20,
            35,
            &origin_block,
            &mut rng,
        );

        for (block, block_contents) in &results {
            ledger_db.append_block(block, block_contents, None).unwrap();
        }

        // The root element should be the same for all TxOuts in the ledger.
        let root_element = ledger_db.get_root_tx_out_membership_element().unwrap();

        for tx_out_index in 0..ledger_db.num_txos().unwrap() {
            let proofs = ledger_db
                .get_tx_out_proof_of_memberships(&[tx_out_index])
                .unwrap();

            let implied_root = compute_implied_merkle_root(&proofs[0]).unwrap();
            assert_eq!(root_element, implied_root);
        }
    }

    // FIXME(MC-526): If these benches are not marked ignore, they get run during
    // cargo test and they are not compiled with optimizations which makes them
    // take several minutes I think they should probably be moved to
    // `ledger_db/benches/...` ?
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
