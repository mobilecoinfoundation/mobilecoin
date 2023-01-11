// Copyright (c) 2018-2022 The MobileCoin Foundation

use crate::{
    ActiveMintConfig, ActiveMintConfigs, Error, Ledger, LedgerMetrics, MetadataStore,
    MetadataStoreSettings, MintConfigStore, MintTxStore, TxOutStore,
};
use lmdb::{
    Database, DatabaseFlags, Environment, EnvironmentFlags, RoTransaction, RwTransaction,
    Transaction, WriteFlags,
};
use mc_blockchain_types::{
    Block, BlockContents, BlockData, BlockID, BlockIndex, BlockMetadata, BlockSignature,
    BlockVersion, MAX_BLOCK_VERSION,
};
use mc_common::{logger::global_log, HashMap};
use mc_crypto_keys::CompressedRistrettoPublic;
use mc_transaction_core::{
    membership_proofs::Range,
    mint::MintTx,
    ring_signature::KeyImage,
    tx::{TxOut, TxOutMembershipElement, TxOutMembershipProof},
    TokenId,
};
use mc_util_serial::{decode, encode, Message};
use mc_util_telemetry::{
    mark_span_as_active, start_block_span, telemetry_static_key, tracer, Key, Span,
};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
    time::Instant,
};

pub const MAX_LMDB_FILE_SIZE: usize = 1 << 40; // 1 TB

/// maximum number of [Database]s in the lmdb file
pub const MAX_LMDB_DATABASES: u32 = 19;

// LMDB Database names.
pub const COUNTS_DB_NAME: &str = "ledger_db:counts";
pub const BLOCKS_DB_NAME: &str = "ledger_db:blocks";
pub const BLOCK_SIGNATURES_DB_NAME: &str = "ledger_db:block_signatures";
pub const BLOCK_METADATA_DB_NAME: &str = "ledger_db:block_metadata";
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
    const LATEST_VERSION: u64 = 2022_09_21;

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

    /// Block metadata by number. `block number -> BlockMetadata`
    block_metadata: Database,

    /// Key Images
    key_images: Database,

    /// Key Images by Block
    key_images_by_block: Database,

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
    fn append_block<'b>(
        &mut self,
        block: &'b Block,
        block_contents: &'b BlockContents,
        signature: Option<&'b BlockSignature>,
        metadata: Option<&'b BlockMetadata>,
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
        self.validate_append_block(block, block_contents, metadata, &db_transaction)?;

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

        // Write ValidatedMintConfigTxs included in the block.
        self.mint_config_store.write_validated_mint_config_txs(
            block.index,
            &block_contents.validated_mint_config_txs,
            &mut db_transaction,
        )?;

        // Write block.
        self.write_block(block, signature, metadata, &mut db_transaction)?;

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

    /// Gets a block's signature by its index in the blockchain.
    fn get_block_signature(&self, block_number: u64) -> Result<BlockSignature, Error> {
        let db_transaction = self.env.begin_ro_txn()?;
        self.get_block_signature_impl(&db_transaction, block_number)
    }

    /// Gets a block's metadata by its index in the blockchain.
    fn get_block_metadata(&self, block_number: u64) -> Result<BlockMetadata, Error> {
        let db_transaction = self.env.begin_ro_txn()?;
        self.get_block_metadata_impl(&db_transaction, block_number)
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
        let metadata = match self.get_block_metadata_impl(&db_transaction, block_number) {
            Ok(metadata) => Ok(Some(metadata)),
            Err(Error::NotFound) => Ok(None),
            Err(err) => Err(err),
        }?;

        Ok(BlockData::new(block, contents, signature, metadata))
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
    fn get_active_mint_configs(
        &self,
        token_id: TokenId,
    ) -> Result<Option<ActiveMintConfigs>, Error> {
        let db_transaction = self.env.begin_ro_txn()?;
        self.mint_config_store
            .get_active_mint_configs(token_id, &db_transaction)
    }

    /// Return the full map of TokenId -> ActiveMintConfigs.
    fn get_active_mint_configs_map(&self) -> Result<HashMap<TokenId, ActiveMintConfigs>, Error> {
        let db_transaction = self.env.begin_ro_txn()?;
        self.mint_config_store
            .get_active_mint_configs_map(&db_transaction)
    }

    /// Checks if the ledger contains a given MintConfigTx nonce for a given
    /// token id. If so, returns the index of the block in which it entered
    /// the ledger. Ok(None) is returned when the nonce is not in the
    /// ledger.
    fn check_mint_config_tx_nonce(
        &self,
        token_id: u64,
        nonce: &[u8],
    ) -> Result<Option<BlockIndex>, Error> {
        let db_transaction = self.env.begin_ro_txn()?;
        self.mint_config_store
            .check_mint_config_tx_nonce(token_id, nonce, &db_transaction)
    }

    /// Checks if the ledger contains a given MintTx nonce for a given token id.
    /// If so, returns the index of the block in which it entered the ledger.
    /// Ok(None) is returned when the nonce is not in the ledger.
    fn check_mint_tx_nonce(
        &self,
        token_id: u64,
        nonce: &[u8],
    ) -> Result<Option<BlockIndex>, Error> {
        let db_transaction = self.env.begin_ro_txn()?;
        self.mint_tx_store
            .check_mint_tx_nonce(token_id, nonce, &db_transaction)
    }

    /// Attempt to get an active mint configuration that is able to verify and
    /// accommodate a given MintTx.
    fn get_active_mint_config_for_mint_tx(
        &self,
        mint_tx: &MintTx,
    ) -> Result<ActiveMintConfig, Error> {
        let db_transaction = self.env.begin_ro_txn()?;
        self.mint_config_store
            .get_active_mint_config_for_mint_tx(mint_tx, &db_transaction)
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
        // Block metadata was added later, so we call create_db instead of open_db.
        // If the Database exists, create_db returns it.
        let block_metadata = env.create_db(Some(BLOCK_METADATA_DB_NAME), DatabaseFlags::empty())?;
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
            block_metadata,
            key_images,
            key_images_by_block,
            tx_outs_by_block,
            block_number_by_tx_out_index,
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
        env.create_db(Some(BLOCK_METADATA_DB_NAME), DatabaseFlags::empty())?;
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
        metadata: Option<&BlockMetadata>,
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

        if let Some(metadata) = metadata {
            db_transaction.put(
                self.block_metadata,
                &u64_to_key_bytes(block.index),
                &encode(metadata),
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
        metadata: Option<&BlockMetadata>,
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
        let has_mint_config_txs = !block_contents.validated_mint_config_txs.is_empty();
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
        let has_minting_txs = !block_contents.validated_mint_config_txs.is_empty()
            || !block_contents.mint_txs.is_empty();
        if block.index != 0 && block_contents.key_images.is_empty() && !has_minting_txs {
            return Err(Error::NoKeyImages);
        }

        // Check that the block contents match the hash.
        if block.contents_hash != block_contents.hash() {
            return Err(Error::InvalidBlockContents);
        }

        // Check that none of the outputs are missing masked amount (or, have a masked
        // amount we don't understand)
        if block_contents
            .outputs
            .iter()
            .any(|output| output.get_masked_amount().is_err())
        {
            return Err(Error::MissingMaskedAmount);
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
                .check_mint_tx_nonce(
                    mint_tx.prefix.token_id,
                    &mint_tx.prefix.nonce,
                    db_transaction,
                )?
                .is_some()
            {
                return Err(Error::DuplicateMintTx);
            }
        }

        // Check that none of the mint-config-tx nonces appear in the ledger.
        for validated_mint_config_tx in block_contents.validated_mint_config_txs.iter() {
            if self
                .mint_config_store
                .check_mint_config_tx_nonce(
                    validated_mint_config_tx.mint_config_tx.prefix.token_id,
                    &validated_mint_config_tx.mint_config_tx.prefix.nonce,
                    db_transaction,
                )?
                .is_some()
            {
                return Err(Error::DuplicateMintConfigTx);
            }
        }

        let block_version = BlockVersion::try_from(block.version)
            .or(Err(Error::InvalidBlockVersion(block.version)))?;
        if block_version.require_block_metadata() && metadata.is_none() {
            return Err(Error::BlockMetadataRequired);
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

        // Get all ValidatedMintConfigTxs in block.
        let validated_mint_config_txs = self
            .mint_config_store
            .get_validated_mint_config_txs_by_block_index(block_number, db_transaction)?;

        // Get all MintTxs in block.
        let mint_txs = self
            .mint_tx_store
            .get_mint_txs_by_block_index(block_number, db_transaction)?;

        // Returns block contents.
        Ok(BlockContents {
            key_images: key_image_list.key_images,
            outputs,
            validated_mint_config_txs,
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

    /// Implementation of the `get_block_metadata` method that operates inside
    /// a given transaction.
    fn get_block_metadata_impl(
        &self,
        db_transaction: &impl Transaction,
        block_number: u64,
    ) -> Result<BlockMetadata, Error> {
        let key = u64_to_key_bytes(block_number);
        let metadata_bytes = db_transaction.get(self.block_metadata, &key)?;
        let metadata = decode(metadata_bytes)?;
        Ok(metadata)
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

/// Creates a LedgerDB instance at the given path.
pub fn create_ledger_in(path: &Path) -> LedgerDB {
    let path = PathBuf::from(path);
    std::fs::create_dir_all(&path).expect("Could not create dirs");
    LedgerDB::create(&path).expect("Could not create ledger_db");
    LedgerDB::open(&path).expect("Could not open ledger_db")
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

#[cfg(test)]
mod ledger_db_test {
    use super::*;
    use crate::test_utils::{add_block_contents_to_ledger, add_txos_and_key_images_to_ledger};
    use mc_blockchain_test_utils::{get_blocks, make_block_metadata};
    use mc_crypto_keys::Ed25519Pair;
    use mc_transaction_core::{membership_proofs::compute_implied_merkle_root, BlockVersion};
    use mc_transaction_core_test_utils::{
        create_mint_config_tx, create_mint_config_tx_and_signers, create_mint_tx,
        create_test_tx_out, mint_config_tx_to_validated as to_validated,
    };
    use mc_util_from_random::FromRandom;
    use mc_util_test_helper::get_seeded_rng;
    use rand::{rngs::StdRng, RngCore, SeedableRng};
    use tempdir::TempDir;
    use test::Bencher;

    // TODO: Should these tests run over several block versions?
    const BLOCK_VERSION: BlockVersion = BlockVersion::ZERO;

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
        num_blocks: usize,
        num_outputs_per_block: usize,
    ) -> Vec<BlockData> {
        // Generate 1 public / private addresses and create transactions.
        let blocks = get_blocks(
            BLOCK_VERSION,
            num_blocks,
            1,
            1,
            num_outputs_per_block,
            1 << 20,
            None,
            &mut get_seeded_rng(),
        );
        for block_data in &blocks {
            db.append_block_data(block_data).unwrap_or_else(|err| {
                panic!(
                    "failed writing block with index {}: {}",
                    block_data.block().index,
                    err
                );
            });
        }

        // Verify that db now contains n transactions.
        assert_eq!(db.num_blocks().unwrap(), num_blocks as u64);

        blocks
    }

    fn get_origin_block() -> BlockData {
        // The origin block contains a single output belonging to the
        // `origin_account_key`.
        get_blocks(BLOCK_VERSION, 1, 1, 1, 1, 1000, None, &mut get_seeded_rng())
            .pop()
            .unwrap()
    }

    fn add_origin_block(ledger_db: &mut LedgerDB) -> BlockData {
        let block_data = get_origin_block();
        ledger_db.append_block_data(&block_data).unwrap();

        block_data
    }

    #[test]
    // Test initial conditions of a new LedgerDB instance.
    fn ledger_db_initialization() {
        let ledger_db = create_db();
        assert_eq!(ledger_db.num_blocks().unwrap(), 0);
        assert_eq!(ledger_db.num_txos().unwrap(), 0);
    }

    #[test]
    // Appending a block without any minting-related transactions should correctly
    // update each LMDB database.
    fn append_block_without_minting() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let mut ledger_db = create_db();

        // === Create and append the origin block. ===
        let origin = add_origin_block(&mut ledger_db);

        assert_eq!(1, ledger_db.num_blocks().unwrap());
        assert_eq!(origin, ledger_db.get_block_data(0).unwrap());
        assert_eq!(1, ledger_db.num_txos().unwrap());

        let origin_tx_out = origin.contents().outputs[0].clone();
        assert_eq!(origin_tx_out, ledger_db.get_tx_out_by_index(0).unwrap());

        let key_images = ledger_db.get_key_images_by_block(0).unwrap();
        assert_eq!(key_images.len(), 0);

        let block_index = ledger_db.get_block_index_by_tx_out_index(0).unwrap();
        assert_eq!(block_index, 0);

        // === Create and append a non-origin block. ===

        let outputs: Vec<TxOut> = (0..4)
            .map(|_i| create_test_tx_out(BLOCK_VERSION, &mut rng))
            .collect();

        let key_images: Vec<KeyImage> = (0..5).map(|_i| KeyImage::from(rng.next_u64())).collect();
        let block_data = add_txos_and_key_images_to_ledger(
            &mut ledger_db,
            BLOCK_VERSION,
            outputs,
            key_images.clone(),
            &mut rng,
        )
        .unwrap();

        assert_eq!(2, ledger_db.num_blocks().unwrap());

        // The origin block should still be in the ledger:
        assert_eq!(origin.block(), &ledger_db.get_block(0).unwrap());
        // The origin's TxOut should still be in the ledger:
        assert_eq!(origin_tx_out, ledger_db.get_tx_out_by_index(0).unwrap());

        // The new block should be in the ledger:
        assert_eq!(block_data.block(), &ledger_db.get_block(1).unwrap());
        assert_eq!(5, ledger_db.num_txos().unwrap());

        // Each TxOut from the current block should be in the ledger.
        for (i, tx_out) in block_data.contents().outputs.iter().enumerate() {
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

        assert!(ledger_db.contains_key_image(&key_images[0]).unwrap());

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
        let origin = add_origin_block(&mut ledger_db);

        let origin_tx_out = origin.contents().outputs[0].clone();
        assert_eq!(origin_tx_out, ledger_db.get_tx_out_by_index(0).unwrap());

        assert_eq!(ledger_db.get_active_mint_configs(token_id1).unwrap(), None);

        // === Append a block with only a single MintConfigTx. ===
        let mint_config_tx1 = create_mint_config_tx(token_id1, &mut rng);

        let block_contents1 = BlockContents {
            validated_mint_config_txs: vec![to_validated(&mint_config_tx1)],
            ..Default::default()
        };
        let block1 =
            add_block_contents_to_ledger(&mut ledger_db, BLOCK_VERSION, block_contents1, &mut rng)
                .unwrap();

        assert_eq!(2, ledger_db.num_blocks().unwrap());
        // The origin block should still be in the ledger:
        assert_eq!(origin, ledger_db.get_block_data(0).unwrap());
        // The new block should be in the ledger:
        assert_eq!(block1, ledger_db.get_block_data(1).unwrap());

        // The origin's TxOut should still be in the ledger:
        assert_eq!(1, ledger_db.num_txos().unwrap());
        assert_eq!(origin_tx_out, ledger_db.get_tx_out_by_index(0).unwrap());

        // The active mint configs should be updated.
        assert_eq!(
            ledger_db
                .get_active_mint_configs(token_id1)
                .unwrap()
                .unwrap()
                .configs,
            vec![
                ActiveMintConfig {
                    mint_config: mint_config_tx1.prefix.configs[0].clone(),
                    total_minted: 0,
                },
                ActiveMintConfig {
                    mint_config: mint_config_tx1.prefix.configs[1].clone(),
                    total_minted: 0,
                },
                ActiveMintConfig {
                    mint_config: mint_config_tx1.prefix.configs[2].clone(),
                    total_minted: 0,
                },
            ]
        );

        // Append another block with two MintConfigTxs, one of which is updating the
        // active config for token_id1.
        let mint_config_tx2 = create_mint_config_tx(token_id1, &mut rng);
        let mint_config_tx3 = create_mint_config_tx(token_id2, &mut rng);

        let block_contents2 = BlockContents {
            validated_mint_config_txs: vec![
                to_validated(&mint_config_tx2),
                to_validated(&mint_config_tx3),
            ],
            ..Default::default()
        };
        let block2 =
            add_block_contents_to_ledger(&mut ledger_db, BLOCK_VERSION, block_contents2, &mut rng)
                .unwrap();

        assert_eq!(3, ledger_db.num_blocks().unwrap());
        assert_eq!(1, ledger_db.num_txos().unwrap());

        // The previous blocks should still be in the ledger.
        assert_eq!(origin, ledger_db.get_block_data(0).unwrap());
        assert_eq!(block1, ledger_db.get_block_data(1).unwrap());

        // The new block contents should be in the ledger.
        assert_eq!(block2, ledger_db.get_block_data(2).unwrap());

        // The active mint configs should be updated.
        assert_eq!(
            ledger_db
                .get_active_mint_configs(token_id1)
                .unwrap()
                .unwrap()
                .configs,
            vec![
                ActiveMintConfig {
                    mint_config: mint_config_tx2.prefix.configs[0].clone(),
                    total_minted: 0,
                },
                ActiveMintConfig {
                    mint_config: mint_config_tx2.prefix.configs[1].clone(),
                    total_minted: 0,
                },
                ActiveMintConfig {
                    mint_config: mint_config_tx2.prefix.configs[2].clone(),
                    total_minted: 0,
                },
            ]
        );

        assert_eq!(
            ledger_db
                .get_active_mint_configs(token_id2)
                .unwrap()
                .unwrap()
                .configs,
            vec![
                ActiveMintConfig {
                    mint_config: mint_config_tx3.prefix.configs[0].clone(),
                    total_minted: 0,
                },
                ActiveMintConfig {
                    mint_config: mint_config_tx3.prefix.configs[1].clone(),
                    total_minted: 0,
                },
                ActiveMintConfig {
                    mint_config: mint_config_tx3.prefix.configs[2].clone(),
                    total_minted: 0,
                },
            ]
        );
    }

    #[test]
    // Appending a block that contains a previously-seen MintConfigTx should
    // fail.
    fn append_block_fails_for_duplicate_mint_config_txs() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let mut ledger_db = create_db();
        let token_id1 = TokenId::from(1);

        // === Create and append the origin block. ===
        add_origin_block(&mut ledger_db);

        // === Append a block with only a single MintConfigTx. ===
        let mint_config_tx1 = create_mint_config_tx(token_id1, &mut rng);

        let block_contents1 = BlockContents {
            validated_mint_config_txs: vec![to_validated(&mint_config_tx1)],
            ..Default::default()
        };

        add_block_contents_to_ledger(&mut ledger_db, BLOCK_VERSION, block_contents1, &mut rng)
            .unwrap();

        // Try appending a block that contains the same set mint config tx.
        let mint_config_tx2 = create_mint_config_tx(token_id1, &mut rng);

        let block_contents2 = BlockContents {
            validated_mint_config_txs: vec![
                to_validated(&mint_config_tx2),
                to_validated(&mint_config_tx1),
            ],
            ..Default::default()
        };
        assert_eq!(
            add_block_contents_to_ledger(&mut ledger_db, BLOCK_VERSION, block_contents2, &mut rng),
            Err(Error::DuplicateMintConfigTx)
        );
    }

    #[test]
    // Appending a block with MintTxs and outputs should correctly update each LMDB
    // database.
    fn append_block_with_mint_txs_and_outputs() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let mut ledger_db = create_db();
        let token_id1 = TokenId::from(1);

        // === Create and append the origin block. ===
        let origin = add_origin_block(&mut ledger_db);
        let origin_tx_out = origin.contents().outputs[0].clone();

        assert_eq!(ledger_db.get_active_mint_configs(token_id1).unwrap(), None);

        // === Append a block wth a MintConfigTx transaction. This is needed since
        // the MintTx must be matched with an active mint config.
        let (mint_config_tx1, signers1) = create_mint_config_tx_and_signers(token_id1, &mut rng);

        let block_contents1 = BlockContents {
            validated_mint_config_txs: vec![to_validated(&mint_config_tx1)],
            ..Default::default()
        };

        let block1 =
            add_block_contents_to_ledger(&mut ledger_db, BLOCK_VERSION, block_contents1, &mut rng)
                .unwrap();

        // === Append a block with only a single MintTx. ===
        let mint_tx1 = create_mint_tx(token_id1, &signers1, 10, &mut rng);

        let block_contents2 = BlockContents {
            mint_txs: vec![mint_tx1.clone()],
            outputs: vec![create_test_tx_out(BLOCK_VERSION, &mut rng)],
            ..Default::default()
        };

        let block2 =
            add_block_contents_to_ledger(&mut ledger_db, BLOCK_VERSION, block_contents2, &mut rng)
                .unwrap();

        assert_eq!(3, ledger_db.num_blocks().unwrap());
        assert_eq!(2, ledger_db.num_txos().unwrap());
        // The origin block should still be in the ledger:
        assert_eq!(origin, ledger_db.get_block_data(0).unwrap());
        assert_eq!(block1, ledger_db.get_block_data(1).unwrap());
        // The new block should be in the ledger:
        assert_eq!(block2, ledger_db.get_block_data(2).unwrap());

        // The origin's TxOut should still be in the ledger:
        assert_eq!(origin_tx_out, ledger_db.get_tx_out_by_index(0).unwrap());

        // The active mint configs should be updated.
        assert_eq!(
            ledger_db
                .get_active_mint_configs(token_id1)
                .unwrap()
                .unwrap()
                .configs,
            vec![
                ActiveMintConfig {
                    mint_config: mint_config_tx1.prefix.configs[0].clone(),
                    total_minted: mint_tx1.prefix.amount,
                },
                ActiveMintConfig {
                    mint_config: mint_config_tx1.prefix.configs[1].clone(),
                    total_minted: 0,
                },
                ActiveMintConfig {
                    mint_config: mint_config_tx1.prefix.configs[2].clone(),
                    total_minted: 0,
                },
            ]
        );

        // === Append another block with a MintTx, this one targetting the
        // second mint configuration.
        let mint_tx2 = create_mint_tx(
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
            outputs: vec![create_test_tx_out(BLOCK_VERSION, &mut rng)],
            ..Default::default()
        };
        let block3 =
            add_block_contents_to_ledger(&mut ledger_db, BLOCK_VERSION, block_contents3, &mut rng)
                .unwrap();

        assert_eq!(4, ledger_db.num_blocks().unwrap());
        assert_eq!(3, ledger_db.num_txos().unwrap());
        // Previous blocks should still be in the ledger:
        assert_eq!(origin, ledger_db.get_block_data(0).unwrap());
        assert_eq!(block1, ledger_db.get_block_data(1).unwrap());
        assert_eq!(block2, ledger_db.get_block_data(2).unwrap());

        // The new block should be in the ledger:
        assert_eq!(block3, ledger_db.get_block_data(3).unwrap());

        // The active mint configs should be updated.
        assert_eq!(
            ledger_db
                .get_active_mint_configs(token_id1)
                .unwrap()
                .unwrap()
                .configs,
            vec![
                ActiveMintConfig {
                    mint_config: mint_config_tx1.prefix.configs[0].clone(),
                    total_minted: mint_tx1.prefix.amount,
                },
                ActiveMintConfig {
                    mint_config: mint_config_tx1.prefix.configs[1].clone(),
                    total_minted: mint_tx2.prefix.amount,
                },
                ActiveMintConfig {
                    mint_config: mint_config_tx1.prefix.configs[2].clone(),
                    total_minted: 0,
                },
            ]
        );

        // === Append a third block with a MintTx, tragetting the first active
        // mint config which should result in the total minted amount
        // increasing.
        let mint_tx3 = create_mint_tx(
            token_id1,
            &[Ed25519Pair::from(signers1[0].private_key())],
            30,
            &mut rng,
        );

        let block_contents4 = BlockContents {
            mint_txs: vec![mint_tx3.clone()],
            outputs: vec![create_test_tx_out(BLOCK_VERSION, &mut rng)],
            ..Default::default()
        };
        let block4 =
            add_block_contents_to_ledger(&mut ledger_db, BLOCK_VERSION, block_contents4, &mut rng)
                .unwrap();

        assert_eq!(5, ledger_db.num_blocks().unwrap());
        assert_eq!(4, ledger_db.num_txos().unwrap());

        // Previous blocks should still be in the ledger:
        assert_eq!(origin, ledger_db.get_block_data(0).unwrap());
        assert_eq!(block1, ledger_db.get_block_data(1).unwrap());
        assert_eq!(block2, ledger_db.get_block_data(2).unwrap());
        assert_eq!(block3, ledger_db.get_block_data(3).unwrap());

        // The new block should be in the ledger:
        assert_eq!(block4, ledger_db.get_block_data(4).unwrap());

        // The active mint configs should be updated.
        assert_eq!(
            ledger_db
                .get_active_mint_configs(token_id1)
                .unwrap()
                .unwrap()
                .configs,
            vec![
                ActiveMintConfig {
                    mint_config: mint_config_tx1.prefix.configs[0].clone(),
                    total_minted: mint_tx1.prefix.amount + mint_tx3.prefix.amount,
                },
                ActiveMintConfig {
                    mint_config: mint_config_tx1.prefix.configs[1].clone(),
                    total_minted: mint_tx2.prefix.amount,
                },
                ActiveMintConfig {
                    mint_config: mint_config_tx1.prefix.configs[2].clone(),
                    total_minted: 0,
                },
            ]
        );

        // === Append a fourth block with two MintTxs, tragetting the first active
        // mint config which should result in the total minted amount
        // increasing.
        let mint_tx4 = create_mint_tx(
            token_id1,
            &[Ed25519Pair::from(signers1[0].private_key())],
            100,
            &mut rng,
        );

        let mint_tx5 = create_mint_tx(
            token_id1,
            &[Ed25519Pair::from(signers1[0].private_key())],
            200,
            &mut rng,
        );

        let block_contents5 = BlockContents {
            mint_txs: vec![mint_tx4.clone(), mint_tx5.clone()],
            outputs: vec![
                create_test_tx_out(BLOCK_VERSION, &mut rng),
                create_test_tx_out(BLOCK_VERSION, &mut rng),
            ],
            ..Default::default()
        };

        let block5 =
            add_block_contents_to_ledger(&mut ledger_db, BLOCK_VERSION, block_contents5, &mut rng)
                .unwrap();

        assert_eq!(6, ledger_db.num_blocks().unwrap());
        assert_eq!(6, ledger_db.num_txos().unwrap());

        // Previous blocks should still be in the ledger:
        assert_eq!(origin, ledger_db.get_block_data(0).unwrap());
        assert_eq!(block1, ledger_db.get_block_data(1).unwrap());
        assert_eq!(block2, ledger_db.get_block_data(2).unwrap());
        assert_eq!(block3, ledger_db.get_block_data(3).unwrap());
        assert_eq!(block4, ledger_db.get_block_data(4).unwrap());

        // The new block should be in the ledger:
        assert_eq!(block5, ledger_db.get_block_data(5).unwrap());

        // The active mint configs should be updated.
        assert_eq!(
            ledger_db
                .get_active_mint_configs(token_id1)
                .unwrap()
                .unwrap()
                .configs,
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
                },
                ActiveMintConfig {
                    mint_config: mint_config_tx1.prefix.configs[2].clone(),
                    total_minted: 0,
                },
            ]
        );

        // === Append a fifth with two MintTxs, tragetting both mint configs which
        // should result in the total minted amount increasing.
        let mint_tx6 = create_mint_tx(
            token_id1,
            &[Ed25519Pair::from(signers1[0].private_key())],
            101,
            &mut rng,
        );

        let mint_tx7 = create_mint_tx(
            token_id1,
            &[Ed25519Pair::from(signers1[1].private_key())],
            201,
            &mut rng,
        );

        let block_contents6 = BlockContents {
            mint_txs: vec![mint_tx6.clone(), mint_tx7.clone()],
            outputs: vec![
                create_test_tx_out(BLOCK_VERSION, &mut rng),
                create_test_tx_out(BLOCK_VERSION, &mut rng),
            ],
            ..Default::default()
        };

        let block6 =
            add_block_contents_to_ledger(&mut ledger_db, BLOCK_VERSION, block_contents6, &mut rng)
                .unwrap();

        assert_eq!(7, ledger_db.num_blocks().unwrap());
        assert_eq!(8, ledger_db.num_txos().unwrap());

        // Previous blocks should still be in the ledger:
        assert_eq!(origin, ledger_db.get_block_data(0).unwrap());
        assert_eq!(block1, ledger_db.get_block_data(1).unwrap());
        assert_eq!(block2, ledger_db.get_block_data(2).unwrap());
        assert_eq!(block3, ledger_db.get_block_data(3).unwrap());
        assert_eq!(block4, ledger_db.get_block_data(4).unwrap());
        assert_eq!(block5, ledger_db.get_block_data(5).unwrap());

        // The new block should be in the ledger:
        assert_eq!(block6, ledger_db.get_block_data(6).unwrap());

        // The active mint configs should be updated.
        assert_eq!(
            ledger_db
                .get_active_mint_configs(token_id1)
                .unwrap()
                .unwrap()
                .configs,
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
                },
                ActiveMintConfig {
                    mint_config: mint_config_tx1.prefix.configs[2].clone(),
                    total_minted: 0,
                },
            ]
        );
    }

    #[test]
    // Appending a block that contains a mix of outputs, key images and mint
    // transactions should work as expected.
    fn append_block_containing_outputs_key_images_and_mint_txs() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let mut ledger_db = create_db();
        let token_id1 = TokenId::from(1);
        let token_id2 = TokenId::from(2);

        // === Create and append the origin block. ===
        let origin = add_origin_block(&mut ledger_db);

        // === Create and append a non-origin block. ===
        let outputs1: Vec<TxOut> = (0..4)
            .map(|_i| create_test_tx_out(BLOCK_VERSION, &mut rng))
            .collect();

        let key_images1: Vec<KeyImage> = (0..5).map(|_i| KeyImage::from(rng.next_u64())).collect();
        let mint_config_tx1 = create_mint_config_tx(token_id1, &mut rng);
        let (mint_config_tx2, signers2) = create_mint_config_tx_and_signers(token_id2, &mut rng);

        let block_contents1 = BlockContents {
            key_images: key_images1,
            outputs: outputs1,
            validated_mint_config_txs: vec![
                to_validated(&mint_config_tx1),
                to_validated(&mint_config_tx2),
            ],
            mint_txs: vec![], /* For this block we cant include any mint txs since we need an
                               * active configuration first. */
        };
        let block1 =
            add_block_contents_to_ledger(&mut ledger_db, BLOCK_VERSION, block_contents1, &mut rng)
                .unwrap();

        assert_eq!(2, ledger_db.num_blocks().unwrap());
        // The origin block should still be in the ledger:
        assert_eq!(origin, ledger_db.get_block_data(0).unwrap());
        // The new block should be in the ledger:
        assert_eq!(block1, ledger_db.get_block_data(1).unwrap());

        // The active mint configs should be updated.
        assert_eq!(
            ledger_db
                .get_active_mint_configs(token_id1)
                .unwrap()
                .unwrap()
                .configs,
            vec![
                ActiveMintConfig {
                    mint_config: mint_config_tx1.prefix.configs[0].clone(),
                    total_minted: 0,
                },
                ActiveMintConfig {
                    mint_config: mint_config_tx1.prefix.configs[1].clone(),
                    total_minted: 0,
                },
                ActiveMintConfig {
                    mint_config: mint_config_tx1.prefix.configs[2].clone(),
                    total_minted: 0,
                },
            ]
        );

        assert_eq!(
            ledger_db
                .get_active_mint_configs(token_id2)
                .unwrap()
                .unwrap()
                .configs,
            vec![
                ActiveMintConfig {
                    mint_config: mint_config_tx2.prefix.configs[0].clone(),
                    total_minted: 0,
                },
                ActiveMintConfig {
                    mint_config: mint_config_tx2.prefix.configs[1].clone(),
                    total_minted: 0,
                },
                ActiveMintConfig {
                    mint_config: mint_config_tx2.prefix.configs[2].clone(),
                    total_minted: 0,
                },
            ]
        );

        // Each TxOut from the current block should be in the ledger.
        assert_eq!(5, ledger_db.num_txos().unwrap());

        for (i, tx_out) in block1.contents().outputs.iter().enumerate() {
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
            .contains_key_image(block1.contents().key_images.get(0).unwrap())
            .unwrap());

        let block1_key_images = ledger_db.get_key_images_by_block(1).unwrap();
        assert_eq!(block1.contents().key_images, block1_key_images);

        //  === Write another block - this one has a MintTx in addition to all
        // the other txs.
        let outputs2: Vec<TxOut> = (0..4)
            .map(|_i| create_test_tx_out(BLOCK_VERSION, &mut rng))
            .collect();

        let key_images2: Vec<KeyImage> = (0..5).map(|_i| KeyImage::from(rng.next_u64())).collect();
        let mint_config_tx3 = create_mint_config_tx(token_id1, &mut rng);
        let mint_tx1 = create_mint_tx(token_id2, &signers2, 10, &mut rng);
        let mint_tx2 = create_mint_tx(token_id2, &signers2, 20, &mut rng);

        let block_contents2 = BlockContents {
            key_images: key_images2,
            outputs: outputs2,
            validated_mint_config_txs: vec![to_validated(&mint_config_tx3)],
            mint_txs: vec![mint_tx1, mint_tx2],
        };
        let block2 =
            add_block_contents_to_ledger(&mut ledger_db, BLOCK_VERSION, block_contents2, &mut rng)
                .unwrap();

        assert_eq!(3, ledger_db.num_blocks().unwrap());
        // The previous blocks should still be in the ledger:
        assert_eq!(origin, ledger_db.get_block_data(0).unwrap());
        assert_eq!(block1, ledger_db.get_block_data(1).unwrap());
        // The new block should be in the ledger:
        assert_eq!(block2, ledger_db.get_block_data(2).unwrap());

        // The active mint configs should be updated.
        assert_eq!(
            ledger_db
                .get_active_mint_configs(token_id1)
                .unwrap()
                .unwrap()
                .configs,
            vec![
                ActiveMintConfig {
                    mint_config: mint_config_tx3.prefix.configs[0].clone(),
                    total_minted: 0,
                },
                ActiveMintConfig {
                    mint_config: mint_config_tx3.prefix.configs[1].clone(),
                    total_minted: 0,
                },
                ActiveMintConfig {
                    mint_config: mint_config_tx3.prefix.configs[2].clone(),
                    total_minted: 0,
                },
            ]
        );

        assert_eq!(
            ledger_db
                .get_active_mint_configs(token_id2)
                .unwrap()
                .unwrap()
                .configs,
            vec![
                ActiveMintConfig {
                    mint_config: mint_config_tx2.prefix.configs[0].clone(),
                    total_minted: 30,
                },
                ActiveMintConfig {
                    mint_config: mint_config_tx2.prefix.configs[1].clone(),
                    total_minted: 0,
                },
                ActiveMintConfig {
                    mint_config: mint_config_tx2.prefix.configs[2].clone(),
                    total_minted: 0,
                },
            ]
        );

        // Each TxOut from the current block should be in the ledger.
        assert_eq!(9, ledger_db.num_txos().unwrap());

        for (i, tx_out) in block2.contents().outputs.iter().enumerate() {
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
            .contains_key_image(block2.contents().key_images.get(0).unwrap())
            .unwrap());

        let block2_key_images = ledger_db.get_key_images_by_block(2).unwrap();
        assert_eq!(block2.contents().key_images, block2_key_images);
    }

    #[test]
    // Appending a block that contains more MintTxs than outputs should fail.
    fn append_block_fails_if_not_enough_outputs() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let mut ledger_db = create_db();
        let token_id1 = TokenId::from(1);

        // === Create and append the origin block. ===
        add_origin_block(&mut ledger_db);

        // === Append a block wth a MintConfigTx transaction. This is needed since
        // the MintTx must be matched with an active mint config.
        let (mint_config_tx1, signers1) = create_mint_config_tx_and_signers(token_id1, &mut rng);

        let block_contents1 = BlockContents {
            validated_mint_config_txs: vec![to_validated(&mint_config_tx1)],
            ..Default::default()
        };

        add_block_contents_to_ledger(&mut ledger_db, BLOCK_VERSION, block_contents1, &mut rng)
            .unwrap();

        // === Append a block with two MintTxs but only a single TxOut. ===
        let mint_tx1 = create_mint_tx(token_id1, &signers1, 10, &mut rng);
        let mint_tx2 = create_mint_tx(token_id1, &signers1, 10, &mut rng);

        let block_contents2 = BlockContents {
            mint_txs: vec![mint_tx1, mint_tx2],
            outputs: vec![create_test_tx_out(BLOCK_VERSION, &mut rng)],
            ..Default::default()
        };

        assert_eq!(
            add_block_contents_to_ledger(&mut ledger_db, BLOCK_VERSION, block_contents2, &mut rng),
            Err(Error::TooFewOutputs)
        );
    }

    #[test]
    // Appending a block that contains a previously-seen MintTx should fail.
    fn append_block_fails_for_duplicate_mint_txs() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let mut ledger_db = create_db();
        let token_id1 = TokenId::from(1);

        // === Create and append the origin block. ===
        add_origin_block(&mut ledger_db);

        // === Append a block wth a MintConfigTx transaction. This is needed since
        // the MintTx must be matched with an active mint config.
        let (mint_config_tx1, signers1) = create_mint_config_tx_and_signers(token_id1, &mut rng);

        let block_contents1 = BlockContents {
            validated_mint_config_txs: vec![to_validated(&mint_config_tx1)],
            ..Default::default()
        };
        add_block_contents_to_ledger(&mut ledger_db, BLOCK_VERSION, block_contents1, &mut rng)
            .unwrap();

        // === Append a block with only a single MintTx. ===
        let mint_tx1 = create_mint_tx(token_id1, &signers1, 10, &mut rng);

        let block_contents2 = BlockContents {
            mint_txs: vec![mint_tx1.clone()],
            outputs: vec![create_test_tx_out(BLOCK_VERSION, &mut rng)],
            ..Default::default()
        };

        add_block_contents_to_ledger(&mut ledger_db, BLOCK_VERSION, block_contents2, &mut rng)
            .unwrap();

        // === Append another block that includes the previous MintTx.
        let mint_tx2 = create_mint_tx(
            token_id1,
            &[
                Ed25519Pair::from(signers1[1].private_key()),
                Ed25519Pair::from(signers1[2].private_key()),
            ],
            20,
            &mut rng,
        );

        let block_contents3 = BlockContents {
            mint_txs: vec![mint_tx2, mint_tx1],
            outputs: vec![
                create_test_tx_out(BLOCK_VERSION, &mut rng),
                create_test_tx_out(BLOCK_VERSION, &mut rng),
            ],
            ..Default::default()
        };

        assert_eq!(
            add_block_contents_to_ledger(&mut ledger_db, BLOCK_VERSION, block_contents3, &mut rng),
            Err(Error::DuplicateMintTx)
        );
    }

    #[test]
    // Appending a block that contains a MintTx that does not reference any active
    // configuration should fail.
    fn append_block_fails_for_mint_tx_not_signed_by_active_configuration() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let mut ledger_db = create_db();
        let token_id1 = TokenId::from(1);

        // === Create and append the origin block. ===
        add_origin_block(&mut ledger_db);

        // === Append a block wth a MintConfigTx transaction. This is needed since
        // the MintTx must be matched with an active mint config.
        let (mint_config_tx1, _signers1) = create_mint_config_tx_and_signers(token_id1, &mut rng);

        let block_contents1 = BlockContents {
            validated_mint_config_txs: vec![to_validated(&mint_config_tx1)],
            ..Default::default()
        };

        add_block_contents_to_ledger(&mut ledger_db, BLOCK_VERSION, block_contents1, &mut rng)
            .unwrap();

        // === Append a block with only a single MintTx signed by an unknown signer. ===
        let mint_tx1 = create_mint_tx(
            token_id1,
            &[Ed25519Pair::from_random(&mut rng)],
            10,
            &mut rng,
        );

        let block_contents2 = BlockContents {
            mint_txs: vec![mint_tx1],
            outputs: vec![create_test_tx_out(BLOCK_VERSION, &mut rng)],
            ..Default::default()
        };

        assert_eq!(
            add_block_contents_to_ledger(&mut ledger_db, BLOCK_VERSION, block_contents2, &mut rng),
            Err(Error::NotFound)
        );
    }

    #[test]
    // Appending a block with a MintTx that exceeds the minting limit should fail.
    fn append_block_with_mint_tx_exceeding_mint_limit_should_fail() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let mut ledger_db = create_db();
        let token_id1 = TokenId::from(1);

        // === Create and append the origin block. ===
        let origin = add_origin_block(&mut ledger_db);

        let origin_tx_out = origin.contents().outputs[0].clone();
        assert_eq!(origin_tx_out, ledger_db.get_tx_out_by_index(0).unwrap());

        assert_eq!(ledger_db.get_active_mint_configs(token_id1).unwrap(), None,);

        // === Append a block wth a MintConfigTx transaction. This is needed since
        // the MintTx must be matched with an active mint config.
        let (mint_config_tx1, signers1) = create_mint_config_tx_and_signers(token_id1, &mut rng);

        let block_contents1 = BlockContents {
            validated_mint_config_txs: vec![to_validated(&mint_config_tx1)],
            ..Default::default()
        };
        add_block_contents_to_ledger(&mut ledger_db, BLOCK_VERSION, block_contents1, &mut rng)
            .unwrap();

        // === Append a block with only a single MintTx. ===
        let mint_tx1 = create_mint_tx(
            token_id1,
            &signers1,
            mint_config_tx1.prefix.configs[0].mint_limit - 10,
            &mut rng,
        );

        let block_contents2 = BlockContents {
            mint_txs: vec![mint_tx1.clone()],
            outputs: vec![create_test_tx_out(BLOCK_VERSION, &mut rng)],
            ..Default::default()
        };

        add_block_contents_to_ledger(&mut ledger_db, BLOCK_VERSION, block_contents2, &mut rng)
            .unwrap();

        // === Append another block with a MintTx that will exceed the mint limit, we
        // should fail.
        let mint_tx2 = create_mint_tx(
            token_id1,
            &[Ed25519Pair::from(signers1[0].private_key())], // Explicitly target the first config
            11,
            &mut rng,
        );

        let block_contents3 = BlockContents {
            mint_txs: vec![mint_tx2],
            outputs: vec![create_test_tx_out(BLOCK_VERSION, &mut rng)],
            ..Default::default()
        };

        assert_eq!(
            add_block_contents_to_ledger(&mut ledger_db, BLOCK_VERSION, block_contents3, &mut rng),
            Err(Error::MintLimitExceeded(
                11,
                mint_config_tx1.prefix.configs[0].mint_limit - 10,
                mint_config_tx1.prefix.configs[0].mint_limit
            ))
        );

        // Amount minted should not update.
        assert_eq!(
            ledger_db
                .get_active_mint_configs(token_id1)
                .unwrap()
                .unwrap()
                .configs,
            vec![
                ActiveMintConfig {
                    mint_config: mint_config_tx1.prefix.configs[0].clone(),
                    total_minted: mint_tx1.prefix.amount,
                },
                ActiveMintConfig {
                    mint_config: mint_config_tx1.prefix.configs[1].clone(),
                    total_minted: 0,
                },
                ActiveMintConfig {
                    mint_config: mint_config_tx1.prefix.configs[2].clone(),
                    total_minted: 0,
                },
            ]
        );

        // === Sanity: Allow the second mint configuration to match, which
        // should allow minting to succeeed.
        let mint_tx3 = create_mint_tx(token_id1, &signers1, 11, &mut rng);

        let block_contents3 = BlockContents {
            mint_txs: vec![mint_tx3],
            outputs: vec![create_test_tx_out(BLOCK_VERSION, &mut rng)],
            ..Default::default()
        };

        add_block_contents_to_ledger(&mut ledger_db, BLOCK_VERSION, block_contents3, &mut rng)
            .unwrap();

        // Amount minted should not update.
        assert_eq!(
            ledger_db
                .get_active_mint_configs(token_id1)
                .unwrap()
                .unwrap()
                .configs,
            vec![
                ActiveMintConfig {
                    mint_config: mint_config_tx1.prefix.configs[0].clone(),
                    total_minted: mint_tx1.prefix.amount,
                },
                ActiveMintConfig {
                    mint_config: mint_config_tx1.prefix.configs[1].clone(),
                    total_minted: 11,
                },
                ActiveMintConfig {
                    mint_config: mint_config_tx1.prefix.configs[2].clone(),
                    total_minted: 0,
                },
            ]
        );
    }

    #[test]
    // Appending an empty block should fail.
    fn append_block_fails_when_block_is_empty() {
        let mut ledger_db = create_db();

        // === Create and append the origin block. ===
        let origin = add_origin_block(&mut ledger_db);

        // === Attempt to append a block with no contents. ===
        let block_contents = Default::default();
        let block = Block::new_with_parent(
            BLOCK_VERSION,
            origin.block(),
            &Default::default(),
            &block_contents,
        );

        assert_eq!(
            ledger_db.append_block(&block, &block_contents, None, None),
            Err(Error::NoOutputs)
        );
    }

    #[test]
    // Appending a non-origin block should fail if the block contains no key images
    // and no minting transactions.
    fn append_block_fails_for_non_origin_non_minting_blocks_without_key_images() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let mut ledger_db = create_db();

        // === Create and append the origin block. ===
        add_origin_block(&mut ledger_db);

        // === Attempt to append a block without key images ===
        let outputs: Vec<TxOut> = (0..4)
            .map(|_i| create_test_tx_out(BLOCK_VERSION, &mut rng))
            .collect();

        let block_contents = BlockContents {
            outputs,
            ..Default::default()
        };

        assert_eq!(
            add_block_contents_to_ledger(&mut ledger_db, BLOCK_VERSION, block_contents, &mut rng),
            Err(Error::NoKeyImages)
        );
    }

    #[test]
    #[ignore]
    // A block that attempts a double spend should be rejected.
    fn reject_double_spend() {
        unimplemented!();
    }

    #[test]
    // `num_blocks` should return the correct number of blocks.
    fn num_blocks() {
        let mut ledger_db = create_db();
        assert_eq!(ledger_db.num_blocks().unwrap(), 0);
        let n_blocks = 7;
        populate_db(&mut ledger_db, n_blocks, 1);
        assert_eq!(ledger_db.num_blocks().unwrap(), n_blocks as u64);
    }

    #[test]
    // Getting a block by index should return the correct block, if it exists.
    fn get_block_by_index() {
        let mut ledger_db = create_db();
        let n_blocks = 43;
        let expected_blocks = populate_db(&mut ledger_db, n_blocks, 1);

        for (block_index, _) in expected_blocks.iter().enumerate().take(n_blocks) {
            let block = ledger_db
                .get_block(block_index as u64)
                .unwrap_or_else(|_| panic!("Could not get block {block_index:?}"));

            assert_eq!(&block, expected_blocks[block_index].block());
        }
    }

    #[test]
    // Getting block contents by index should return the correct block contents, if
    // that exists.
    fn get_block_contents_by_index() {
        let mut ledger_db = create_db();
        let n_blocks = 43;
        let expected_blocks = populate_db(&mut ledger_db, n_blocks, 1);

        for (block_index, _) in expected_blocks.iter().enumerate().take(n_blocks) {
            let block_contents = ledger_db
                .get_block_contents(block_index as u64)
                .unwrap_or_else(|_| panic!("Could not get block contents {block_index:?}"));

            let expected_block_contents = expected_blocks[block_index].contents();
            assert_eq!(&block_contents, expected_block_contents);
        }
    }

    #[test]
    // Getting a block by its index should return an error if the block doesn't
    // exist.
    fn get_block_by_index_doesnt_exist() {
        let mut ledger_db = create_db();
        let n_blocks = 43;
        populate_db(&mut ledger_db, n_blocks, 1);

        let out_of_range = 999;

        match ledger_db.get_block(out_of_range) {
            Ok(_block) => panic!("Should not return a block."),
            Err(Error::NotFound) => {
                // This is expected.
            }
            Err(e) => panic!("Unexpected error {e:?}"),
        }
    }

    #[test]
    // Getting a block number by tx out index should return the correct block
    // number, if it exists.
    fn get_block_index_by_tx_out_index() {
        let mut ledger_db = create_db();
        let n_blocks = 43;
        let blocks = populate_db(&mut ledger_db, n_blocks, 1);
        let expected = blocks.iter().map(BlockData::contents);

        for (block_index, block_contents) in expected.enumerate() {
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
    fn get_block_index_by_tx_out_index_doesnt_exist() {
        let mut ledger_db = create_db();
        let n_blocks = 43;
        populate_db(&mut ledger_db, n_blocks, 1);

        let out_of_range = 999;

        match ledger_db.get_block_index_by_tx_out_index(out_of_range) {
            Ok(_block_index) => panic!("Should not return a block index."),
            Err(Error::NotFound) => {
                // This is expected.
            }
            Err(e) => panic!("Unexpected error {e:?}"),
        }
    }

    #[test]
    // `Ledger::contains_key_image` should find key images that exist.
    fn contains_key_image() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let mut ledger_db = create_db();

        // The origin block can't contain key images.
        add_origin_block(&mut ledger_db);

        // Write the next block, containing several key images.
        let num_key_images = 3;
        let key_images: Vec<KeyImage> = (0..num_key_images)
            .map(|_i| KeyImage::from(rng.next_u64()))
            .collect();

        let tx_out = create_test_tx_out(BLOCK_VERSION, &mut rng);
        let outputs = vec![tx_out];
        add_txos_and_key_images_to_ledger(
            &mut ledger_db,
            BLOCK_VERSION,
            outputs,
            key_images.clone(),
            &mut rng,
        )
        .unwrap();

        // The ledger should each key image.
        for key_image in &key_images {
            assert!(ledger_db.contains_key_image(key_image).unwrap());
        }
    }

    #[test]
    // `get_key_images_by_block` should return the correct set of key images used in
    // a single block.
    fn get_key_images_by_block() {
        let mut ledger_db = create_db();
        let blocks = populate_db(&mut ledger_db, 3, 2);
        let expected_key_images = blocks[1].contents().key_images.clone();

        assert_eq!(
            expected_key_images,
            ledger_db.get_key_images_by_block(1).unwrap()
        );
    }

    #[test]
    /// Attempting to append an empty block should return Error::NoOutputs.
    fn append_empty_block() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let mut ledger_db = create_db();

        add_origin_block(&mut ledger_db);

        // Write the next block, containing several key images but no outputs.
        let num_key_images = 3;
        let key_images: Vec<KeyImage> = (0..num_key_images)
            .map(|_i| KeyImage::from(rng.next_u64()))
            .collect();

        let block_contents = BlockContents {
            key_images,
            ..Default::default()
        };

        assert_eq!(
            add_block_contents_to_ledger(&mut ledger_db, BLOCK_VERSION, block_contents, &mut rng),
            Err(Error::NoOutputs)
        );
    }

    #[test]
    /// Appending an block of incorrect version should return
    /// Error::InvalidBlockVersion.
    fn append_block_with_invalid_version() {
        let block_data = get_origin_block();
        let mut ledger_db = create_db();

        let mut block = block_data.block().clone();
        block.version = 1337;

        assert_eq!(
            ledger_db.append_block(&block, block_data.contents(), None, None),
            Err(Error::InvalidBlockVersion(block.version))
        );
    }

    #[test]
    /// Appending blocks that have ever-increasing and continous version numbers
    /// should work as long as it is <= MAX_BLOCK_VERSION.
    /// Appending a block > MAX_BLOCK_VERSION should fail even if it is after a
    /// block with version == MAX_BLOCK_VERSION.
    /// Appending a block with a version < last block's version should fail.
    fn append_block_with_version_bumps() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let mut ledger_db = create_db();

        add_origin_block(&mut ledger_db);

        // MAX_BLOCK_VERSION sets the current max block version
        for block_version in BlockVersion::iterator() {
            // In each iteration we add a few blocks with the same version.
            for _ in 0..3 {
                let outputs: Vec<TxOut> = (0..4)
                    .map(|_i| create_test_tx_out(BLOCK_VERSION, &mut rng))
                    .collect();
                let key_images: Vec<KeyImage> =
                    (0..5).map(|_i| KeyImage::from(rng.next_u64())).collect();
                add_txos_and_key_images_to_ledger(
                    &mut ledger_db,
                    block_version,
                    outputs,
                    key_images,
                    &mut rng,
                )
                .unwrap();
            }

            // All blocks should've been written (+ origin block).
            assert_eq!(
                ledger_db.num_blocks().unwrap(),
                1 + (3 * (*block_version + 1)) as u64
            );
        }

        // Last block version should be what we expect.
        let last_block = ledger_db
            .get_block(ledger_db.num_blocks().unwrap() - 1)
            .unwrap();
        assert_eq!(last_block.version, *MAX_BLOCK_VERSION);

        // Appending a block with version < previous block version should fail.
        {
            let outputs: Vec<TxOut> = (0..4)
                .map(|_i| create_test_tx_out(BLOCK_VERSION, &mut rng))
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
                ledger_db.append_block(&invalid_block, &block_contents, None, None),
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
                    ledger_db.append_block(&invalid_block, &block_contents, None, None),
                    Err(Error::InvalidBlockVersion(invalid_block.version))
                );
            }
        }
    }

    #[test]
    fn append_block_requires_metadata() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let mut ledger_db = create_db();

        let origin = add_origin_block(&mut ledger_db);
        let mut last_block = origin.block().clone();

        // MAX_BLOCK_VERSION sets the current max block version
        for block_version in BlockVersion::iterator() {
            // In each iteration we add a few blocks with the same version.
            for _ in 0..3 {
                let outputs: Vec<TxOut> = (0..4)
                    .map(|_i| create_test_tx_out(block_version, &mut rng))
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

                let metadata = make_block_metadata(last_block.id.clone(), &mut rng);

                let result = ledger_db.append_block(&last_block, &block_contents, None, None);

                if block_version.require_block_metadata() {
                    assert_eq!(result, Err(Error::BlockMetadataRequired));
                    ledger_db
                        .append_block(&last_block, &block_contents, None, Some(&metadata))
                        .unwrap();
                } else {
                    result.unwrap();
                }
            }

            // All blocks should've been written (+ origin block).
            assert_eq!(
                ledger_db.num_blocks().unwrap(),
                1 + (3 * (*block_version + 1)) as u64
            );
        }
    }

    #[test]
    fn append_block_at_wrong_location() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let mut ledger_db = create_db();

        // initialize a ledger with 3 blocks.
        let n_blocks = 3;
        let blocks = populate_db(&mut ledger_db, n_blocks, 2);
        let origin = blocks[0].block();
        assert_eq!(ledger_db.num_blocks().unwrap(), n_blocks as u64);

        let key_images = vec![KeyImage::from(rng.next_u64())];

        let tx_out = create_test_tx_out(BLOCK_VERSION, &mut rng);

        let outputs = vec![tx_out];
        let block_contents = BlockContents {
            key_images,
            outputs,
            ..Default::default()
        };

        // Appending a block to a previously written location should fail.
        let mut new_block = Block::new(
            BLOCK_VERSION,
            &origin.id,
            1,
            origin.cumulative_txo_count,
            &Default::default(),
            &block_contents,
        );
        assert_eq!(
            ledger_db.append_block(&new_block, &block_contents, None, None),
            Err(Error::InvalidBlockIndex(new_block.index))
        );

        // Appending a non-contiguous location should fail.
        new_block.index += n_blocks as u64;
        assert_eq!(
            ledger_db.append_block(&new_block, &block_contents, None, None),
            Err(Error::InvalidBlockIndex(new_block.index))
        );
    }

    #[test]
    /// Appending a block with a spent key image should return
    /// Error::KeyImageAlreadySpent.
    fn append_block_with_spent_key_image() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let mut ledger_db = create_db();

        add_origin_block(&mut ledger_db);

        // Write the next block, containing several key images.
        let num_key_images = 3;
        let block_one_key_images: Vec<KeyImage> = (0..num_key_images)
            .map(|_i| KeyImage::from(rng.next_u64()))
            .collect();

        add_txos_and_key_images_to_ledger(
            &mut ledger_db,
            BLOCK_VERSION,
            vec![create_test_tx_out(BLOCK_VERSION, &mut rng)],
            block_one_key_images.clone(),
            &mut rng,
        )
        .unwrap();

        // The next block reuses a key image.
        assert_eq!(
            add_txos_and_key_images_to_ledger(
                &mut ledger_db,
                BLOCK_VERSION,
                vec![create_test_tx_out(BLOCK_VERSION, &mut rng)],
                block_one_key_images,
                &mut rng,
            ),
            Err(Error::KeyImageAlreadySpent)
        );
    }

    #[test]
    /// Appending a block with a pre-existing output public key should return
    /// Error::DuplicateOutputPublicKey.
    fn append_block_with_duplicate_output_public_key() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let mut ledger_db = create_db();

        let origin = add_origin_block(&mut ledger_db);

        // The next block reuses a public key.
        let existing_tx_out = ledger_db.get_tx_out_by_index(0).unwrap();

        let block_one_contents = {
            let mut tx_out = create_test_tx_out(BLOCK_VERSION, &mut rng);
            tx_out.public_key = existing_tx_out.public_key;
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
            origin.block(),
            &Default::default(),
            &block_one_contents,
        );

        assert_eq!(
            ledger_db.append_block(&block_one, &block_one_contents, None, None),
            Err(Error::DuplicateOutputPublicKey)
        );
    }

    #[test]
    // append_block rejects invalid blocks.
    fn append_invalid_blocks() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let mut ledger_db = create_db();

        let origin = get_origin_block();

        // append_block rejects a block with invalid id.
        {
            let mut block = origin.block().clone();
            block.id.0[0] += 1;
            assert_eq!(
                ledger_db.append_block(&block, origin.contents(), None, None),
                Err(Error::InvalidBlockID(block.id.clone()))
            );
        }

        // append_block rejects a block with invalid contents hash.
        {
            let mut block = origin.block().clone();
            block.contents_hash.0[0] += 1;
            assert_eq!(
                ledger_db.append_block(&block, origin.contents(), None, None),
                Err(Error::InvalidBlockContents)
            );
        }

        assert_eq!(ledger_db.append_block_data(&origin), Ok(()));

        // append_block rejects a block with non-existent parent.
        {
            let tx_out = create_test_tx_out(BLOCK_VERSION, &mut rng);

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
                origin.block().cumulative_txo_count,
                &Default::default(),
                &block_contents,
            );

            assert_eq!(
                ledger_db.append_block(&block_one_bad, &block_contents, None, None),
                Err(Error::InvalidParentBlockID(block_one_bad.parent_id.clone()))
            );

            // This block correctly has block zero as its parent.
            let block_one_good = Block::new(
                BLOCK_VERSION,
                &origin.block().id,
                1,
                origin.block().cumulative_txo_count,
                &Default::default(),
                &block_contents,
            );

            assert_eq!(
                ledger_db.append_block(&block_one_good, &block_contents, None, None),
                Ok(())
            );
        }
    }

    #[test]
    // ledger.num_txos agrees with the computed block header values
    fn double_check_num_txos() {
        let mut ledger_db = create_db();

        // Get some random blocks
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let results = get_blocks(BLOCK_VERSION, 25, 3, 1, 1, 42, None, &mut rng);

        for block_data in results {
            ledger_db
                .append_block_data(&block_data)
                .expect("failed to write block data");
            assert_eq!(
                block_data.block().cumulative_txo_count,
                ledger_db.num_txos().unwrap()
            );
        }
    }

    #[test]
    // ledger_db.get_root_tx_out_membership_element returns the correct element
    fn get_root_tx_out_membership_element_returns_correct_element() {
        let mut ledger_db = create_db();
        // Add some random blocks
        populate_db(&mut ledger_db, 42, 3);

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
        populate_db(&mut ledger_db, n_blocks, n_txs_per_block);

        b.iter(|| ledger_db.num_blocks().unwrap())
    }

    #[bench]
    #[ignore]
    fn bench_get_block(b: &mut Bencher) {
        let mut ledger_db = create_db();
        let n_blocks = 30;
        let n_txs_per_block = 1000;
        populate_db(&mut ledger_db, n_blocks, n_txs_per_block);
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

        b.iter(|| {
            ledger_db
                .get_block(rng.next_u64() % n_blocks as u64)
                .unwrap()
        })
    }
}
