// Copyright (c) 2018-2021 The MobileCoin Foundation

//! An store object for managing storage of BlockData objects in the database, while taking care of
//! de-duplicating contents when possible.

use crate::error::WatcherDBError;
use lmdb::{Cursor, Database, DatabaseFlags, Environment, RwTransaction, Transaction, WriteFlags};
use mc_common::{
    logger::{log, Logger},
    HashMap,
};
use mc_crypto_digestible::{Digestible, MerlinTranscript};
use mc_transaction_core::{Block, BlockContents, BlockData, BlockIndex, BlockSignature};
use mc_util_serial::{decode, encode};
use prost::Message;
use std::{str::FromStr, sync::Arc};
use url::Url;

/// Block datas database name.
pub const BLOCK_DATAS_BY_INDEX_DB_NAME: &str = "watcher_db:block_data:blocks_datas_by_index";

/// Blocks by hash database name.
pub const BLOCKS_BY_HASH_DB_NAME: &str = "watcher_db:block_data:blocks_by_hash";

/// BlockContentss by hash database name.
pub const BLOCK_CONTENTS_BY_HASH_DB_NAME: &str = "watcher_db:block_data:block_contents_by_hash";

/// An internal object for representing BlockData that doesn't hold the actual Block and
/// BlockContents since those might be shared with other blocks.
#[derive(Clone, Message)]
pub struct StoredBlockData {
    /// 32 bytes hash of Block.
    #[prost(bytes, required, tag = "1")]
    pub block_hash: Vec<u8>,

    /// 32 bytes hash of BlockContent.
    #[prost(bytes, required, tag = "2")]
    pub block_contents_hash: Vec<u8>,

    /// Block signature (optional).
    // The signature is unique (we do not expect to encounter duplicate signatures)
    // so we store it inside here.
    #[prost(message, tag = "3")]
    pub signature: Option<BlockSignature>,
}

/// Object for managing the storage of BlockDatas.
#[derive(Clone)]
pub struct BlockDataStore {
    /// Blocks data database. Indexed by (block index, tx_src_url) and maps into a StoredBlockData object
    block_datas_by_index: Database,

    /// Block hash -> Block.
    blocks_by_hash: Database,

    /// BlockContents hash -> BlockContents
    block_contents_by_hash: Database,

    /// Logger.
    logger: Logger,
}

impl BlockDataStore {
    /// Create a new BlockDataStore instance.
    pub fn new(env: Arc<Environment>, logger: Logger) -> Result<Self, WatcherDBError> {
        let block_datas_by_index = env.open_db(Some(BLOCK_DATAS_BY_INDEX_DB_NAME))?;
        let blocks_by_hash = env.open_db(Some(BLOCKS_BY_HASH_DB_NAME))?;
        let block_contents_by_hash = env.open_db(Some(BLOCK_CONTENTS_BY_HASH_DB_NAME))?;
        Ok(Self {
            block_datas_by_index,
            blocks_by_hash,
            block_contents_by_hash,
            logger,
        })
    }

    /// Setup the required databases in the LMDB file.
    pub fn create(env: Arc<Environment>) -> Result<(), WatcherDBError> {
        env.create_db(Some(BLOCK_DATAS_BY_INDEX_DB_NAME), DatabaseFlags::empty())?;
        env.create_db(Some(BLOCKS_BY_HASH_DB_NAME), DatabaseFlags::empty())?;
        env.create_db(Some(BLOCK_CONTENTS_BY_HASH_DB_NAME), DatabaseFlags::empty())?;
        Ok(())
    }

    /// Add a single BlockData that was fetched from `src_url` into the database.
    pub fn add_block_data<'env>(
        &self,
        db_txn: &mut RwTransaction<'env>,
        src_url: &Url,
        block_data: &BlockData,
    ) -> Result<(), WatcherDBError> {
        let block_hash = self.store_block(db_txn, block_data.block())?;
        let block_contents_hash = self.store_block_contents(db_txn, block_data.contents())?;

        let stored_block_data = StoredBlockData {
            block_hash,
            block_contents_hash,
            signature: block_data.signature().clone(),
        };

        let mut key_bytes = block_data.block().index.to_be_bytes().to_vec();
        key_bytes.extend(src_url.as_str().as_bytes());

        let value_bytes = encode(&stored_block_data);

        log::debug!(
            self.logger,
            "Storing block data for {}@{}: {} bytes",
            block_data.block().index,
            src_url,
            value_bytes.len()
        );

        db_txn.put(
            self.block_datas_by_index,
            &key_bytes,
            &value_bytes,
            WriteFlags::NO_OVERWRITE,
        )?;

        Ok(())
    }

    /// Get all known BlockDatas for a given block index, mapped by tx source url.
    pub fn get_block_data(
        &self,
        db_txn: &impl Transaction,
        block_index: BlockIndex,
    ) -> Result<HashMap<Url, BlockData>, WatcherDBError> {
        let mut cursor = db_txn.open_ro_cursor(self.block_datas_by_index)?;
        let first_key_bytes = block_index.to_be_bytes();

        let mut results = HashMap::default();
        for (key_bytes, value_bytes) in cursor.iter_from(&first_key_bytes).filter_map(Result::ok) {
            // Try and get the index and tx source url from the database key.
            // Remember that the key is the block index , followed by the source url.
            if key_bytes.len() < first_key_bytes.len() {
                continue;
            }

            let index_bytes = &key_bytes[..first_key_bytes.len()];
            if index_bytes != first_key_bytes {
                // Moved to the next index, we're done.
                break;
            }

            let tx_source_url_bytes = &key_bytes[first_key_bytes.len()..];
            let tx_source_url = Url::from_str(&String::from_utf8(tx_source_url_bytes.to_vec())?)?;

            // Get the StoredBlockData.
            let stored_block_data: StoredBlockData = decode(value_bytes)?;

            let block = self.get_block_by_hash(db_txn, &stored_block_data.block_hash)?;
            let block_contents =
                self.get_block_contents_by_hash(db_txn, &stored_block_data.block_contents_hash)?;

            results.insert(
                tx_source_url,
                BlockData::new(block, block_contents, stored_block_data.signature),
            );
        }

        Ok(results)
    }

    fn store_block<'env>(
        &self,
        db_txn: &mut RwTransaction<'env>,
        block: &Block,
    ) -> Result<Vec<u8>, WatcherDBError> {
        let hash = block.digest32::<MerlinTranscript>(b"block").to_vec();

        match db_txn.put(
            self.blocks_by_hash,
            &hash,
            &encode(block),
            WriteFlags::NO_OVERWRITE,
        ) {
            Ok(()) => Ok(hash),
            Err(lmdb::Error::KeyExist) => Ok(hash),
            Err(err) => Err(err.into()),
        }
    }

    fn store_block_contents<'env>(
        &self,
        db_txn: &mut RwTransaction<'env>,
        block_contents: &BlockContents,
    ) -> Result<Vec<u8>, WatcherDBError> {
        let hash: Vec<u8> = block_contents.hash().as_ref().to_vec();

        match db_txn.put(
            self.block_contents_by_hash,
            &hash,
            &encode(block_contents),
            WriteFlags::NO_OVERWRITE,
        ) {
            Ok(()) => Ok(hash),
            Err(lmdb::Error::KeyExist) => Ok(hash),
            Err(err) => Err(err.into()),
        }
    }

    fn get_block_by_hash(
        &self,
        db_txn: &impl Transaction,
        hash: &[u8],
    ) -> Result<Block, WatcherDBError> {
        db_txn
            .get(self.blocks_by_hash, &hash)
            .map_err(|err| WatcherDBError::from(err))
            .and_then(|bytes| decode(bytes).map_err(|err| WatcherDBError::from(err)))
    }

    fn get_block_contents_by_hash(
        &self,
        db_txn: &impl Transaction,
        hash: &[u8],
    ) -> Result<BlockContents, WatcherDBError> {
        db_txn
            .get(self.block_contents_by_hash, &hash)
            .map_err(|err| WatcherDBError::from(err))
            .and_then(|bytes| decode(bytes).map_err(|err| WatcherDBError::from(err)))
    }
}
