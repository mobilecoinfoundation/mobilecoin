// Copyright (c) 2018-2021 The MobileCoin Foundation

//! An store object for managing storage of BlockData objects in the database,
//! while taking care of de-duplicating contents when possible.

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

/// BlockContents by hash database name.
pub const BLOCK_CONTENTS_BY_HASH_DB_NAME: &str = "watcher_db:block_data:block_contents_by_hash";

/// An internal object for representing BlockData that doesn't hold the actual
/// Block and BlockContents since those might be shared with other blocks.
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
    /// Blocks data database. Indexed by (block index, tx_src_url) and maps into
    /// a StoredBlockData object
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

    /// Add a single BlockData that was fetched from `src_url` into the
    /// database.
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

        match db_txn.put(
            self.block_datas_by_index,
            &key_bytes,
            &value_bytes,
            WriteFlags::NO_OVERWRITE,
        ) {
            Ok(()) => Ok(()),
            Err(lmdb::Error::KeyExist) => Err(WatcherDBError::AlreadyExists),
            Err(err) => Err(err.into()),
        }
    }

    /// Get BlockData for a given block index provided by a specific tx source
    /// url.
    pub fn get_block_data(
        &self,
        db_txn: &impl Transaction,
        src_url: &Url,
        block_index: BlockIndex,
    ) -> Result<BlockData, WatcherDBError> {
        let mut key_bytes = block_index.to_be_bytes().to_vec();
        key_bytes.extend(src_url.as_str().as_bytes());

        let stored_block_data_bytes = match db_txn.get(self.block_datas_by_index, &key_bytes) {
            Ok(bytes) => Ok(bytes),
            Err(lmdb::Error::NotFound) => Err(WatcherDBError::NotFound),
            Err(err) => Err(err.into()),
        }?;

        let stored_block_data: StoredBlockData = decode(&stored_block_data_bytes)?;

        let block = self.get_block_by_hash(db_txn, &stored_block_data.block_hash)?;
        let block_contents =
            self.get_block_contents_by_hash(db_txn, &stored_block_data.block_contents_hash)?;

        Ok(BlockData::new(
            block,
            block_contents,
            stored_block_data.signature,
        ))
    }

    /// Get all known BlockDatas for a given block index, mapped by tx source
    /// url.
    pub fn get_block_data_map(
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

    /// Remove all block data associated with a given source url.
    /// Note that this assumes blocks where added in a sequential order, and
    /// that there are no gaps (no blocks were skipped).
    /// It does not remove Block/BlockContents as those might be shared with
    /// other source URLs.
    pub fn remove_all_for_source_url<'env>(
        &self,
        db_txn: &mut RwTransaction<'env>,
        src_url: &Url,
        last_synced_block_index: u64,
    ) -> Result<(), WatcherDBError> {
        let mut block_index: u64 = 0;
        loop {
            let mut key_bytes = block_index.to_be_bytes().to_vec();
            key_bytes.extend(src_url.as_str().as_bytes());

            match db_txn.del(self.block_datas_by_index, &key_bytes, None) {
                Ok(()) => {}
                Err(lmdb::Error::NotFound) => {
                    if block_index > last_synced_block_index {
                        break;
                    }
                }
                Err(err) => {
                    return Err(err.into());
                }
            }

            block_index += 1;
        }

        Ok(())
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
            .map_err(WatcherDBError::from)
            .and_then(|bytes| decode(bytes).map_err(WatcherDBError::from))
    }

    fn get_block_contents_by_hash(
        &self,
        db_txn: &impl Transaction,
        hash: &[u8],
    ) -> Result<BlockContents, WatcherDBError> {
        db_txn
            .get(self.block_contents_by_hash, &hash)
            .map_err(WatcherDBError::from)
            .and_then(|bytes| decode(bytes).map_err(WatcherDBError::from))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::watcher_db::tests::{setup_blocks, setup_watcher_db};
    use mc_common::logger::{test_with_logger, Logger};
    use mc_crypto_keys::Ed25519Pair;
    use mc_util_from_random::FromRandom;
    use rand_core::SeedableRng;
    use rand_hc::Hc128Rng;
    use std::iter::FromIterator;

    #[test_with_logger]
    fn block_data_store_happy_path(logger: Logger) {
        let mut rng: Hc128Rng = Hc128Rng::from_seed([8u8; 32]);
        let tx_src_url1 = Url::parse("http://www.my_url1.com").unwrap();
        let tx_src_url2 = Url::parse("http://www.my_url2.com").unwrap();
        let tx_src_urls = vec![tx_src_url1.clone(), tx_src_url2.clone()];
        let watcher_db = setup_watcher_db(&tx_src_urls, logger);
        let blocks = setup_blocks();

        let block_datas = blocks
            .iter()
            .map(|(block, contents)| {
                BlockData::new(
                    block.clone(),
                    contents.clone(),
                    Some(
                        BlockSignature::from_block_and_keypair(
                            block,
                            &Ed25519Pair::from_random(&mut rng),
                        )
                        .unwrap(),
                    ),
                )
            })
            .collect::<Vec<_>>();

        // Initially, there is no data.
        for block_data in block_datas.iter() {
            assert_eq!(
                watcher_db
                    .get_block_data_map(block_data.block().index)
                    .unwrap(),
                HashMap::default()
            );
        }

        // Add a block to tx_src_url1 and see that we can get it.
        watcher_db
            .add_block_data(&tx_src_url1, &block_datas[0])
            .unwrap();

        assert_eq!(
            watcher_db
                .get_block_data_map(block_datas[0].block().index)
                .unwrap(),
            HashMap::from_iter(vec![(tx_src_url1.clone(), block_datas[0].clone()),])
        );
        assert_eq!(
            watcher_db
                .get_block_data_map(block_datas[1].block().index)
                .unwrap(),
            HashMap::default()
        );

        // Add the same block but for a different URL.
        watcher_db
            .add_block_data(&tx_src_url2, &block_datas[0])
            .unwrap();

        assert_eq!(
            watcher_db
                .get_block_data_map(block_datas[0].block().index)
                .unwrap(),
            HashMap::from_iter(vec![
                (tx_src_url1.clone(), block_datas[0].clone()),
                (tx_src_url2.clone(), block_datas[0].clone()),
            ])
        );
        assert_eq!(
            watcher_db
                .get_block_data_map(block_datas[1].block().index)
                .unwrap(),
            HashMap::default()
        );

        // Add the same block again (should error).
        assert!(watcher_db
            .add_block_data(&tx_src_url2, &block_datas[0])
            .is_err());

        // Add another block.
        watcher_db
            .add_block_data(&tx_src_url2, &block_datas[1])
            .unwrap();

        assert_eq!(
            watcher_db
                .get_block_data_map(block_datas[0].block().index)
                .unwrap(),
            HashMap::from_iter(vec![
                (tx_src_url1.clone(), block_datas[0].clone()),
                (tx_src_url2.clone(), block_datas[0].clone()),
            ])
        );
        assert_eq!(
            watcher_db
                .get_block_data_map(block_datas[1].block().index)
                .unwrap(),
            HashMap::from_iter(vec![(tx_src_url2.clone(), block_datas[1].clone()),])
        );
    }
}
