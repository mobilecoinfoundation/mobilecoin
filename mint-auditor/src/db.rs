// Copyright (c) 2018-2022 The MobileCoin Foundation

//! LMDB database abstraction.

use crate::Error;
use lmdb::{
    Database, DatabaseFlags, Environment, EnvironmentFlags, RwTransaction, Transaction, WriteFlags,
};
use mc_account_keys::burn_address_view_private;
use mc_common::logger::{log, Logger};
use mc_ledger_db::u64_to_key_bytes;
use mc_transaction_core::{Block, BlockContents, BlockIndex};
use mc_util_lmdb::{MetadataStore, MetadataStoreSettings};
use mc_util_serial::{decode, encode, Message};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, path::Path, sync::Arc};

/// Max LMDB file size.
const MAX_LMDB_FILE_SIZE: usize = 1_099_511_627_776; // 1 TB

/// Number of LMDB databases.
const NUM_LMDB_DATABASES: u32 = 3;

/// Metadata store settings that are used for version control.
#[derive(Clone, Default, Debug)]
pub struct WatcherDbMetadataStoreSettings;
impl MetadataStoreSettings for WatcherDbMetadataStoreSettings {
    // Default database version. This should be bumped when breaking changes are
    // introduced. If this is properly maintained, we could check during
    // db opening for any incompatibilities, and either refuse to open or
    // perform a migration.
    #[allow(clippy::inconsistent_digit_grouping)]
    const LATEST_VERSION: u64 = 2022_03_28;

    /// The current crate version that manages the database.
    const CRATE_VERSION: &'static str = env!("CARGO_PKG_VERSION");

    /// LMDB Database name to use for storing the metadata information.
    const DB_NAME: &'static str = "mint_auditor_db_metadata";
}

/// LMDB database names.
pub const KEY_VAL_DB_NAME: &str = "mint_auditor_db:key_val";
pub const MINT_AUDIT_DATA_BY_BLOCK_INDEX_DB_NAME: &str =
    "mint_auditor_db:mint_audit_data_by_block_index";

/// Keys used by the `key_val` database.
pub const COUNTERS_KEY: &str = "counters";

/// Mint audit data that we store per block.
#[derive(Deserialize, Eq, Message, PartialEq, Serialize)]
pub struct BlockAuditData {
    /// A map of token id -> calculated balance.
    #[prost(btree_map = "uint32, uint64", tag = 1)]
    pub balance_map: BTreeMap<u32, u64>,
}

#[derive(Deserialize, Eq, Message, PartialEq, Serialize)]
pub struct Counters {
    /// Number of blocks we've synced so far.
    #[prost(uint64, tag = 1)]
    pub num_blocks_synced: u64,

    // Number of times we've encountered a burn that exceeds the calculated balance.
    #[prost(uint64, tag = 2)]
    pub num_burns_exceeding_balance: u64,
}

/// Mint Auditor Database.
#[derive(Clone)]
pub struct MintAuditorDb {
    /// LMDB Environment (database).
    env: Arc<Environment>,

    /// General-purpose key-value store.
    /// * `COUNTERS`: A serialized `Counters` object.
    key_val: Database,

    /// block index -> BlockAuditData database.
    mint_audit_data_by_block_index: Database,

    /// Logger.
    logger: Logger,
}

impl MintAuditorDb {
    /// Opens a database previously created by `create`.
    pub fn open(path: &impl AsRef<Path>, logger: Logger) -> Result<Self, Error> {
        let env = Arc::new(
            Environment::new()
                .set_max_dbs(NUM_LMDB_DATABASES)
                .set_map_size(MAX_LMDB_FILE_SIZE)
                // TODO - needed because currently our test cloud machines have slow disks.
                .set_flags(EnvironmentFlags::NO_SYNC)
                .open(path.as_ref())?,
        );

        let metadata_store = MetadataStore::<WatcherDbMetadataStoreSettings>::new(&env)?;

        let db_txn = env.begin_ro_txn()?;
        let version = metadata_store.get_version(&db_txn)?;
        log::info!(
            logger,
            "Mint audtor db is currently at version: {:?}",
            version
        );
        db_txn.commit()?;

        let key_val = env.open_db(Some(KEY_VAL_DB_NAME))?;
        let mint_audit_data_by_block_index =
            env.open_db(Some(MINT_AUDIT_DATA_BY_BLOCK_INDEX_DB_NAME))?;

        Ok(Self {
            env,
            key_val,
            mint_audit_data_by_block_index,
            logger,
        })
    }

    /// Create an empty database.
    pub fn create(path: &impl AsRef<Path>) -> Result<(), Error> {
        let env = Arc::new(
            Environment::new()
                .set_max_dbs(NUM_LMDB_DATABASES)
                .set_map_size(MAX_LMDB_FILE_SIZE)
                // TODO - needed because currently our test cloud machines have slow disks.
                .set_flags(EnvironmentFlags::NO_SYNC)
                .open(path.as_ref())?,
        );

        MetadataStore::<WatcherDbMetadataStoreSettings>::create(&env)?;

        env.create_db(Some(KEY_VAL_DB_NAME), DatabaseFlags::empty())?;
        env.create_db(
            Some(MINT_AUDIT_DATA_BY_BLOCK_INDEX_DB_NAME),
            DatabaseFlags::DUP_SORT,
        )?;
        Ok(())
    }

    /// Open an existing database, or create one if it does not already exist.
    pub fn create_or_open(path: &impl AsRef<Path>, logger: Logger) -> Result<Self, Error> {
        if !path.as_ref().exists() {
            std::fs::create_dir_all(path)?;
        }

        // Attempt to open the database and see if it has anything in it.
        if let Ok(db) = Self::open(path, logger.clone()) {
            if db.last_synced_block_index()?.is_some() {
                // Successfully opened a database that has something in it.
                return Ok(db);
            }
        }

        // DB doesn't exist or is empty.
        Self::create(path)?;
        Self::open(path, logger)
    }

    /// Get all counters.
    pub fn get_counters(&self) -> Result<Counters, Error> {
        let db_txn = self.env.begin_ro_txn()?;
        self.get_counters_impl(&db_txn)
    }

    /// Get the last synced block index, or None if no blocks were synced.
    pub fn last_synced_block_index(&self) -> Result<Option<u64>, Error> {
        match self.get_counters()?.num_blocks_synced {
            0 => Ok(None),
            val => Ok(Some(val - 1)),
        }
    }

    /// Get the audit data for a given block index.
    pub fn get_block_audit_data(&self, block_index: BlockIndex) -> Result<BlockAuditData, Error> {
        let db_txn = self.env.begin_ro_txn()?;
        self.get_block_audit_data_impl(block_index, &db_txn)
    }

    /// Sync mint data from a given block.
    pub fn sync_block(
        &self,
        block: &Block,
        block_contents: &BlockContents,
    ) -> Result<BlockAuditData, Error> {
        let mut db_txn = self.env.begin_rw_txn()?;

        let block_index = block.index;
        log::info!(self.logger, "Syncing block {}", block_index);

        let mut counters = self.get_counters_impl(&db_txn)?;

        // Ensure that we are syncing the next block and haven't skipped any blocks (or
        // went backwards).
        let next_block_index = counters.num_blocks_synced;
        if block_index != next_block_index {
            return Err(Error::UnexpectedBlockIndex(block_index, next_block_index));
        }

        // Get the audit data for the previous block.
        let mut block_audit_data = if block_index == 0 {
            BlockAuditData::default()
        } else {
            self.get_block_audit_data_impl(block_index - 1, &db_txn)?
        };

        // Count mints.
        for mint_tx in &block_contents.mint_txs {
            let balance = block_audit_data
                .balance_map
                .entry(mint_tx.prefix.token_id)
                .or_default();

            *balance += mint_tx.prefix.amount;
            log::info!(
                self.logger,
                "Block {}: Minted {} of token id {}, balance is now {}",
                block_index,
                mint_tx.prefix.amount,
                mint_tx.prefix.token_id,
                balance,
            );
        }

        // Count burns.
        for tx_out in &block_contents.outputs {
            if let Ok((amount, _)) = tx_out.view_key_match(&burn_address_view_private()) {
                let balance = block_audit_data
                    .balance_map
                    .entry(*amount.token_id)
                    .or_default();

                if amount.value > *balance {
                    log::crit!(
                        self.logger,
                        "Block {}: Burned {} of token id {} but only had {}. Setting balance to 0",
                        block_index,
                        amount.value,
                        amount.token_id,
                        balance
                    );
                    *balance = 0;
                    counters.num_burns_exceeding_balance += 1;
                } else {
                    *balance -= amount.value;
                    log::info!(
                        self.logger,
                        "Block {}: Burned {} of token id {}, balance is now {}",
                        block_index,
                        amount.value,
                        amount.token_id,
                        balance,
                    );
                }
            }
        }

        // Update the database.
        db_txn.put(
            self.mint_audit_data_by_block_index,
            &u64_to_key_bytes(block_index),
            &encode(&block_audit_data),
            WriteFlags::NO_OVERWRITE,
        )?;

        counters.num_blocks_synced += 1;
        self.set_counters_impl(&counters, &mut db_txn)?;

        db_txn.commit()?;

        // Success.
        Ok(block_audit_data)
    }

    fn get_block_audit_data_impl(
        &self,
        block_index: BlockIndex,
        db_txn: &impl Transaction,
    ) -> Result<BlockAuditData, Error> {
        let bytes = db_txn.get(
            self.mint_audit_data_by_block_index,
            &u64_to_key_bytes(block_index),
        )?;
        Ok(decode(bytes)?)
    }

    fn get_counters_impl(&self, db_txn: &impl Transaction) -> Result<Counters, Error> {
        match db_txn.get(self.key_val, &COUNTERS_KEY) {
            Ok(bytes) => Ok(decode(bytes)?),
            Err(lmdb::Error::NotFound) => Ok(Counters::default()),
            Err(err) => Err(err.into()),
        }
    }

    fn set_counters_impl<'env>(
        &self,
        counters: &Counters,
        db_txn: &mut RwTransaction<'env>,
    ) -> Result<(), Error> {
        db_txn.put(
            self.key_val,
            &COUNTERS_KEY,
            &encode(counters),
            WriteFlags::empty(),
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mc_account_keys::{burn_address, AccountKey};
    use mc_common::logger::{test_with_logger, Logger};
    use mc_crypto_keys::RistrettoPrivate;
    use mc_ledger_db::Ledger;
    use mc_transaction_core::{tx::TxOut, Amount, BlockVersion, TokenId};
    use mc_transaction_core_test_utils::{
        create_ledger, create_mint_config_tx_and_signers, create_mint_tx, create_test_tx_out,
        initialize_ledger,
    };
    use mc_util_from_random::FromRandom;
    use rand_core::SeedableRng;
    use rand_hc::Hc128Rng;
    use std::iter::FromIterator;
    use tempfile::tempdir;

    #[test_with_logger]
    fn test_sync_block_happy_flow(logger: Logger) {
        let mut rng = Hc128Rng::from_seed([1u8; 32]);
        let token_id1 = TokenId::from(1);
        let token_id2 = TokenId::from(22);
        let token_id3 = TokenId::from(3);

        let mint_audit_db_path = tempdir().unwrap();
        let mint_audit_db = MintAuditorDb::create_or_open(&mint_audit_db_path, logger).unwrap();

        let mut ledger_db = create_ledger();
        let account_key = AccountKey::random(&mut rng);
        let initial_num_blocks = 3;
        initialize_ledger(
            BlockVersion::MAX,
            &mut ledger_db,
            initial_num_blocks,
            &account_key,
            &mut rng,
        );

        // The blocks we currently have in the ledger contain no burning or minting.
        for block_index in 0..initial_num_blocks {
            let block_data = ledger_db.get_block_data(block_index).unwrap();

            let mint_audit_data = mint_audit_db
                .sync_block(block_data.block(), block_data.contents())
                .unwrap();

            assert_eq!(mint_audit_data, BlockAuditData::default());
        }

        // Sync a block that contains a few mint transactions.
        let (_mint_config_tx1, signers1) = create_mint_config_tx_and_signers(token_id1, &mut rng);
        let (_mint_config_tx2, signers2) = create_mint_config_tx_and_signers(token_id2, &mut rng);

        let mint_tx1 = create_mint_tx(token_id1, &signers1, 1, &mut rng);
        let mint_tx2 = create_mint_tx(token_id2, &signers2, 2, &mut rng);
        let mint_tx3 = create_mint_tx(token_id1, &signers1, 100, &mut rng);

        let block_contents = BlockContents {
            mint_txs: vec![mint_tx1, mint_tx2, mint_tx3],
            outputs: (0..3).map(|_i| create_test_tx_out(&mut rng)).collect(),
            ..Default::default()
        };

        let parent_block = ledger_db
            .get_block(ledger_db.num_blocks().unwrap() - 1)
            .unwrap();
        let block = Block::new_with_parent(
            BlockVersion::MAX,
            &parent_block,
            &Default::default(),
            &block_contents,
        );

        let mint_audit_data = mint_audit_db.sync_block(&block, &block_contents).unwrap();
        assert_eq!(
            mint_audit_data,
            BlockAuditData {
                balance_map: BTreeMap::from_iter([(*token_id1, 101), (*token_id2, 2)]),
            }
        );

        // Sync a block with two burn transactions and some unrelated transaction.
        let burn_recipient = burn_address();

        let tx_out1 = TxOut::new(
            Amount {
                value: 50,
                token_id: token_id1,
            },
            &burn_recipient,
            &RistrettoPrivate::from_random(&mut rng),
            Default::default(),
        )
        .unwrap();

        let tx_out2 = TxOut::new(
            Amount {
                value: 10,
                token_id: token_id1,
            },
            &burn_recipient,
            &RistrettoPrivate::from_random(&mut rng),
            Default::default(),
        )
        .unwrap();

        let tx_out3 = create_test_tx_out(&mut rng);

        let block_contents = BlockContents {
            outputs: vec![tx_out1, tx_out2, tx_out3],
            ..Default::default()
        };

        let block = Block::new_with_parent(
            BlockVersion::MAX,
            &block,
            &Default::default(),
            &block_contents,
        );

        let mint_audit_data = mint_audit_db.sync_block(&block, &block_contents).unwrap();
        assert_eq!(
            mint_audit_data,
            BlockAuditData {
                balance_map: BTreeMap::from_iter([(*token_id1, 41), (*token_id2, 2)]),
            }
        );

        // Sync a block that mixes burning and minting.
        let mint_tx1 = create_mint_tx(token_id1, &signers1, 1000, &mut rng);
        let mint_tx2 = create_mint_tx(token_id2, &signers1, 2000, &mut rng);
        let mint_tx3 = create_mint_tx(token_id3, &signers1, 20000, &mut rng);

        let tx_out1 = TxOut::new(
            Amount {
                value: 900,
                token_id: token_id1,
            },
            &burn_recipient,
            &RistrettoPrivate::from_random(&mut rng),
            Default::default(),
        )
        .unwrap();

        let tx_out2 = TxOut::new(
            Amount {
                value: 1000,
                token_id: token_id2,
            },
            &burn_recipient,
            &RistrettoPrivate::from_random(&mut rng),
            Default::default(),
        )
        .unwrap();

        let tx_out3 = create_test_tx_out(&mut rng);

        let block_contents = BlockContents {
            outputs: vec![tx_out1, tx_out2, tx_out3],
            mint_txs: vec![mint_tx1, mint_tx2, mint_tx3],
            ..Default::default()
        };

        let block = Block::new_with_parent(
            BlockVersion::MAX,
            &block,
            &Default::default(),
            &block_contents,
        );

        let mint_audit_data = mint_audit_db.sync_block(&block, &block_contents).unwrap();
        assert_eq!(
            mint_audit_data,
            BlockAuditData {
                balance_map: BTreeMap::from_iter([
                    (*token_id1, 141),
                    (*token_id2, 1002),
                    (*token_id3, 20000)
                ]),
            }
        );

        // Sanity check counters.
        assert_eq!(
            mint_audit_db.get_counters().unwrap(),
            Counters {
                num_blocks_synced: block.index + 1,
                num_burns_exceeding_balance: 0,
            }
        );
    }

    // Attempting to skip a block when syncing should fail.
    #[test_with_logger]
    fn test_sync_block_refuses_skipping_a_block(logger: Logger) {
        let mut rng = Hc128Rng::from_seed([1u8; 32]);

        let mint_audit_db_path = tempdir().unwrap();
        let mint_audit_db = MintAuditorDb::create_or_open(&mint_audit_db_path, logger).unwrap();

        let mut ledger_db = create_ledger();
        let account_key = AccountKey::random(&mut rng);
        let initial_num_blocks = 3;
        initialize_ledger(
            BlockVersion::MAX,
            &mut ledger_db,
            initial_num_blocks,
            &account_key,
            &mut rng,
        );

        // Sync the first block, this should succeed.
        let block_data = ledger_db.get_block_data(0).unwrap();
        mint_audit_db
            .sync_block(block_data.block(), block_data.contents())
            .unwrap();

        // Syncing the third block should fail since we haven't synced the second block.
        let block_data = ledger_db.get_block_data(2).unwrap();
        match mint_audit_db.sync_block(block_data.block(), block_data.contents()) {
            Err(Error::UnexpectedBlockIndex(2, 1)) => {
                // Expected
            }
            err @ _ => {
                panic!("Unexpected result: {:?}", err);
            }
        }
    }

    // Attempting to sync the same block twice should fail.
    #[test_with_logger]
    fn test_sync_block_refuses_same_block(logger: Logger) {
        let mut rng = Hc128Rng::from_seed([1u8; 32]);

        let mint_audit_db_path = tempdir().unwrap();
        let mint_audit_db = MintAuditorDb::create_or_open(&mint_audit_db_path, logger).unwrap();

        let mut ledger_db = create_ledger();
        let account_key = AccountKey::random(&mut rng);
        let initial_num_blocks = 3;
        initialize_ledger(
            BlockVersion::MAX,
            &mut ledger_db,
            initial_num_blocks,
            &account_key,
            &mut rng,
        );

        // Sync the first block, this should succeed.
        let block_data = ledger_db.get_block_data(0).unwrap();
        mint_audit_db
            .sync_block(block_data.block(), block_data.contents())
            .unwrap();

        // Syncing it again should fail.
        match mint_audit_db.sync_block(block_data.block(), block_data.contents()) {
            Err(Error::UnexpectedBlockIndex(0, 1)) => {
                // Expected
            }
            err @ _ => {
                panic!("Unexpected result: {:?}", err);
            }
        }
    }

    // Attempting to sync an old block should fail.
    #[test_with_logger]
    fn test_sync_block_refuses_going_backwards(logger: Logger) {
        let mut rng = Hc128Rng::from_seed([1u8; 32]);

        let mint_audit_db_path = tempdir().unwrap();
        let mint_audit_db = MintAuditorDb::create_or_open(&mint_audit_db_path, logger).unwrap();

        let mut ledger_db = create_ledger();
        let account_key = AccountKey::random(&mut rng);
        let initial_num_blocks = 3;
        initialize_ledger(
            BlockVersion::MAX,
            &mut ledger_db,
            initial_num_blocks,
            &account_key,
            &mut rng,
        );

        for block_index in 0..initial_num_blocks {
            let block_data = ledger_db.get_block_data(block_index).unwrap();

            let mint_audit_data = mint_audit_db
                .sync_block(block_data.block(), block_data.contents())
                .unwrap();

            assert_eq!(mint_audit_data, BlockAuditData::default());
        }
        // Syncing the first block should fail since we already synced it.
        let block_data = ledger_db.get_block_data(0).unwrap();
        match mint_audit_db.sync_block(block_data.block(), block_data.contents()) {
            Err(Error::UnexpectedBlockIndex(0, 3)) => {
                // Expected
            }
            err @ _ => {
                panic!("Unexpected result: {:?}", err);
            }
        }
    }

    // Attempting to burn more than the calculated balance result in the counter
    // being increased.
    #[test_with_logger]
    fn test_sync_block_increases_counter_on_over_burn(logger: Logger) {
        let mut rng = Hc128Rng::from_seed([1u8; 32]);
        let token_id1 = TokenId::from(1);
        let token_id2 = TokenId::from(22);

        let mint_audit_db_path = tempdir().unwrap();
        let mint_audit_db = MintAuditorDb::create_or_open(&mint_audit_db_path, logger).unwrap();

        let mut ledger_db = create_ledger();
        let account_key = AccountKey::random(&mut rng);
        let initial_num_blocks = 3;
        initialize_ledger(
            BlockVersion::MAX,
            &mut ledger_db,
            initial_num_blocks,
            &account_key,
            &mut rng,
        );

        // The blocks we currently have in the ledger contain no burning or minting.
        for block_index in 0..initial_num_blocks {
            let block_data = ledger_db.get_block_data(block_index).unwrap();

            let mint_audit_data = mint_audit_db
                .sync_block(block_data.block(), block_data.contents())
                .unwrap();

            assert_eq!(mint_audit_data, BlockAuditData::default());
        }

        // Sync a block that contains a few mint transactions.
        let (_mint_config_tx1, signers1) = create_mint_config_tx_and_signers(token_id1, &mut rng);
        let (_mint_config_tx2, signers2) = create_mint_config_tx_and_signers(token_id2, &mut rng);

        let mint_tx1 = create_mint_tx(token_id1, &signers1, 1, &mut rng);
        let mint_tx2 = create_mint_tx(token_id2, &signers2, 2, &mut rng);
        let mint_tx3 = create_mint_tx(token_id1, &signers1, 100, &mut rng);

        let block_contents = BlockContents {
            mint_txs: vec![mint_tx1, mint_tx2, mint_tx3],
            outputs: (0..3).map(|_i| create_test_tx_out(&mut rng)).collect(),
            ..Default::default()
        };

        let parent_block = ledger_db
            .get_block(ledger_db.num_blocks().unwrap() - 1)
            .unwrap();
        let block = Block::new_with_parent(
            BlockVersion::MAX,
            &parent_block,
            &Default::default(),
            &block_contents,
        );

        let mint_audit_data = mint_audit_db.sync_block(&block, &block_contents).unwrap();
        assert_eq!(
            mint_audit_data,
            BlockAuditData {
                balance_map: BTreeMap::from_iter([(*token_id1, 101), (*token_id2, 2)]),
            }
        );

        // At this point nothing has been over-burned.
        assert_eq!(
            mint_audit_db
                .get_counters()
                .unwrap()
                .num_burns_exceeding_balance,
            0
        );

        // Sync a block with two burn transactions that results in one of them
        // over-burning.
        let burn_recipient = burn_address();

        let tx_out1 = TxOut::new(
            Amount {
                value: 50000,
                token_id: token_id1,
            },
            &burn_recipient,
            &RistrettoPrivate::from_random(&mut rng),
            Default::default(),
        )
        .unwrap();

        let tx_out2 = TxOut::new(
            Amount {
                value: 2,
                token_id: token_id2,
            },
            &burn_recipient,
            &RistrettoPrivate::from_random(&mut rng),
            Default::default(),
        )
        .unwrap();

        let tx_out3 = create_test_tx_out(&mut rng);

        let block_contents = BlockContents {
            outputs: vec![tx_out1, tx_out2, tx_out3],
            ..Default::default()
        };

        let block = Block::new_with_parent(
            BlockVersion::MAX,
            &block,
            &Default::default(),
            &block_contents,
        );

        let mint_audit_data = mint_audit_db.sync_block(&block, &block_contents).unwrap();
        assert_eq!(
            mint_audit_data,
            BlockAuditData {
                balance_map: BTreeMap::from_iter([(*token_id1, 0), (*token_id2, 0)]),
            }
        );

        // Over-burn has been recorded.
        assert_eq!(
            mint_audit_db
                .get_counters()
                .unwrap()
                .num_burns_exceeding_balance,
            1
        );

        // Over burn once again, see that counter increases.
        let block = Block::new_with_parent(
            BlockVersion::MAX,
            &block,
            &Default::default(),
            &block_contents,
        );

        mint_audit_db.sync_block(&block, &block_contents).unwrap();

        assert_eq!(
            mint_audit_db
                .get_counters()
                .unwrap()
                .num_burns_exceeding_balance,
            3
        );
    }
}
