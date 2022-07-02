// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Mint auditor database.

#[cfg(test)]
pub mod test_utils;

mod conn;
mod models;
mod transaction;

/// Db schema (made public for anyone wanting to do custom queries).
pub mod schema;

pub use self::{
    conn::{Conn, ConnectionOptions},
    models::{
        BlockAuditData, BlockBalance, Counters, GnosisSafeDeposit, GnosisSafeTx,
        GnosisSafeWithdrawal, MintConfig, MintConfigTx, MintTx,
    },
    transaction::{transaction, TransactionRetriableError},
};

use crate::Error;
use diesel::{
    r2d2::{ConnectionManager, Pool},
    SqliteConnection,
};
use diesel_migrations::embed_migrations;
use mc_account_keys::burn_address_view_private;
use mc_blockchain_types::{Block, BlockContents, BlockIndex};
use mc_common::{
    logger::{log, Logger},
    HashMap,
};
use mc_transaction_core::TokenId;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use std::time::Duration;

embed_migrations!("migrations/");

no_arg_sql_function!(
    last_insert_rowid,
    diesel::sql_types::Integer,
    "Represents the SQLite last_insert_rowid() function"
);

/// Mint Auditor Database.
#[derive(Clone)]
pub struct MintAuditorDb {
    pool: Pool<ConnectionManager<SqliteConnection>>,
    logger: Logger,
}

impl MintAuditorDb {
    /// Instantiate a new database using an existing connection pool.
    pub fn new(pool: Pool<ConnectionManager<SqliteConnection>>, logger: Logger) -> Self {
        Self { pool, logger }
    }

    /// Instantiate a new database from a path that points at a database file.
    pub fn new_from_path(
        db_file_path: &str,
        db_connections: u32,
        logger: Logger,
    ) -> Result<Self, Error> {
        let manager = ConnectionManager::<SqliteConnection>::new(db_file_path);
        let pool = Pool::builder()
            .max_size(db_connections)
            .connection_customizer(Box::new(ConnectionOptions {
                enable_wal: true,
                busy_timeout: Some(Duration::from_secs(30)),
            }))
            .test_on_check_out(true)
            .build(manager)?;

        let conn = pool.get()?;
        embedded_migrations::run_with_output(&conn, &mut std::io::stdout())?;

        Ok(Self::new(pool, logger))
    }

    /// Get a connection from the pool.
    pub fn get_conn(&self) -> Result<Conn, Error> {
        Ok(self.pool.get()?)
    }

    /// Sync mint audit data of a single block.
    pub fn sync_block(
        &self,
        block: &Block,
        block_contents: &BlockContents,
    ) -> Result<(BlockAuditData, HashMap<TokenId, u64>), Error> {
        let conn = self.get_conn()?;
        self.sync_block_with_conn(&conn, block, block_contents)
    }

    /// Sync mint audit data of a single block using a pre-existing connection.
    pub fn sync_block_with_conn(
        &self,
        conn: &Conn,
        block: &Block,
        block_contents: &BlockContents,
    ) -> Result<(BlockAuditData, HashMap<TokenId, u64>), Error> {
        transaction(conn, |conn| {
            let block_index = block.index;
            log::info!(self.logger, "Syncing block {}", block_index);

            let mut counters = Counters::get(conn)?;

            // Ensure that we are syncing the next block and haven't skipped any blocks (or
            // went backwards).
            let next_block_index = counters.num_blocks_synced as BlockIndex;
            if block_index != next_block_index {
                return Err(Error::UnexpectedBlockIndex(block_index, next_block_index));
            }

            // Store mint config txs.
            for validated_mint_config_tx in &block_contents.validated_mint_config_txs {
                MintConfigTx::insert(block_index, &validated_mint_config_tx.mint_config_tx, conn)?;
            }

            // Get balance map for the previous block
            let mut balance_map = if block_index == 0 {
                Default::default()
            } else {
                BlockBalance::get_balances_for_block(conn, block_index - 1)?
            };

            // Process mints.
            log::trace!(
                self.logger,
                "Processing {} mints",
                block_contents.mint_txs.len()
            );
            for mint_tx in &block_contents.mint_txs {
                // Balance accounting.
                let mint_balance = balance_map
                    .entry(TokenId::from(mint_tx.prefix.token_id))
                    .or_default();

                *mint_balance += mint_tx.prefix.amount;
                log::info!(
                    self.logger,
                    "Block {}: Minted {} of token id {}, balance is now {}",
                    block_index,
                    mint_tx.prefix.amount,
                    mint_tx.prefix.token_id,
                    mint_balance,
                );

                // Try and match the mint tx to an active mint config.
                let mint_config = Self::lookup_mint_config(block_index, mint_tx, conn)?;

                // Alert and count if we did not find a matching mint config.
                if mint_config.is_none() {
                    log::crit!(
                        self.logger,
                        "Block {}: Found mint tx {} that did not match any active mint config",
                        block_index,
                        mint_tx,
                    );

                    counters.num_mint_txs_without_matching_mint_config += 1;
                }

                // Store the mint tx.
                MintTx::insert(
                    block_index,
                    mint_config.and_then(|config| config.id()),
                    mint_tx,
                    conn,
                )?;
            }

            // Count burns.
            log::trace!(self.logger, "Processing burns");
            let burn_amounts = block_contents
                .outputs
                .par_iter()
                .filter_map(|tx_out| {
                    tx_out
                        .view_key_match(&burn_address_view_private())
                        .ok()
                        .map(|(amount, _shared_secret)| amount)
                })
                .collect::<Vec<_>>();

            for amount in burn_amounts {
                let burn_balance = balance_map.entry(amount.token_id).or_default();

                if amount.value > *burn_balance {
                    log::crit!(
                        self.logger,
                        "Block {}: Burned {} of token id {} but only had {}. Setting balance to 0",
                        block_index,
                        amount.value,
                        amount.token_id,
                        burn_balance
                    );
                    *burn_balance = 0;
                    counters.num_burns_exceeding_balance += 1;
                } else {
                    *burn_balance -= amount.value;
                    log::info!(
                        self.logger,
                        "Block {}: Burned {} of token id {}, balance is now {}",
                        block_index,
                        amount.value,
                        amount.token_id,
                        burn_balance,
                    );
                }
            }

            // Update the database.
            counters.num_blocks_synced += 1;
            log::trace!(self.logger, "Updating counters: {:?}", counters);
            counters.set(conn)?;

            let block_audit_data = BlockAuditData::new(block_index);
            log::trace!(
                self.logger,
                "Storing block audit data: {:?}",
                block_audit_data
            );
            block_audit_data.set(conn)?;

            BlockBalance::set_balances_for_block(conn, block_index, &balance_map)?;

            // Success.
            log::info!(
                self.logger,
                "Done syncing block {}, block_audit_data={:?}, balance_map={:?}",
                block_index,
                block_audit_data,
                balance_map
            );
            Ok((block_audit_data, balance_map))
        })
    }

    /// Lookup a mint config that can accommodate a given mint tx.
    pub fn lookup_mint_config(
        block_index: BlockIndex,
        mint_tx: &mc_transaction_core::mint::MintTx,
        conn: &Conn,
    ) -> Result<Option<MintConfig>, Error> {
        let sql_mint_config_tx = match MintConfigTx::most_recent_for_token(
            block_index,
            TokenId::from(mint_tx.prefix.token_id),
            conn,
        )? {
            Some(tx) => tx,
            None => {
                return Ok(None);
            }
        };

        // Get the total that was minted using this mint configuration and see if we
        // will not exceed its total mint limit.
        let total_minted = sql_mint_config_tx.get_total_minted_before_block(block_index, conn)?;
        if let Some(new_total_minted) = total_minted.checked_add(mint_tx.prefix.amount) {
            if new_total_minted > sql_mint_config_tx.total_mint_limit() {
                return Ok(None);
            }
        } else {
            return Ok(None);
        }

        // SQLite auto-increment ids start at 1, so calling unwrap_or_default() on the
        // id field will result on no rows returned if no id is available.
        let sql_mint_configs = MintConfig::get_by_mint_config_tx_id(
            sql_mint_config_tx.id().unwrap_or_default(),
            conn,
        )?;

        let message = mint_tx.prefix.hash();

        for sql_mint_config in sql_mint_configs {
            // See if the mint tx was signed by this mint config.
            let mint_config = sql_mint_config.decode()?;
            if mint_config
                .signer_set
                .verify(&message, &mint_tx.signature)
                .is_err()
            {
                continue;
            }

            // See how much was minted already with this mint config.
            let total_minted = sql_mint_config.get_total_minted_before_block(block_index, conn)?;

            // This mint config has signed the mint tx. Is it allowed to mint the given
            // amount of tokens?
            // If we overflow (checked_add returns None) then we will keep looking for an
            // active mint configuration that is able to accommodate the MintTx.
            if let Some(new_total_minted) = total_minted.checked_add(mint_tx.prefix.amount) {
                if new_total_minted <= sql_mint_config.mint_limit() {
                    return Ok(Some(sql_mint_config));
                }
            }
        }

        // Couldn't find a mint config that can accommodate the mint tx.
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::test_utils::{append_and_sync, TestDbContext};
    use mc_account_keys::{burn_address, AccountKey};
    use mc_common::logger::{test_with_logger, Logger};
    use mc_crypto_keys::RistrettoPrivate;
    use mc_ledger_db::{
        test_utils::{create_ledger, initialize_ledger},
        Ledger,
    };
    use mc_transaction_core::{tx::TxOut, Amount, BlockVersion, TokenId};
    use mc_transaction_core_test_utils::{
        create_mint_config_tx_and_signers, create_mint_tx, create_test_tx_out,
        mint_config_tx_to_validated as to_validated, KeyImage,
    };
    use mc_util_from_random::FromRandom;

    const BLOCK_VERSION: BlockVersion = BlockVersion::MAX;

    #[test_with_logger]
    fn test_sync_block_happy_flow(logger: Logger) {
        let mut rng = mc_util_test_helper::get_seeded_rng();
        let token_id1 = TokenId::from(1);
        let token_id2 = TokenId::from(22);
        let token_id3 = TokenId::from(3);

        let test_db_context = TestDbContext::default();
        let mint_auditor_db = test_db_context.get_db_instance(logger.clone());
        let conn = mint_auditor_db.get_conn().unwrap();

        let mut ledger_db = create_ledger();
        let account_key = AccountKey::random(&mut rng);
        let initial_num_blocks = 3;
        initialize_ledger(
            BLOCK_VERSION,
            &mut ledger_db,
            initial_num_blocks,
            &account_key,
            &mut rng,
        );

        // The blocks we currently have in the ledger contain no burning or minting.
        for block_index in 0..initial_num_blocks {
            let block_data = ledger_db.get_block_data(block_index).unwrap();

            let (mint_audit_data, balance_map) = mint_auditor_db
                .sync_block(block_data.block(), block_data.contents())
                .unwrap();

            assert_eq!(
                mint_audit_data,
                BlockAuditData::new(block_data.block().index),
            );
            assert_eq!(balance_map, Default::default());
        }

        // Sync a block that contains MintConfigTxs so that we have valid
        // active configs.
        let (mint_config_tx1, signers1) = create_mint_config_tx_and_signers(token_id1, &mut rng);
        let (mint_config_tx2, signers2) = create_mint_config_tx_and_signers(token_id2, &mut rng);
        let (mint_config_tx3, signers3) = create_mint_config_tx_and_signers(token_id3, &mut rng);

        let block_contents = BlockContents {
            validated_mint_config_txs: vec![
                to_validated(&mint_config_tx1),
                to_validated(&mint_config_tx2),
                to_validated(&mint_config_tx3),
            ],
            ..Default::default()
        };

        let (mint_audit_data, balance_map, block_index) =
            append_and_sync(block_contents, &mut ledger_db, &mint_auditor_db, &mut rng).unwrap();
        assert_eq!(mint_audit_data, BlockAuditData::new(block_index));
        assert_eq!(balance_map, Default::default());

        // Sync a block that contains a few mint transactions.
        let mint_tx1 = create_mint_tx(token_id1, &signers1, 1, &mut rng);
        let mint_tx2 = create_mint_tx(token_id2, &signers2, 2, &mut rng);
        let mint_tx3 = create_mint_tx(token_id1, &signers1, 100, &mut rng);

        let block_contents = BlockContents {
            mint_txs: vec![mint_tx1, mint_tx2, mint_tx3],
            outputs: (0..3)
                .map(|_i| create_test_tx_out(BLOCK_VERSION, &mut rng))
                .collect(),
            ..Default::default()
        };

        let (mint_audit_data, balance_map, block_index) =
            append_and_sync(block_contents, &mut ledger_db, &mint_auditor_db, &mut rng).unwrap();

        assert_eq!(mint_audit_data, BlockAuditData::new(block_index));
        assert_eq!(
            balance_map,
            HashMap::from_iter([(token_id1, 101), (token_id2, 2)])
        );

        // Sync a block with two burn transactions and some unrelated
        // transaction.
        let burn_recipient = burn_address();

        let tx_out1 = TxOut::new(
            BLOCK_VERSION,
            Amount::new(50, token_id1),
            &burn_recipient,
            &RistrettoPrivate::from_random(&mut rng),
            Default::default(),
        )
        .unwrap();

        let tx_out2 = TxOut::new(
            BLOCK_VERSION,
            Amount::new(10, token_id1),
            &burn_recipient,
            &RistrettoPrivate::from_random(&mut rng),
            Default::default(),
        )
        .unwrap();

        let tx_out3 = create_test_tx_out(BLOCK_VERSION, &mut rng);

        let block_contents = BlockContents {
            outputs: vec![tx_out1, tx_out2, tx_out3],
            key_images: vec![KeyImage::from(1)],
            ..Default::default()
        };

        let (mint_audit_data, balance_map, block_index) =
            append_and_sync(block_contents, &mut ledger_db, &mint_auditor_db, &mut rng).unwrap();
        assert_eq!(mint_audit_data, BlockAuditData::new(block_index));

        assert_eq!(
            balance_map,
            HashMap::from_iter([(token_id1, 41), (token_id2, 2)]),
        );

        // Sync a block that mixes burning and minting.
        let mint_tx1 = create_mint_tx(token_id1, &signers1, 1000, &mut rng);
        let mint_tx2 = create_mint_tx(token_id2, &signers2, 2000, &mut rng);
        let mint_tx3 = create_mint_tx(token_id3, &signers3, 20000, &mut rng);

        let tx_out1 = TxOut::new(
            BLOCK_VERSION,
            Amount::new(900, token_id1),
            &burn_recipient,
            &RistrettoPrivate::from_random(&mut rng),
            Default::default(),
        )
        .unwrap();

        let tx_out2 = TxOut::new(
            BLOCK_VERSION,
            Amount::new(1000, token_id2),
            &burn_recipient,
            &RistrettoPrivate::from_random(&mut rng),
            Default::default(),
        )
        .unwrap();

        let tx_out3 = create_test_tx_out(BLOCK_VERSION, &mut rng);

        let block_contents = BlockContents {
            outputs: vec![tx_out1, tx_out2, tx_out3],
            mint_txs: vec![mint_tx1, mint_tx2, mint_tx3],
            ..Default::default()
        };

        let (mint_audit_data, balance_map, block_index) =
            append_and_sync(block_contents, &mut ledger_db, &mint_auditor_db, &mut rng).unwrap();

        assert_eq!(mint_audit_data, BlockAuditData::new(block_index));
        assert_eq!(
            balance_map,
            HashMap::from_iter([(token_id1, 141), (token_id2, 1002), (token_id3, 20000)]),
        );

        // Sanity check counters.
        assert_eq!(
            Counters::get(&conn).unwrap(),
            Counters {
                id: 0,
                num_blocks_synced: block_index as i64 + 1,
                num_burns_exceeding_balance: 0,
                num_mint_txs_without_matching_mint_config: 0,
            }
        );
    }

    // Attempting to skip a block when syncing should fail.
    #[test_with_logger]
    fn test_sync_block_refuses_skipping_a_block(logger: Logger) {
        let mut rng = mc_util_test_helper::get_seeded_rng();

        let test_db_context = TestDbContext::default();
        let mint_auditor_db = test_db_context.get_db_instance(logger.clone());
        let mut ledger_db = create_ledger();
        let account_key = AccountKey::random(&mut rng);
        let initial_num_blocks = 3;
        initialize_ledger(
            BLOCK_VERSION,
            &mut ledger_db,
            initial_num_blocks,
            &account_key,
            &mut rng,
        );

        // Sync the first block, this should succeed.
        let block_data = ledger_db.get_block_data(0).unwrap();
        mint_auditor_db
            .sync_block(block_data.block(), block_data.contents())
            .unwrap();

        // Syncing the third block should fail since we haven't synced the second block.
        let block_data = ledger_db.get_block_data(2).unwrap();
        assert!(matches!(
            mint_auditor_db.sync_block(block_data.block(), block_data.contents()),
            Err(Error::UnexpectedBlockIndex(2, 1))
        ));
    }

    // Attempting to sync the same block twice should fail.
    #[test_with_logger]
    fn test_sync_block_refuses_same_block(logger: Logger) {
        let mut rng = mc_util_test_helper::get_seeded_rng();

        let test_db_context = TestDbContext::default();
        let mint_auditor_db = test_db_context.get_db_instance(logger.clone());
        let mut ledger_db = create_ledger();
        let account_key = AccountKey::random(&mut rng);
        let initial_num_blocks = 3;
        initialize_ledger(
            BLOCK_VERSION,
            &mut ledger_db,
            initial_num_blocks,
            &account_key,
            &mut rng,
        );

        // Sync the first block, this should succeed.
        let block_data = ledger_db.get_block_data(0).unwrap();
        mint_auditor_db
            .sync_block(block_data.block(), block_data.contents())
            .unwrap();

        // Syncing it again should fail.
        assert!(matches!(
            mint_auditor_db.sync_block(block_data.block(), block_data.contents()),
            Err(Error::UnexpectedBlockIndex(0, 1))
        ));
    }

    // Attempting to sync an old block should fail.
    #[test_with_logger]
    fn test_sync_block_refuses_going_backwards(logger: Logger) {
        let mut rng = mc_util_test_helper::get_seeded_rng();

        let test_db_context = TestDbContext::default();
        let mint_auditor_db = test_db_context.get_db_instance(logger.clone());

        let mut ledger_db = create_ledger();
        let account_key = AccountKey::random(&mut rng);
        let initial_num_blocks = 3;
        initialize_ledger(
            BLOCK_VERSION,
            &mut ledger_db,
            initial_num_blocks,
            &account_key,
            &mut rng,
        );

        for block_index in 0..initial_num_blocks {
            let block_data = ledger_db.get_block_data(block_index).unwrap();

            mint_auditor_db
                .sync_block(block_data.block(), block_data.contents())
                .unwrap();
        }
        // Syncing the first block should fail since we already synced it.
        let block_data = ledger_db.get_block_data(0).unwrap();
        assert!(matches!(
            mint_auditor_db.sync_block(block_data.block(), block_data.contents()),
            Err(Error::UnexpectedBlockIndex(0, 3))
        ));
    }

    // Attempting to burn more than the calculated balance result in the counter
    // being increased.
    #[test_with_logger]
    fn test_sync_block_increases_counter_on_over_burn(logger: Logger) {
        let mut rng = mc_util_test_helper::get_seeded_rng();
        let token_id1 = TokenId::from(1);
        let token_id2 = TokenId::from(22);

        let test_db_context = TestDbContext::default();
        let mint_auditor_db = test_db_context.get_db_instance(logger.clone());
        let conn = mint_auditor_db.get_conn().unwrap();

        let mut ledger_db = create_ledger();
        let account_key = AccountKey::random(&mut rng);
        let initial_num_blocks = 3;
        initialize_ledger(
            BLOCK_VERSION,
            &mut ledger_db,
            initial_num_blocks,
            &account_key,
            &mut rng,
        );

        // The blocks we currently have in the ledger contain no burning or minting.
        for block_index in 0..initial_num_blocks {
            let block_data = ledger_db.get_block_data(block_index).unwrap();

            mint_auditor_db
                .sync_block(block_data.block(), block_data.contents())
                .unwrap();
        }

        // Sync a block that contains a few mint transactions.
        let (mint_config_tx1, signers1) = create_mint_config_tx_and_signers(token_id1, &mut rng);
        let (mint_config_tx2, signers2) = create_mint_config_tx_and_signers(token_id2, &mut rng);

        let block_contents = BlockContents {
            validated_mint_config_txs: vec![
                to_validated(&mint_config_tx1),
                to_validated(&mint_config_tx2),
            ],
            ..Default::default()
        };

        append_and_sync(block_contents, &mut ledger_db, &mint_auditor_db, &mut rng).unwrap();

        let mint_tx1 = create_mint_tx(token_id1, &signers1, 1, &mut rng);
        let mint_tx2 = create_mint_tx(token_id2, &signers2, 2, &mut rng);
        let mint_tx3 = create_mint_tx(token_id1, &signers1, 100, &mut rng);

        let block_contents = BlockContents {
            mint_txs: vec![mint_tx1, mint_tx2, mint_tx3],
            outputs: (0..3)
                .map(|_i| create_test_tx_out(BLOCK_VERSION, &mut rng))
                .collect(),
            ..Default::default()
        };

        let (mint_audit_data, balance_map, block_index) =
            append_and_sync(block_contents, &mut ledger_db, &mint_auditor_db, &mut rng).unwrap();
        assert_eq!(mint_audit_data, BlockAuditData::new(block_index));
        assert_eq!(
            balance_map,
            HashMap::from_iter([(token_id1, 101), (token_id2, 2)])
        );

        // At this point nothing has been over-burned.
        assert_eq!(Counters::get(&conn).unwrap().num_burns_exceeding_balance, 0);

        // Sync a block with two burn transactions that results in one of them
        // over-burning.
        let burn_recipient = burn_address();

        let tx_out1 = TxOut::new(
            BLOCK_VERSION,
            Amount::new(50000, token_id1),
            &burn_recipient,
            &RistrettoPrivate::from_random(&mut rng),
            Default::default(),
        )
        .unwrap();

        let tx_out2 = TxOut::new(
            BLOCK_VERSION,
            Amount::new(2, token_id2),
            &burn_recipient,
            &RistrettoPrivate::from_random(&mut rng),
            Default::default(),
        )
        .unwrap();

        let tx_out3 = create_test_tx_out(BLOCK_VERSION, &mut rng);

        let block_contents = BlockContents {
            outputs: vec![tx_out1, tx_out2, tx_out3],
            key_images: vec![KeyImage::from(1)],
            ..Default::default()
        };

        let (mint_audit_data, balance_map, block_index) =
            append_and_sync(block_contents, &mut ledger_db, &mint_auditor_db, &mut rng).unwrap();
        assert_eq!(mint_audit_data, BlockAuditData::new(block_index));
        assert_eq!(
            balance_map,
            HashMap::from_iter([(token_id1, 0), (token_id2, 0)]),
        );

        // Over-burn has been recorded.
        assert_eq!(Counters::get(&conn).unwrap().num_burns_exceeding_balance, 1);

        // Over burn once again, see that counter increases.
        let tx_out1 = TxOut::new(
            BLOCK_VERSION,
            Amount::new(50000, token_id1),
            &burn_recipient,
            &RistrettoPrivate::from_random(&mut rng),
            Default::default(),
        )
        .unwrap();

        let tx_out2 = TxOut::new(
            BLOCK_VERSION,
            Amount::new(2, token_id2),
            &burn_recipient,
            &RistrettoPrivate::from_random(&mut rng),
            Default::default(),
        )
        .unwrap();

        let tx_out3 = create_test_tx_out(BLOCK_VERSION, &mut rng);

        let block_contents = BlockContents {
            outputs: vec![tx_out1, tx_out2, tx_out3],
            key_images: vec![KeyImage::from(2)],
            ..Default::default()
        };

        append_and_sync(block_contents, &mut ledger_db, &mint_auditor_db, &mut rng).unwrap();

        assert_eq!(Counters::get(&conn).unwrap().num_burns_exceeding_balance, 3);
    }

    // MintTxs that do not match an active MintConfig get counted.
    #[test_with_logger]
    fn test_sync_block_counts_mint_txs_without_active_config(logger: Logger) {
        let mut rng = mc_util_test_helper::get_seeded_rng();
        let token_id1 = TokenId::from(1);
        let token_id2 = TokenId::from(22);

        let test_db_context = TestDbContext::default();
        let mint_auditor_db = test_db_context.get_db_instance(logger.clone());
        let conn = mint_auditor_db.get_conn().unwrap();

        let mut ledger_db = create_ledger();
        let account_key = AccountKey::random(&mut rng);
        let initial_num_blocks = 3;
        initialize_ledger(
            BLOCK_VERSION,
            &mut ledger_db,
            initial_num_blocks,
            &account_key,
            &mut rng,
        );

        // The blocks we currently have in the ledger contain no burning or minting.
        for block_index in 0..initial_num_blocks {
            let block_data = ledger_db.get_block_data(block_index).unwrap();

            mint_auditor_db
                .sync_block(block_data.block(), block_data.contents())
                .unwrap();
        }

        // Sync a block that contains MintConfigTxs so that we have valid active
        // configs.
        let (mint_config_tx1, signers1) = create_mint_config_tx_and_signers(token_id1, &mut rng);
        let (mint_config_tx2, signers2) = create_mint_config_tx_and_signers(token_id2, &mut rng);

        let block_contents = BlockContents {
            validated_mint_config_txs: vec![
                to_validated(&mint_config_tx1),
                to_validated(&mint_config_tx2),
            ],
            ..Default::default()
        };

        append_and_sync(block_contents, &mut ledger_db, &mint_auditor_db, &mut rng).unwrap();

        // Sync a block that contains a mint transaction with incorrect signers.
        // Normally we would append the block to the ledger and test as usual, but since
        // it contains an invalid MintTx append_block would actually fail. As
        // such we do this inside a transaction and then roll back.
        // We need to roll the transaction back otherwise the ledger db block count and
        // the mint auditor db number of blocks synced gets out of sync and we will
        // start seeing UnexpectedBlockIndex errors.
        {
            let mint_tx1 = create_mint_tx(token_id1, &signers2, 1, &mut rng);

            let block_contents = BlockContents {
                mint_txs: vec![mint_tx1],
                outputs: (0..3)
                    .map(|_i| create_test_tx_out(BLOCK_VERSION, &mut rng))
                    .collect(),
                ..Default::default()
            };

            let parent_block = ledger_db.get_latest_block().unwrap();
            let block = Block::new_with_parent(
                BLOCK_VERSION,
                &parent_block,
                &Default::default(),
                &block_contents,
            );

            let _ = transaction(&conn, |conn| -> Result<(), Error> {
                mint_auditor_db
                    .sync_block_with_conn(conn, &block, &block_contents)
                    .unwrap();

                assert_eq!(
                    Counters::get(conn).unwrap(),
                    Counters {
                        id: 0,
                        num_blocks_synced: block.index as i64 + 1,
                        num_burns_exceeding_balance: 0,
                        num_mint_txs_without_matching_mint_config: 1,
                    }
                );

                // Chosen arbitrarily, we just need to return an error to ensure the transaction
                // gets rolled back.
                Err(Error::NotFound)
            });
        }

        // Sync a block that invalidates the previous configs.
        let (mint_config_tx3, signers3) = create_mint_config_tx_and_signers(token_id1, &mut rng);

        let block_contents = BlockContents {
            validated_mint_config_txs: vec![to_validated(&mint_config_tx3)],
            ..Default::default()
        };

        append_and_sync(block_contents, &mut ledger_db, &mint_auditor_db, &mut rng).unwrap();

        // Sync a block that contains a mint transaction with signers that refer to a no
        // longer valid mint config.
        {
            let mint_tx2 = create_mint_tx(token_id1, &signers1, 1, &mut rng);

            let block_contents = BlockContents {
                mint_txs: vec![mint_tx2],
                outputs: (0..3)
                    .map(|_i| create_test_tx_out(BLOCK_VERSION, &mut rng))
                    .collect(),
                ..Default::default()
            };

            let parent_block = ledger_db.get_latest_block().unwrap();
            let block = Block::new_with_parent(
                BLOCK_VERSION,
                &parent_block,
                &Default::default(),
                &block_contents,
            );

            let _ = transaction(&conn, |conn| -> Result<(), Error> {
                mint_auditor_db
                    .sync_block_with_conn(conn, &block, &block_contents)
                    .unwrap();

                assert_eq!(
                    Counters::get(conn).unwrap(),
                    Counters {
                        id: 0,
                        num_blocks_synced: block.index as i64 + 1,
                        num_burns_exceeding_balance: 0,
                        num_mint_txs_without_matching_mint_config: 1,
                    }
                );

                // Chosen arbitrarily, we just need to return an error to ensure the transaction
                // gets rolled back.
                Err(Error::NotFound)
            });
        }

        // Sanity - sync a block with a MintTx that matches a valid config.
        let mint_tx3 = create_mint_tx(token_id1, &signers3, 1, &mut rng);

        let block_contents = BlockContents {
            mint_txs: vec![mint_tx3],
            outputs: (0..3)
                .map(|_i| create_test_tx_out(BLOCK_VERSION, &mut rng))
                .collect(),
            ..Default::default()
        };

        let (_, _, block_index) =
            append_and_sync(block_contents, &mut ledger_db, &mint_auditor_db, &mut rng).unwrap();

        assert_eq!(
            Counters::get(&conn).unwrap(),
            Counters {
                id: 0,
                num_blocks_synced: block_index as i64 + 1,
                num_burns_exceeding_balance: 0,
                num_mint_txs_without_matching_mint_config: 0,
            }
        );
    }

    // MintTxs that exceed the MintConfigTx limit get counted.
    #[test_with_logger]
    fn test_sync_blocks_counts_mint_txs_exceeding_total_mint_limit(logger: Logger) {
        let mut rng = mc_util_test_helper::get_seeded_rng();
        let token_id1 = TokenId::from(1);

        let test_db_context = TestDbContext::default();
        let mint_auditor_db = test_db_context.get_db_instance(logger.clone());
        let conn = mint_auditor_db.get_conn().unwrap();

        let mut ledger_db = create_ledger();
        let account_key = AccountKey::random(&mut rng);
        let initial_num_blocks = 3;
        initialize_ledger(
            BLOCK_VERSION,
            &mut ledger_db,
            initial_num_blocks,
            &account_key,
            &mut rng,
        );

        // The blocks we currently have in the ledger contain no burning or minting.
        for block_index in 0..initial_num_blocks {
            let block_data = ledger_db.get_block_data(block_index).unwrap();

            mint_auditor_db
                .sync_block(block_data.block(), block_data.contents())
                .unwrap();
        }

        // Sync a block that contains a MintConfigTx with a total limit we are able to
        // exceed.
        let (mut mint_config_tx1, signers1) =
            create_mint_config_tx_and_signers(token_id1, &mut rng);
        mint_config_tx1.prefix.total_mint_limit = 2;

        assert!(
            mint_config_tx1.prefix.configs[0].mint_limit > mint_config_tx1.prefix.total_mint_limit
        );

        let block_contents = BlockContents {
            validated_mint_config_txs: vec![to_validated(&mint_config_tx1)],
            ..Default::default()
        };

        append_and_sync(block_contents, &mut ledger_db, &mint_auditor_db, &mut rng).unwrap();

        // Sync a block that mints the total mint limit.
        let mint_tx1 = create_mint_tx(
            token_id1,
            &signers1,
            mint_config_tx1.prefix.total_mint_limit,
            &mut rng,
        );

        let block_contents = BlockContents {
            mint_txs: vec![mint_tx1],
            outputs: (0..3)
                .map(|_i| create_test_tx_out(BLOCK_VERSION, &mut rng))
                .collect(),
            ..Default::default()
        };

        let (_, _, block_index) =
            append_and_sync(block_contents, &mut ledger_db, &mint_auditor_db, &mut rng).unwrap();

        assert_eq!(
            Counters::get(&conn).unwrap(),
            Counters {
                id: 0,
                num_blocks_synced: block_index as i64 + 1,
                num_burns_exceeding_balance: 0,
                num_mint_txs_without_matching_mint_config: 0,
            }
        );

        // Minting more should get flagged since we are exceeding the total mint limit.
        let mint_tx1 = create_mint_tx(token_id1, &signers1, 1, &mut rng);

        let block_contents = BlockContents {
            mint_txs: vec![mint_tx1],
            outputs: (0..3)
                .map(|_i| create_test_tx_out(BLOCK_VERSION, &mut rng))
                .collect(),
            ..Default::default()
        };

        let parent_block = ledger_db.get_latest_block().unwrap();

        let block = Block::new_with_parent(
            BLOCK_VERSION,
            &parent_block,
            &Default::default(),
            &block_contents,
        );

        mint_auditor_db.sync_block(&block, &block_contents).unwrap();

        assert_eq!(
            Counters::get(&conn).unwrap(),
            Counters {
                id: 0,
                num_blocks_synced: block.index as i64 + 1,
                num_burns_exceeding_balance: 0,
                num_mint_txs_without_matching_mint_config: 1,
            }
        );
    }
}
