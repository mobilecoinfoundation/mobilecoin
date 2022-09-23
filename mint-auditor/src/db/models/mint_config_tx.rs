// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Model file for the mint_config_txs table.

use crate::{
    db::{
        last_insert_rowid,
        models::MintConfig,
        schema::{mint_config_txs, mint_configs, mint_txs},
        transaction, Conn,
    },
    Error,
};
use diesel::prelude::*;
use mc_blockchain_types::BlockIndex;
use mc_transaction_core::{mint::MintConfigTx as CoreMintConfigTx, TokenId};
use mc_util_serial::{decode, encode};
use serde::{Deserialize, Serialize};

/// Diesel model for the `mint_config_txs` table.
/// This stores audit data for a specific block index.
#[derive(
    Clone, Debug, Default, Deserialize, Eq, Hash, Insertable, PartialEq, Queryable, Serialize,
)]
pub struct MintConfigTx {
    /// Auto incrementing primary key.
    id: Option<i32>,

    /// The block index at which this mint config tx appreared.
    block_index: i64,

    /// The token id this mint config tx is for.
    token_id: i64,

    /// The nonce, as hex-encoded bytes.
    nonce_hex: String,

    /// The maximal amount that can be minted by configurations specified in
    /// this tx. This amount is shared amongst all configs.
    total_mint_limit: i64,

    /// Tombstone block.
    tombstone_block: i64,

    /// The protobuf-serialized MintConfigTx.
    protobuf: Vec<u8>,
}

impl MintConfigTx {
    /// Get id.
    pub fn id(&self) -> Option<i32> {
        self.id
    }

    /// Get block index.
    pub fn block_index(&self) -> u64 {
        self.block_index as u64
    }

    /// Get token id.
    pub fn token_id(&self) -> TokenId {
        TokenId::from(self.token_id as u64)
    }

    /// Get nonce.
    pub fn nonce_hex(&self) -> &str {
        &self.nonce_hex
    }

    /// Get mint limit.
    pub fn total_mint_limit(&self) -> u64 {
        self.total_mint_limit as u64
    }

    /// Get tombstone block.
    pub fn tombstone_block(&self) -> u64 {
        self.tombstone_block as u64
    }

    /// Get the original MintConfigTx
    pub fn decode(&self) -> Result<CoreMintConfigTx, Error> {
        Ok(decode(&self.protobuf)?)
    }

    /// Create an instance of this object from a
    /// [mc_transaction_core::mint::MintConfigTx] and some extra information.
    pub fn from_core_mint_config_tx(block_index: BlockIndex, tx: &CoreMintConfigTx) -> Self {
        Self {
            id: None,
            block_index: block_index as i64,
            token_id: tx.prefix.token_id as i64,
            nonce_hex: hex::encode(&tx.prefix.nonce),
            total_mint_limit: tx.prefix.total_mint_limit as i64,
            tombstone_block: tx.prefix.tombstone_block as i64,
            protobuf: encode(tx),
        }
    }

    /// Insert a new MintConfigTx into the database.
    pub fn insert(&mut self, conn: &Conn) -> Result<(), Error> {
        let core_mint_config_tx = self.decode()?;
        let mint_config_tx = self.clone();

        let mint_config_tx_id = transaction(conn, |conn| -> Result<i32, Error> {
            diesel::insert_into(mint_config_txs::table)
                .values(mint_config_tx)
                .execute(conn)?;

            let mint_config_tx_id = diesel::select(last_insert_rowid).get_result::<i32>(conn)?;

            for config in &core_mint_config_tx.prefix.configs {
                MintConfig::insert_from_core_mint_config(mint_config_tx_id, config, conn)?;
            }

            Ok(mint_config_tx_id)
        })?;

        self.id = Some(mint_config_tx_id);
        Ok(())
    }

    /// Helper for inserting from a [mc_transaction_core::mint::MintConfigTx]
    /// and some extra information.
    pub fn insert_from_core_mint_config_tx(
        block_index: BlockIndex,
        config_tx: &CoreMintConfigTx,
        conn: &Conn,
    ) -> Result<Self, Error> {
        let mut mint_config_tx = Self::from_core_mint_config_tx(block_index, config_tx);
        mint_config_tx.insert(conn)?;
        Ok(mint_config_tx)
    }

    /// Get the most recent MintConfigTx for a given token id that was active
    /// before a given block index.
    pub fn most_recent_for_token(
        block_index: BlockIndex,
        token_id: TokenId,
        conn: &Conn,
    ) -> Result<Option<MintConfigTx>, Error> {
        Ok(mint_config_txs::table
            .filter(mint_config_txs::token_id.eq(*token_id as i64))
            .filter(mint_config_txs::block_index.lt(block_index as i64))
            .order_by(mint_config_txs::block_index.desc())
            .limit(1)
            .first::<MintConfigTx>(conn)
            .optional()?)
    }

    /// Get the total amount minted by all configurations in this MintConfigTx
    /// before the given block index.
    pub fn get_total_minted_before_block(
        &self,
        block_index: BlockIndex,
        conn: &Conn,
    ) -> Result<u64, Error> {
        // Note: We sum in Rust and not Sqlite due to Sqlite not properly supporting
        // unsigned ints.
        // We default our id to 0 since SQLite auto-inc values start at 1.
        let mint_amounts: Vec<i64> = mint_txs::table
            .inner_join(mint_configs::table.inner_join(mint_config_txs::table))
            .filter(mint_config_txs::block_index.lt(mint_txs::block_index))
            .filter(mint_config_txs::id.eq(self.id.unwrap_or_default()))
            .filter(mint_txs::block_index.lt(block_index as i64))
            .select(mint_txs::amount)
            .load::<i64>(conn)?;
        Ok(mint_amounts.into_iter().map(|val| val as u64).sum())
    }
}

#[cfg(test)]
mod tests {
    use super::{super::MintTx, *};
    use crate::db::test_utils::TestDbContext;
    use mc_common::logger::{test_with_logger, Logger};
    use mc_transaction_core_test_utils::{create_mint_config_tx_and_signers, create_mint_tx};

    fn assert_mint_config_tx_eq(
        sql_mint_config_tx: &MintConfigTx,
        orig_mint_config_tx: &CoreMintConfigTx,
    ) {
        assert_eq!(
            sql_mint_config_tx.token_id(),
            TokenId::from(orig_mint_config_tx.prefix.token_id)
        );
        assert_eq!(
            sql_mint_config_tx.nonce_hex,
            hex::encode(&orig_mint_config_tx.prefix.nonce)
        );
        assert_eq!(
            sql_mint_config_tx.total_mint_limit(),
            orig_mint_config_tx.prefix.total_mint_limit
        );
        assert_eq!(
            sql_mint_config_tx.tombstone_block(),
            orig_mint_config_tx.prefix.tombstone_block
        );
        assert_eq!(sql_mint_config_tx.decode().unwrap(), *orig_mint_config_tx);
    }

    #[test_with_logger]
    fn most_recent_for_token_works(logger: Logger) {
        let mut rng = mc_util_test_helper::get_seeded_rng();
        let test_db_context = TestDbContext::default();
        let mint_auditor_db = test_db_context.get_db_instance(logger.clone());
        let token_id1 = TokenId::from(1);
        let token_id2 = TokenId::from(2);

        let conn = mint_auditor_db.get_conn().unwrap();

        // Initially we dont have a MintConfigTx for either token.
        assert_eq!(
            MintConfigTx::most_recent_for_token(0, token_id1, &conn).unwrap(),
            None
        );

        assert_eq!(
            MintConfigTx::most_recent_for_token(1, token_id1, &conn).unwrap(),
            None
        );

        // Store a mint config at block index 5.
        let (mint_config_tx1, _signers) = create_mint_config_tx_and_signers(token_id1, &mut rng);
        MintConfigTx::insert_from_core_mint_config_tx(5, &mint_config_tx1, &conn).unwrap();

        // tx should not show up on any prior blocks and show up for any blocks after 5.
        for block_index in 0..=5 {
            assert_eq!(
                MintConfigTx::most_recent_for_token(block_index, token_id1, &conn).unwrap(),
                None
            );
            assert_eq!(
                MintConfigTx::most_recent_for_token(block_index, token_id2, &conn).unwrap(),
                None
            );
        }

        for block_index in 6..10 {
            let sql_mint_config_tx =
                MintConfigTx::most_recent_for_token(block_index, token_id1, &conn)
                    .unwrap()
                    .unwrap();
            assert_eq!(sql_mint_config_tx.block_index, 5);
            assert_mint_config_tx_eq(&sql_mint_config_tx, &mint_config_tx1);

            assert_eq!(
                MintConfigTx::most_recent_for_token(block_index, token_id2, &conn).unwrap(),
                None
            );
        }

        // Store a mint tx for the 2nd token at block index 7 and verify queries work as
        // expected.
        let (mint_config_tx2, _signers) = create_mint_config_tx_and_signers(token_id2, &mut rng);
        MintConfigTx::insert_from_core_mint_config_tx(7, &mint_config_tx2, &conn).unwrap();

        // For block indexes 0-5 we don't expect anything to be returned.
        for block_index in 0..=5 {
            assert_eq!(
                MintConfigTx::most_recent_for_token(block_index, token_id1, &conn).unwrap(),
                None
            );
            assert_eq!(
                MintConfigTx::most_recent_for_token(block_index, token_id2, &conn).unwrap(),
                None
            );
        }

        // For block indexes 6-7 we expect only token_id1 to have data.
        for block_index in 6..=7 {
            let sql_mint_config_tx =
                MintConfigTx::most_recent_for_token(block_index, token_id1, &conn)
                    .unwrap()
                    .unwrap();
            assert_eq!(sql_mint_config_tx.block_index, 5);
            assert_mint_config_tx_eq(&sql_mint_config_tx, &mint_config_tx1);

            assert_eq!(
                MintConfigTx::most_recent_for_token(block_index, token_id2, &conn).unwrap(),
                None
            );
        }

        // For block indexes 8-10 we expect both to have data.
        for block_index in 8..=10 {
            let sql_mint_config_tx =
                MintConfigTx::most_recent_for_token(block_index, token_id1, &conn)
                    .unwrap()
                    .unwrap();
            assert_eq!(sql_mint_config_tx.block_index, 5);
            assert_mint_config_tx_eq(&sql_mint_config_tx, &mint_config_tx1);

            let sql_mint_config_tx =
                MintConfigTx::most_recent_for_token(block_index, token_id2, &conn)
                    .unwrap()
                    .unwrap();
            assert_eq!(sql_mint_config_tx.block_index, 7);
            assert_mint_config_tx_eq(&sql_mint_config_tx, &mint_config_tx2);
        }

        // Add another mint config tx for token id 1 at block index 7.
        let (mint_config_tx3, _signers) = create_mint_config_tx_and_signers(token_id1, &mut rng);
        MintConfigTx::insert_from_core_mint_config_tx(7, &mint_config_tx3, &conn).unwrap();

        // For block indexes 0-5 we don't expect anything to be returned.
        for block_index in 0..=5 {
            assert_eq!(
                MintConfigTx::most_recent_for_token(block_index, token_id1, &conn).unwrap(),
                None
            );
            assert_eq!(
                MintConfigTx::most_recent_for_token(block_index, token_id2, &conn).unwrap(),
                None
            );
        }

        // For block indexes 6-7 we expect only token_id1 to have data.
        for block_index in 6..=7 {
            let sql_mint_config_tx =
                MintConfigTx::most_recent_for_token(block_index, token_id1, &conn)
                    .unwrap()
                    .unwrap();
            assert_eq!(sql_mint_config_tx.block_index, 5);
            assert_mint_config_tx_eq(&sql_mint_config_tx, &mint_config_tx1);

            assert_eq!(
                MintConfigTx::most_recent_for_token(block_index, token_id2, &conn).unwrap(),
                None
            );
        }

        // For block indexes 8-10 we expect both to have data, and token id 1 should
        // have the new mint config tx.
        for block_index in 8..=10 {
            let sql_mint_config_tx =
                MintConfigTx::most_recent_for_token(block_index, token_id1, &conn)
                    .unwrap()
                    .unwrap();
            assert_eq!(sql_mint_config_tx.block_index, 7);
            assert_mint_config_tx_eq(&sql_mint_config_tx, &mint_config_tx3);

            let sql_mint_config_tx =
                MintConfigTx::most_recent_for_token(block_index, token_id2, &conn)
                    .unwrap()
                    .unwrap();
            assert_eq!(sql_mint_config_tx.block_index, 7);
            assert_mint_config_tx_eq(&sql_mint_config_tx, &mint_config_tx2);
        }
    }

    #[test_with_logger]
    fn insert_enforces_uniqueness(logger: Logger) {
        let test_db_context = TestDbContext::default();
        let mint_auditor_db = test_db_context.get_db_instance(logger.clone());
        let token_id1 = TokenId::from(1);
        let token_id2 = TokenId::from(2);

        let conn = mint_auditor_db.get_conn().unwrap();
        let mut rng = mc_util_test_helper::get_seeded_rng();
        let (mint_config_tx1, _signers) = create_mint_config_tx_and_signers(token_id1, &mut rng);
        let (mint_config_tx2, _signers) = create_mint_config_tx_and_signers(token_id1, &mut rng);
        let mut mint_config_tx1_tkn2 = mint_config_tx1.clone();
        mint_config_tx1_tkn2.prefix.token_id = *token_id2;
        // Store a mint config at block index 5.
        MintConfigTx::insert_from_core_mint_config_tx(5, &mint_config_tx1, &conn).unwrap();

        // Trying again for the same block will fail.
        assert!(MintConfigTx::insert_from_core_mint_config_tx(5, &mint_config_tx1, &conn).is_err());
        assert!(MintConfigTx::insert_from_core_mint_config_tx(5, &mint_config_tx2, &conn).is_err());

        // Trying for a different block but with the same nonce will fail.
        assert!(MintConfigTx::insert_from_core_mint_config_tx(6, &mint_config_tx1, &conn).is_err());
        // Trying for a different block with the same nonce but different token_id
        // should not fail
        assert!(
            MintConfigTx::insert_from_core_mint_config_tx(6, &mint_config_tx1_tkn2, &conn).is_ok()
        );

        // Sanity, inserting a different mint config at block index 6 should succeed.
        assert!(MintConfigTx::insert_from_core_mint_config_tx(6, &mint_config_tx2, &conn).is_ok());
    }

    #[test_with_logger]
    fn get_total_minted_before_block_works(logger: Logger) {
        let mut rng = mc_util_test_helper::get_seeded_rng();
        let test_db_context = TestDbContext::default();
        let mint_auditor_db = test_db_context.get_db_instance(logger.clone());
        let token_id1 = TokenId::from(1);
        let token_id2 = TokenId::from(2);

        let conn = mint_auditor_db.get_conn().unwrap();

        // Create a fewtest mint config txs and insert them.
        let (mint_config_tx1, signers1) = create_mint_config_tx_and_signers(token_id1, &mut rng);
        let (mint_config_tx2, signers2) = create_mint_config_tx_and_signers(token_id1, &mut rng);
        let (mint_config_tx3, signers3) = create_mint_config_tx_and_signers(token_id2, &mut rng);

        MintConfigTx::insert_from_core_mint_config_tx(5, &mint_config_tx1, &conn).unwrap();
        MintConfigTx::insert_from_core_mint_config_tx(10, &mint_config_tx2, &conn).unwrap();
        MintConfigTx::insert_from_core_mint_config_tx(7, &mint_config_tx3, &conn).unwrap();

        // Get our mint config txs from the database (and quick sanity check we got what
        // we expected).
        let sql_mint_config_tx_1 = MintConfigTx::most_recent_for_token(6, token_id1, &conn)
            .unwrap()
            .unwrap();
        assert_eq!(sql_mint_config_tx_1.decode().unwrap(), mint_config_tx1);
        assert!(sql_mint_config_tx_1.id.is_some());

        let sql_mint_config_tx_2 = MintConfigTx::most_recent_for_token(11, token_id1, &conn)
            .unwrap()
            .unwrap();
        assert_eq!(sql_mint_config_tx_2.decode().unwrap(), mint_config_tx2);
        assert!(sql_mint_config_tx_2.id.is_some());

        let sql_mint_config_tx_3 = MintConfigTx::most_recent_for_token(11, token_id2, &conn)
            .unwrap()
            .unwrap();
        assert_eq!(sql_mint_config_tx_3.decode().unwrap(), mint_config_tx3);
        assert!(sql_mint_config_tx_3.id.is_some());

        assert_ne!(sql_mint_config_tx_1.id, sql_mint_config_tx_2.id);
        assert_ne!(sql_mint_config_tx_2.id, sql_mint_config_tx_3.id);

        let sql_mint_configs = [
            &sql_mint_config_tx_1,
            &sql_mint_config_tx_2,
            &sql_mint_config_tx_3,
        ];

        // Initially nothing has been mounted at any point.
        for block_index in 0..20 {
            for sql_mint_config in &sql_mint_configs {
                assert_eq!(
                    sql_mint_config
                        .get_total_minted_before_block(block_index, &conn)
                        .unwrap(),
                    0
                );
            }
        }

        // Get a mint config id for each mint config tx.
        let mint_config_id1 =
            MintConfig::get_by_mint_config_tx_id(sql_mint_config_tx_1.id.unwrap(), &conn).unwrap()
                [0]
            .id();
        let mint_config_id2 =
            MintConfig::get_by_mint_config_tx_id(sql_mint_config_tx_2.id.unwrap(), &conn).unwrap()
                [0]
            .id();
        let mint_config_id3 =
            MintConfig::get_by_mint_config_tx_id(sql_mint_config_tx_3.id.unwrap(), &conn).unwrap()
                [0]
            .id();

        // Write some mint txs so we have what to test with.
        let mint_tx1 = create_mint_tx(token_id1, &signers1, 100, &mut rng);
        MintTx::insert_from_core_mint_tx(3, mint_config_id1, &mint_tx1, &conn).unwrap();

        let mint_tx2 = create_mint_tx(token_id1, &signers1, 200, &mut rng);
        MintTx::insert_from_core_mint_tx(6, mint_config_id1, &mint_tx2, &conn).unwrap();

        let mint_tx3 = create_mint_tx(token_id1, &signers1, 300, &mut rng);
        MintTx::insert_from_core_mint_tx(8, mint_config_id1, &mint_tx3, &conn).unwrap();

        let mint_tx4 = create_mint_tx(token_id1, &signers2, 400, &mut rng);
        MintTx::insert_from_core_mint_tx(11, mint_config_id2, &mint_tx4, &conn).unwrap();

        let mint_tx5 = create_mint_tx(token_id2, &signers3, 2000, &mut rng);
        MintTx::insert_from_core_mint_tx(11, mint_config_id3, &mint_tx5, &conn).unwrap();

        // Sanity test that we get the expected total minted amounts.

        // The mint configuration is only active starting at block index 6 so even
        // though the mint tx somehow entered at block index 3, we should not
        // see it.
        assert_eq!(
            sql_mint_config_tx_1
                .get_total_minted_before_block(6, &conn)
                .unwrap(),
            0
        );

        // At block index 7 we should see the 200 mint (but not the 100 one since it
        // happened before the configuration was active).
        assert_eq!(
            sql_mint_config_tx_1
                .get_total_minted_before_block(7, &conn)
                .unwrap(),
            200
        );

        // At block index 8 we should still see only 200 since the 300 mint only takes
        // place after block 8.
        assert_eq!(
            sql_mint_config_tx_1
                .get_total_minted_before_block(8, &conn)
                .unwrap(),
            200
        );

        // At block index 9 we should see both 200+300 mints.
        assert_eq!(
            sql_mint_config_tx_1
                .get_total_minted_before_block(9, &conn)
                .unwrap(),
            500
        );

        // sql_mint_config_tx_2 only starts after block index 11, so before that we
        // should not see anything fori t.
        assert_eq!(
            sql_mint_config_tx_2
                .get_total_minted_before_block(11, &conn)
                .unwrap(),
            0,
        );

        //std::thread::sleep(std::time::Duration::from_millis(100000000));

        assert_eq!(
            sql_mint_config_tx_2
                .get_total_minted_before_block(12, &conn)
                .unwrap(),
            400,
        );

        assert_eq!(
            sql_mint_config_tx_2
                .get_total_minted_before_block(120, &conn)
                .unwrap(),
            400,
        );

        // same for sql_mint_config_tx_3
        assert_eq!(
            sql_mint_config_tx_3
                .get_total_minted_before_block(11, &conn)
                .unwrap(),
            0,
        );

        assert_eq!(
            sql_mint_config_tx_3
                .get_total_minted_before_block(12, &conn)
                .unwrap(),
            2000,
        );

        assert_eq!(
            sql_mint_config_tx_3
                .get_total_minted_before_block(120, &conn)
                .unwrap(),
            2000,
        );

        // Adding another mint tx to sql_mint_config_tx_2 should work as expected.
        let mint_tx6 = create_mint_tx(token_id2, &signers3, 3000, &mut rng);
        MintTx::insert_from_core_mint_tx(12, mint_config_id3, &mint_tx6, &conn).unwrap();

        assert_eq!(
            sql_mint_config_tx_3
                .get_total_minted_before_block(11, &conn)
                .unwrap(),
            0,
        );

        assert_eq!(
            sql_mint_config_tx_3
                .get_total_minted_before_block(12, &conn)
                .unwrap(),
            2000,
        );

        assert_eq!(
            sql_mint_config_tx_3
                .get_total_minted_before_block(13, &conn)
                .unwrap(),
            5000,
        );

        assert_eq!(
            sql_mint_config_tx_3
                .get_total_minted_before_block(14, &conn)
                .unwrap(),
            5000,
        );
    }
}
