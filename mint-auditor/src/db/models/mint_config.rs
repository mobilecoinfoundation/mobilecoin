// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Model file for the mint_configs table.

use crate::{
    db::{
        schema::{mint_config_txs, mint_configs, mint_txs},
        Conn,
    },
    Error,
};
use diesel::prelude::*;
use mc_blockchain_types::BlockIndex;
use mc_util_serial::{decode, encode};
use serde::{Deserialize, Serialize};

/// Diesel model for the `mint_configs` table.
/// This stores audit data for a specific block index.
#[derive(Debug, Deserialize, Eq, Insertable, PartialEq, Queryable, Serialize)]
pub struct MintConfig {
    /// Auto incrementing primary key.
    pub id: Option<i32>,

    /// id linking to the mint_config_txs table.
    pub mint_config_tx_id: i32,

    /// The maximal amount this configuration can mint from the moment it has
    /// been applied.
    pub mint_limit: i64,

    /// The protobuf-serialized MintConfig.
    pub protobuf: Vec<u8>,
}

impl MintConfig {
    /// Get mint limit.
    pub fn mint_limit(&self) -> u64 {
        self.mint_limit as u64
    }

    /// Get the original MintConfig
    pub fn decode(&self) -> Result<mc_transaction_core::mint::MintConfig, Error> {
        Ok(decode(&self.protobuf)?)
    }

    /// Insert a new MintConfig into the database.
    pub fn insert(
        mint_config_tx_id: i32,
        config: &mc_transaction_core::mint::MintConfig,
        conn: &Conn,
    ) -> Result<(), Error> {
        let obj = Self {
            id: None,
            mint_config_tx_id,
            mint_limit: config.mint_limit as i64,
            protobuf: encode(config),
        };

        diesel::insert_into(mint_configs::table)
            .values(&obj)
            .execute(conn)?;

        Ok(())
    }

    /// Get all mint configs associated with a given mint config tx id.
    pub fn get_by_mint_config_tx_id(
        mint_config_tx_id: i32,
        conn: &Conn,
    ) -> Result<Vec<Self>, Error> {
        Ok(mint_configs::table
            .filter(mint_configs::mint_config_tx_id.eq(mint_config_tx_id))
            .load::<Self>(conn)?)
    }

    /// Get the total amount minted by this configuration before the given block index.
    pub fn get_total_minted_before_block(
        &self,
        block_index: BlockIndex,
        conn: &Conn,
    ) -> Result<u64, Error> {
        // Note: We sum in Rust and not Sqlite due to Sqlite not properly supporting
        // unsigned ints.
        let mint_amounts: Vec<i64> = mint_txs::table
            .inner_join(mint_configs::table.inner_join(mint_config_txs::table))
            .filter(mint_config_txs::block_index.lt(mint_txs::block_index))
            .filter(mint_configs::id.eq(self.id.unwrap_or_default()))
            .filter(mint_txs::block_index.lt(block_index as i64))
            .select(mint_txs::amount)
            .load::<i64>(conn)?;
        Ok(mint_amounts.into_iter().map(|val| val as u64).sum())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{test_utils::TestDbContext, MintConfigTx, MintTx};
    use mc_common::logger::{test_with_logger, Logger};
    use mc_transaction_core::TokenId;
    use mc_transaction_core_test_utils::{create_mint_config_tx_and_signers, create_mint_tx};
    use std::collections::HashSet;

    fn assert_mint_configs_match(
        mint_config_tx_id: i32,
        expected: &[mc_transaction_core::mint::MintConfig],
        actual: &[MintConfig],
    ) {
        assert_eq!(expected.len(), actual.len());

        let expected_set: HashSet<mc_transaction_core::mint::MintConfig> =
            expected.iter().cloned().collect();
        let actual_set = HashSet::from_iter(actual.iter().map(|c| c.decode().unwrap()));
        assert_eq!(expected_set, actual_set);

        for mint_config in actual {
            let decoded = mint_config.decode().unwrap();
            assert!(mint_config.id.is_some());
            assert_eq!(mint_config.mint_config_tx_id, mint_config_tx_id);
            assert_eq!(mint_config.mint_limit(), decoded.mint_limit);
        }
    }

    #[test_with_logger]
    fn get_by_mint_config_tx_id_works(logger: Logger) {
        let mut rng = mc_util_test_helper::get_seeded_rng();
        let test_db_context = TestDbContext::default();
        let mint_auditor_db = test_db_context.get_db_instance(logger.clone());
        let token_id1 = TokenId::from(1);
        let token_id2 = TokenId::from(2);

        let conn = mint_auditor_db.get_conn().unwrap();

        // Store two mint config txs.
        let (mint_config_tx1, _signers) = create_mint_config_tx_and_signers(token_id1, &mut rng);
        let (mint_config_tx2, _signers) = create_mint_config_tx_and_signers(token_id2, &mut rng);
        MintConfigTx::insert(5, &mint_config_tx1, &conn).unwrap();
        MintConfigTx::insert(5, &mint_config_tx2, &conn).unwrap();

        // Get the sql mint config txs.
        let sql_mint_config_tx1 = MintConfigTx::most_recent_for_token(6, token_id1, &conn)
            .unwrap()
            .unwrap();
        let sql_mint_config_tx2 = MintConfigTx::most_recent_for_token(6, token_id2, &conn)
            .unwrap()
            .unwrap();

        // Get the MintConfigs and sanity check them.
        let mint_configs1 =
            MintConfig::get_by_mint_config_tx_id(sql_mint_config_tx1.id.unwrap(), &conn).unwrap();
        let mint_configs2 =
            MintConfig::get_by_mint_config_tx_id(sql_mint_config_tx2.id.unwrap(), &conn).unwrap();

        assert_mint_configs_match(
            sql_mint_config_tx1.id.unwrap(),
            &mint_config_tx1.prefix.configs[..],
            &mint_configs1,
        );
        assert_mint_configs_match(
            sql_mint_config_tx2.id.unwrap(),
            &mint_config_tx2.prefix.configs[..],
            &mint_configs2,
        );

        // Some ids we don't have configs for should return an empty array.
        assert_eq!(
            MintConfig::get_by_mint_config_tx_id(0, &conn).unwrap(),
            vec![]
        );
        assert_eq!(
            MintConfig::get_by_mint_config_tx_id(10, &conn).unwrap(),
            vec![]
        );
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

        MintConfigTx::insert(5, &mint_config_tx1, &conn).unwrap();
        MintConfigTx::insert(10, &mint_config_tx2, &conn).unwrap();
        MintConfigTx::insert(7, &mint_config_tx3, &conn).unwrap();

        // Get the mint configs we'll be testing with.
        let sql_mint_config_tx1 = MintConfigTx::most_recent_for_token(6, token_id1, &conn)
            .unwrap()
            .unwrap();
        let sql_mint_config_tx2 = MintConfigTx::most_recent_for_token(11, token_id1, &conn)
            .unwrap()
            .unwrap();
        let sql_mint_config_tx3 = MintConfigTx::most_recent_for_token(8, token_id2, &conn)
            .unwrap()
            .unwrap();

        let mint_config1 =
            &MintConfig::get_by_mint_config_tx_id(sql_mint_config_tx1.id.unwrap(), &conn).unwrap()
                [0];
        let mint_config2 =
            &MintConfig::get_by_mint_config_tx_id(sql_mint_config_tx2.id.unwrap(), &conn).unwrap()
                [0];
        let mint_config3 =
            &MintConfig::get_by_mint_config_tx_id(sql_mint_config_tx3.id.unwrap(), &conn).unwrap()
                [0];

        // Write some mint txs so we have what to test with.
        let mint_tx1 = create_mint_tx(token_id1, &signers1, 100, &mut rng);
        MintTx::insert(3, mint_config1.id, &mint_tx1, &conn).unwrap();

        let mint_tx2 = create_mint_tx(token_id1, &signers1, 200, &mut rng);
        MintTx::insert(6, mint_config1.id, &mint_tx2, &conn).unwrap();

        let mint_tx3 = create_mint_tx(token_id1, &signers1, 300, &mut rng);
        MintTx::insert(8, mint_config1.id, &mint_tx3, &conn).unwrap();

        let mint_tx4 = create_mint_tx(token_id1, &signers2, 400, &mut rng);
        MintTx::insert(11, mint_config2.id, &mint_tx4, &conn).unwrap();

        let mint_tx5 = create_mint_tx(token_id2, &signers3, 2000, &mut rng);
        MintTx::insert(11, mint_config3.id, &mint_tx5, &conn).unwrap();

        // Sanity test that we get the expected total minted amounts.

        // The mint configuration is only active starting at block index 6 so even
        // though the mint tx somehow entered at block index 3, we should not
        // see it.
        assert_eq!(
            mint_config1
                .get_total_minted_before_block(6, &conn)
                .unwrap(),
            0
        );

        // At block index 7 we should see the 200 mint (but not the 100 one since it
        // happened before the configuration was active).
        assert_eq!(
            mint_config1
                .get_total_minted_before_block(7, &conn)
                .unwrap(),
            200
        );

        // At block index 8 we should still see only 200 since the 300 mint only takes
        // place after block 8.
        assert_eq!(
            mint_config1
                .get_total_minted_before_block(8, &conn)
                .unwrap(),
            200
        );

        // At block index 9 we should see both 200+300 mints.
        assert_eq!(
            mint_config1
                .get_total_minted_before_block(9, &conn)
                .unwrap(),
            500
        );

        // mint_config2 only starts after block index 11, so before that we
        // should not see anything fori t.
        assert_eq!(
            mint_config2
                .get_total_minted_before_block(11, &conn)
                .unwrap(),
            0,
        );

        assert_eq!(
            mint_config2
                .get_total_minted_before_block(12, &conn)
                .unwrap(),
            400,
        );

        assert_eq!(
            mint_config2
                .get_total_minted_before_block(120, &conn)
                .unwrap(),
            400,
        );

        // same for mint_config3
        assert_eq!(
            mint_config3
                .get_total_minted_before_block(11, &conn)
                .unwrap(),
            0,
        );

        assert_eq!(
            mint_config3
                .get_total_minted_before_block(12, &conn)
                .unwrap(),
            2000,
        );

        assert_eq!(
            mint_config3
                .get_total_minted_before_block(120, &conn)
                .unwrap(),
            2000,
        );

        // Adding another mint tx to mint_config2 should work as expected.
        let mint_tx6 = create_mint_tx(token_id2, &signers3, 3000, &mut rng);
        MintTx::insert(12, mint_config3.id, &mint_tx6, &conn).unwrap();

        assert_eq!(
            mint_config3
                .get_total_minted_before_block(11, &conn)
                .unwrap(),
            0,
        );

        assert_eq!(
            mint_config3
                .get_total_minted_before_block(12, &conn)
                .unwrap(),
            2000,
        );

        assert_eq!(
            mint_config3
                .get_total_minted_before_block(13, &conn)
                .unwrap(),
            5000,
        );

        assert_eq!(
            mint_config3
                .get_total_minted_before_block(14, &conn)
                .unwrap(),
            5000,
        );
    }
}
