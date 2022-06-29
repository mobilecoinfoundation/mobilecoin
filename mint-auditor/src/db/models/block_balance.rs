// Copyright (c) 2018-2022 The MobileCoin Foundation

use super::super::{schema::block_balance, transaction, Conn, Error};
use diesel::prelude::*;
use mc_blockchain_types::BlockIndex;
use mc_common::HashMap;
use mc_transaction_core::TokenId;
use serde::{Deserialize, Serialize};
use std::ops::Deref;

/// Diesel model for the `block_balance` table.
/// This stores the balance of each token for a specific block index.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Insertable, PartialEq, Queryable, Serialize)]
#[table_name = "block_balance"]
pub struct BlockBalance {
    /// Block index.
    block_index: i64,

    /// Token id.
    token_id: i64,

    /// Balanace.
    balance: i64,
}

impl BlockBalance {
    /// Construct a new [BlockBalance] object.
    pub fn new(block_index: BlockIndex, token_id: TokenId, balance: u64) -> Self {
        Self {
            block_index: block_index as i64,
            token_id: *token_id as i64,
            balance: balance as i64,
        }
    }

    /// Get block index.
    pub fn block_index(&self) -> u64 {
        self.block_index as u64
    }

    /// Get token id.
    pub fn token_id(&self) -> TokenId {
        TokenId::from(self.token_id as u64)
    }

    /// Get balance.
    pub fn balance(&self) -> u64 {
        self.balance as u64
    }

    /// Get a map of TokenId -> balance for a given block id.
    pub fn get_balances_for_block(
        conn: &Conn,
        block_index: BlockIndex,
    ) -> Result<HashMap<TokenId, u64>, Error> {
        let query = block_balance::table
            .filter(block_balance::columns::block_index.eq(block_index as i64))
            .select((
                block_balance::columns::token_id,
                block_balance::columns::balance,
            ));

        let rows = query.load::<(i64, i64)>(conn)?;

        Ok(rows
            .iter()
            .map(|(token_id, balance)| (TokenId::from(*token_id as u64), *balance as u64))
            .collect())
    }

    /// Store a map of TokenId -> balance for a given block id.
    pub fn set_balances_for_block(
        conn: &Conn,
        block_index: BlockIndex,
        balances: &HashMap<TokenId, u64>,
    ) -> Result<(), Error> {
        transaction(conn, |conn| {
            for block_balance in balances.iter().map(|(token_id, balance)| Self {
                block_index: block_index as i64,
                token_id: *token_id.deref() as i64,
                balance: *balance as i64,
            }) {
                diesel::insert_into(block_balance::table)
                    .values(&block_balance)
                    .execute(conn)?;
            }
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{super::BlockAuditData, *};
    use crate::db::test_utils::TestDbContext;
    use mc_common::logger::{test_with_logger, Logger};

    #[test_with_logger]
    fn block_balance_test(logger: Logger) {
        let test_db_context = TestDbContext::default();
        let mint_auditor_db = test_db_context.get_db_instance(logger.clone());

        BlockAuditData::new(0)
            .set(&mint_auditor_db.get_conn().unwrap())
            .unwrap();
        BlockAuditData::new(1)
            .set(&mint_auditor_db.get_conn().unwrap())
            .unwrap();

        let balances =
            BlockBalance::get_balances_for_block(&mint_auditor_db.get_conn().unwrap(), 0).unwrap();
        assert_eq!(balances, HashMap::default());

        let expected_balances = HashMap::from_iter(vec![
            (TokenId::from(1), 10),
            (TokenId::from(2), 20),
            (TokenId::from(3), <u64>::MAX - 1),
        ]);
        BlockBalance::set_balances_for_block(
            &mint_auditor_db.get_conn().unwrap(),
            0,
            &expected_balances,
        )
        .unwrap();

        assert_eq!(
            BlockBalance::get_balances_for_block(&mint_auditor_db.get_conn().unwrap(), 0).unwrap(),
            expected_balances
        );

        // Try a tested transaction
        transaction(
            &mint_auditor_db.get_conn().unwrap(),
            |conn| -> Result<(), Error> {
                let expected_balances2 = HashMap::from_iter(vec![
                    (TokenId::from(1), 10),
                    (TokenId::from(2), 20),
                    (TokenId::from(<u64>::MAX - 30), <u64>::MAX - 123),
                ]);
                BlockBalance::set_balances_for_block(conn, 1, &expected_balances2).unwrap();

                assert_eq!(
                    BlockBalance::get_balances_for_block(conn, 0).unwrap(),
                    expected_balances
                );
                assert_eq!(
                    BlockBalance::get_balances_for_block(conn, 1).unwrap(),
                    expected_balances2
                );

                Ok(())
            },
        )
        .unwrap();

        // Test that transaction failure is rolled back as expected.
        transaction(
            &mint_auditor_db.get_conn().unwrap(),
            |conn| -> Result<(), Error> {
                let balances_with_dupe = HashMap::from_iter(vec![
                    (TokenId::from(10), 10),
                    (TokenId::from(20), 20),
                    (TokenId::from(1), 10),
                ]);
                assert!(
                    BlockBalance::set_balances_for_block(conn, 0, &balances_with_dupe,).is_err()
                );

                assert_eq!(
                    BlockBalance::get_balances_for_block(conn, 0).unwrap(),
                    expected_balances
                );
                Ok(())
            },
        )
        .unwrap();
    }
}
