// Copyright (c) 2018-2022 The MobileCoin Foundation

pub use super::models::BlockBalance;

use super::{schema, transaction, Conn};
use crate::Error;
use diesel::prelude::*;
use mc_blockchain_types::BlockIndex;
use mc_common::HashMap;
use mc_transaction_core::TokenId;
use std::ops::Deref;

/// Trait for providing convenience functions for interacting with the
/// [BlockBalance] model/table.
pub trait BlockBalanceModel {
    /// Get a map of TokenId -> balance for a given block id.
    fn get_balances_for_block(
        conn: &Conn,
        block_index: BlockIndex,
    ) -> Result<HashMap<TokenId, u64>, Error>;

    /// Store a map of TokenId -> balance for a given block id.
    fn set_balances_for_block(
        conn: &Conn,
        block_index: BlockIndex,
        balances: &HashMap<TokenId, u64>,
    ) -> Result<(), Error>;
}

impl BlockBalanceModel for BlockBalance {
    fn get_balances_for_block(
        conn: &Conn,
        block_index: BlockIndex,
    ) -> Result<HashMap<TokenId, u64>, Error> {
        let query = schema::block_balance::table
            .filter(schema::block_balance::columns::block_index.eq(block_index as i64))
            .select((
                schema::block_balance::columns::token_id,
                schema::block_balance::columns::balance,
            ));

        let rows = query.load::<(i64, i64)>(conn)?;

        Ok(rows
            .iter()
            .map(|(token_id, balance)| (TokenId::from(*token_id as u64), *balance as u64))
            .collect())
    }

    fn set_balances_for_block(
        conn: &Conn,
        block_index: BlockIndex,
        balances: &HashMap<TokenId, u64>,
    ) -> Result<(), Error> {
        transaction(conn, |conn| {
            for block_balance in balances.iter().map(|(token_id, balance)| BlockBalance {
                block_index: block_index as i64,
                token_id: *token_id.deref() as i64,
                balance: *balance as i64,
            }) {
                diesel::insert_into(schema::block_balance::table)
                    .values(&block_balance)
                    .execute(conn)?;
            }
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{
        block_audit_data::{BlockAuditData, BlockAuditDataModel},
        test_utils::TestDbContext,
    };
    use mc_common::logger::{test_with_logger, Logger};

    #[test_with_logger]
    fn block_balance_test(logger: Logger) {
        let test_db_context = TestDbContext::default();
        let mint_auditor_db = test_db_context.get_db_instance(logger.clone());

        BlockAuditData { block_index: 0 }
            .set(&mint_auditor_db.get_conn().unwrap())
            .unwrap();
        BlockAuditData { block_index: 1 }
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
