// Copyright (c) 2018-2022 The MobileCoin Foundation

use crate::{
    db::{schema::counters, Conn},
    Error,
};
use diesel::prelude::*;
use serde::{Deserialize, Serialize};

/// This stores a bunch of general purpose counters. There is only ever one row
/// in this table.
#[derive(
    Clone, Debug, Default, Deserialize, Eq, Hash, Insertable, PartialEq, Queryable, Serialize,
)]
#[table_name = "counters"]
pub struct Counters {
    /// Id (required to keep Diesel happy).
    pub id: i32,

    /// The number of blocks synced so far.
    pub num_blocks_synced: i64,

    /// The number of burn transactions that exceeded the minted amount.
    pub num_burns_exceeding_balance: i64,

    /// The number of mint transactions that did not match an active mint
    /// configuration.
    pub num_mint_txs_without_matching_mint_config: i64,
}

impl Counters {
    /// Get the number of blocks synced so far.
    pub fn num_blocks_synced(&self) -> u64 {
        self.num_blocks_synced as u64
    }

    /// Get the number of burn transactions that exceeded the minted amount.
    pub fn num_burns_exceeding_balance(&self) -> u64 {
        self.num_burns_exceeding_balance as u64
    }

    /// Get the number of mint transactions that did not match an active mint
    /// configuration.
    pub fn num_mint_txs_without_matching_mint_config(&self) -> u64 {
        self.num_mint_txs_without_matching_mint_config as u64
    }

    /// Get all counters.
    pub fn get(conn: &Conn) -> Result<Self, Error> {
        match counters::table.get_result(conn) {
            Ok(obj) => Ok(obj),
            Err(diesel::result::Error::NotFound) => Ok(Counters::default()),
            Err(e) => Err(e.into()),
        }
    }

    /// Set all counters.
    pub fn set(&self, conn: &Conn) -> Result<(), Error> {
        diesel::replace_into(counters::table)
            .values(self)
            .execute(conn)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::test_utils::TestDbContext;
    use mc_common::logger::{test_with_logger, Logger};

    #[test_with_logger]
    fn counters_sanity_test(logger: Logger) {
        let test_db_context = TestDbContext::default();
        let mint_auditor_db = test_db_context.get_db_instance(logger.clone());

        let mut counters = Counters::get(&mint_auditor_db.get_conn().unwrap()).unwrap();
        assert_eq!(counters, Counters::default());

        counters.num_blocks_synced = 123;
        counters.set(&mint_auditor_db.get_conn().unwrap()).unwrap();
        assert_eq!(
            Counters::get(&mint_auditor_db.get_conn().unwrap()).unwrap(),
            counters
        );

        counters.num_blocks_synced = 1234;
        counters.num_burns_exceeding_balance = 5;
        counters.set(&mint_auditor_db.get_conn().unwrap()).unwrap();
        assert_eq!(
            Counters::get(&mint_auditor_db.get_conn().unwrap()).unwrap(),
            counters
        );
    }
}
