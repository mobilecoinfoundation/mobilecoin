// Copyright (c) 2018-2022 The MobileCoin Foundation

use crate::{
    counters as prom_counters,
    db::{schema::counters, transaction, Conn},
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
    id: i32,

    /// The number of blocks synced so far.
    num_blocks_synced: i64,

    /// The number of burn transactions that exceeded the minted amount.
    num_burns_exceeding_balance: i64,

    /// The number of mint transactions that did not match an active mint
    /// configuration.
    num_mint_txs_without_matching_mint_config: i64,

    /// The number of mismatching MintTxs and Gnosis deposits.
    num_mismatching_mints_and_deposits: i64,

    /// The number of times we encountered deposits to an unknown Ethereum token
    /// contract address.
    num_unknown_ethereum_token_deposits: i64,
}

impl Counters {
    /// Get the number of blocks synced so far.
    pub fn num_blocks_synced(&self) -> u64 {
        self.num_blocks_synced as u64
    }

    /// Atomically increase the number of blocks synced so far.
    pub fn inc_num_blocks_synced(conn: &Conn) -> Result<(), Error> {
        match diesel::update(counters::table)
            .set(counters::num_blocks_synced.eq(counters::num_blocks_synced + 1))
            .execute(conn)?
        {
            0 => Err(Error::NotFound),
            1 => Ok(()),
            num_rows => Err(Error::Other(format!(
                "inc_num_blocks_synced: unexpected number of rows ({})",
                num_rows
            ))),
        }
    }

    /// Get the number of burn transactions that exceeded the minted amount.
    pub fn num_burns_exceeding_balance(&self) -> u64 {
        self.num_burns_exceeding_balance as u64
    }

    /// Atomically increase the number of burn transactions that exceeded the
    /// minted amount.
    pub fn inc_num_burns_exceeding_balance(conn: &Conn) -> Result<(), Error> {
        match diesel::update(counters::table)
            .set(
                counters::num_burns_exceeding_balance.eq(counters::num_burns_exceeding_balance + 1),
            )
            .execute(conn)?
        {
            0 => Err(Error::NotFound),
            1 => Ok(()),
            num_rows => Err(Error::Other(format!(
                "inc_num_burns_exceeding_balance: unexpected number of rows ({})",
                num_rows
            ))),
        }
    }
    /// Get the number of mint transactions that did not match an active mint
    /// configuration.
    pub fn num_mint_txs_without_matching_mint_config(&self) -> u64 {
        self.num_mint_txs_without_matching_mint_config as u64
    }

    /// Atomically increase the number of mint transactions that did not match
    /// an active mint configuration.
    pub fn inc_num_mint_txs_without_matching_mint_config(conn: &Conn) -> Result<(), Error> {
        match diesel::update(counters::table)
            .set(
                counters::num_mint_txs_without_matching_mint_config
                    .eq(counters::num_mint_txs_without_matching_mint_config + 1),
            )
            .execute(conn)?
        {
            0 => Err(Error::NotFound),
            1 => Ok(()),
            num_rows => Err(Error::Other(format!(
                "inc_num_mint_txs_without_matching_mint_config: unexpected number of rows ({})",
                num_rows
            ))),
        }
    }

    /// Get the number of blocks synced so far.
    pub fn num_mismatching_mints_and_deposits(&self) -> u64 {
        self.num_mismatching_mints_and_deposits as u64
    }

    /// Atomically increase the number of mismatching MintTxs and Gnosis
    /// deposits.
    pub fn inc_num_mismatching_mints_and_deposits(conn: &Conn) -> Result<(), Error> {
        match diesel::update(counters::table)
            .set(
                counters::num_mismatching_mints_and_deposits
                    .eq(counters::num_mismatching_mints_and_deposits + 1),
            )
            .execute(conn)?
        {
            0 => Err(Error::NotFound),
            1 => Ok(()),
            num_rows => Err(Error::Other(format!(
                "inc_num_mismatching_mints_and_deposits: unexpected number of rows ({})",
                num_rows
            ))),
        }
    }

    /// Get the number of times we encountered deposits to an unknown Ethereum
    /// token contract address.
    pub fn num_unknown_ethereum_token_deposits(&self) -> u64 {
        self.num_unknown_ethereum_token_deposits as u64
    }

    /// Atomically increase the number of times we encountered deposits to an
    /// unknown Ethereum token contract address.
    pub fn inc_num_unknown_ethereum_token_deposits(conn: &Conn) -> Result<(), Error> {
        match diesel::update(counters::table)
            .set(
                counters::num_unknown_ethereum_token_deposits
                    .eq(counters::num_unknown_ethereum_token_deposits + 1),
            )
            .execute(conn)?
        {
            0 => Err(Error::NotFound),
            1 => Ok(()),
            num_rows => Err(Error::Other(format!(
                "inc_num_unknown_ethereum_token_deposits: unexpected number of rows ({})",
                num_rows
            ))),
        }
    }

    /// Get all counters.
    pub fn get(conn: &Conn) -> Result<Self, Error> {
        match counters::table.get_result(conn) {
            Ok(obj) => Ok(obj),
            Err(diesel::result::Error::NotFound) => Ok(Counters::default()),
            Err(e) => Err(e.into()),
        }
    }

    /// Ensure we have a row in the counters table.
    pub fn ensure_exists(conn: &Conn) -> Result<(), Error> {
        transaction(conn, |conn| -> Result<(), Error> {
            match counters::table.get_result::<Self>(conn) {
                Ok(_) => Ok(()),
                Err(diesel::result::Error::NotFound) => Ok(diesel::insert_into(counters::table)
                    .values(Self::default())
                    .execute(conn)
                    .map(|_| ())?),
                Err(e) => Err(e.into()),
            }
        })
    }

    /// Update prometheus counters.
    pub fn update_prometheus(&self) {
        prom_counters::NUM_BLOCKS_SYNCED.set(self.num_blocks_synced);
        prom_counters::NUM_BURNS_EXCEEDING_BALANCE.set(self.num_burns_exceeding_balance);
        prom_counters::NUM_MINT_TXS_WITHOUT_MATCHING_MINT_CONFIG
            .set(self.num_mint_txs_without_matching_mint_config);
        prom_counters::NUM_MISMATCHING_MINTS_AND_DEPOSITS
            .set(self.num_mismatching_mints_and_deposits);
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
        let conn = mint_auditor_db.get_conn().unwrap();

        assert_eq!(Counters::get(&conn).unwrap(), Counters::default());

        Counters::ensure_exists(&conn).unwrap();
        Counters::ensure_exists(&conn).unwrap();
        Counters::ensure_exists(&conn).unwrap();

        assert_eq!(Counters::get(&conn).unwrap().num_blocks_synced(), 0);
        Counters::inc_num_blocks_synced(&conn).unwrap();
        Counters::inc_num_blocks_synced(&conn).unwrap();
        Counters::inc_num_blocks_synced(&conn).unwrap();
        assert_eq!(Counters::get(&conn).unwrap().num_blocks_synced(), 3);

        assert_eq!(
            Counters::get(&conn).unwrap().num_burns_exceeding_balance(),
            0
        );
        Counters::inc_num_burns_exceeding_balance(&conn).unwrap();
        Counters::inc_num_burns_exceeding_balance(&conn).unwrap();
        Counters::inc_num_burns_exceeding_balance(&conn).unwrap();
        Counters::inc_num_burns_exceeding_balance(&conn).unwrap();
        assert_eq!(
            Counters::get(&conn).unwrap().num_burns_exceeding_balance(),
            4
        );

        assert_eq!(
            Counters::get(&conn)
                .unwrap()
                .num_mint_txs_without_matching_mint_config(),
            0
        );
        Counters::inc_num_mint_txs_without_matching_mint_config(&conn).unwrap();
        Counters::inc_num_mint_txs_without_matching_mint_config(&conn).unwrap();
        assert_eq!(
            Counters::get(&conn)
                .unwrap()
                .num_mint_txs_without_matching_mint_config(),
            2
        );

        assert_eq!(
            Counters::get(&conn)
                .unwrap()
                .num_mismatching_mints_and_deposits(),
            0
        );
        Counters::inc_num_mismatching_mints_and_deposits(&conn).unwrap();
        Counters::inc_num_mismatching_mints_and_deposits(&conn).unwrap();
        Counters::inc_num_mismatching_mints_and_deposits(&conn).unwrap();
        assert_eq!(
            Counters::get(&conn)
                .unwrap()
                .num_mismatching_mints_and_deposits(),
            3
        );

        assert_eq!(
            Counters::get(&conn)
                .unwrap()
                .num_unknown_ethereum_token_deposits(),
            0
        );
        Counters::inc_num_unknown_ethereum_token_deposits(&conn).unwrap();
        Counters::inc_num_unknown_ethereum_token_deposits(&conn).unwrap();
        Counters::inc_num_unknown_ethereum_token_deposits(&conn).unwrap();
        Counters::inc_num_unknown_ethereum_token_deposits(&conn).unwrap();
        assert_eq!(
            Counters::get(&conn)
                .unwrap()
                .num_unknown_ethereum_token_deposits(),
            4
        );
    }
}
