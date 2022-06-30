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

    /// Number of blocks synced so far.
    num_blocks_synced: i64,

    /// Number of burn transactions that exceeded the minted amount.
    num_burns_exceeding_balance: i64,

    /// Number of mint transactions that did not match an active mint
    /// configuration.
    num_mint_txs_without_matching_mint_config: i64,

    /// Number of mismatching MintTxs and Gnosis deposits.
    num_mismatching_mints_and_deposits: i64,

    /// Number of times we encountered deposits to an unknown Ethereum token
    /// contract address.
    num_unknown_ethereum_token_deposits: i64,

    /// Number of times we encountered a mint that is associated with an
    /// unaudited safe.
    num_mints_to_unknown_safe: i64,

    /// Number of unexpected errors attempting to match deposits to mints.
    num_unexpected_errors_matching_deposits_to_mints: i64,

    // Number of unexpected errors attempting to match mints to deposits.
    num_unexpected_errors_matching_mints_to_deposits: i64,
}

// A helper macro for DRYING up get/inc methods for each counter.
// Unfortunately we need to pass both the member name (which ends being the
// getter method name) and the increment method name, since Rust macros do not
// currently support identifier concatenation.
macro_rules! impl_get_and_inc {
    ($( $var_name:ident $inc_fn_name:ident $(,)?)+) => (
        impl Counters {
            $(
                /// Get $var_name.
                pub fn $var_name(&self) -> u64 {
                    self.$var_name as u64
                }

                /// Atomically increase $var_name.
                pub fn $inc_fn_name(conn: &Conn) -> Result<(), Error> {
                    match diesel::update(counters::table)
                        .set(counters::$var_name.eq(counters::$var_name + 1))
                        .execute(conn)?
                    {
                        0 => Err(Error::NotFound),
                        1 => Ok(()),
                        num_rows => Err(Error::Other(format!(
                            "$var_name: unexpected number of rows ({})",
                            num_rows
                        ))),
                    }
                }
            )+
        }
    )
}

impl_get_and_inc! {
    num_blocks_synced inc_num_blocks_synced,
    num_burns_exceeding_balance inc_num_burns_exceeding_balance,
    num_mint_txs_without_matching_mint_config inc_num_mint_txs_without_matching_mint_config,
    num_mismatching_mints_and_deposits inc_num_mismatching_mints_and_deposits,
    num_unknown_ethereum_token_deposits inc_num_unknown_ethereum_token_deposits,
    num_mints_to_unknown_safe inc_num_mints_to_unknown_safe,
    num_unexpected_errors_matching_deposits_to_mints inc_num_unexpected_errors_matching_deposits_to_mints,
    num_unexpected_errors_matching_mints_to_deposits inc_num_unexpected_errors_matching_mints_to_deposits,
}

impl Counters {
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
        prom_counters::NUM_MINTS_TO_UNKNOWN_SAFE.set(self.num_mints_to_unknown_safe);
        prom_counters::NUM_UNEXPECTED_ERRORS_MATCHING_DEPOSITS_TO_MINTS
            .set(self.num_unexpected_errors_matching_deposits_to_mints);
        prom_counters::NUM_UNEXPECTED_ERRORS_MATCHING_MINTS_TO_DEPOSITS
            .set(self.num_unexpected_errors_matching_mints_to_deposits);
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

        // Since all get/inc methods are implemented the same way we don't need to test
        // each and every one. We test two just to see they are not affecting
        // eachother.
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
    }
}
