// Copyright (c) 2018-2022 The MobileCoin Foundation

use crate::{
    db::{schema::gnosis_safe_withdrawals, Conn},
    error::Error,
};
use diesel::prelude::*;
use serde::{Deserialize, Serialize};

/// Diesel model for the `gnosis_safe_withdrawals` table.
/// This table stores withdrawals into the monitored gnosis safe.
#[derive(Debug, Deserialize, Eq, Insertable, PartialEq, Queryable, Serialize)]
pub struct GnosisSafeWithdrawal {
    /// Id (required to keep Diesel happy).
    pub id: Option<i32>,

    /// Ethereum transaction hash.
    pub eth_tx_hash: String,

    /// Ethereum block number.
    pub eth_block_number: i64,

    /// Gnosis safe address  being withdrawn from.
    pub safe_address: String,

    /// Token contract address that is being withdrawn.
    pub token_address: String,

    /// Amount withdrawan.
    pub amount: i64,

    /// Associated mobilecoin transaction public key (hex-encoded).
    pub mc_tx_out_public_key_hex: String,
}

impl GnosisSafeWithdrawal {
    /// Get amount withdrawan.
    pub fn amount(&self) -> u64 {
        self.amount as u64
    }

    /// Get ethereum block number.
    pub fn eth_block_number(&self) -> u64 {
        self.eth_block_number as u64
    }
}

impl GnosisSafeWithdrawal {
    /// Insert a withdrawal into the database.
    /// This consumes the object since we are not back-filling the id field.
    pub fn insert(self, conn: &Conn) -> Result<(), Error> {
        diesel::insert_into(gnosis_safe_withdrawals::table)
            .values(self)
            .execute(conn)?;

        Ok(())
    }
}
