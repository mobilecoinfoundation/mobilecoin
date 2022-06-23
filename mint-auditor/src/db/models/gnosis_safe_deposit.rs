// Copyright (c) 2018-2022 The MobileCoin Foundation

use crate::{
    db::{schema::gnosis_safe_deposits, Conn},
    error::Error,
};
use diesel::prelude::*;
use serde::{Deserialize, Serialize};

/// Diesel model for the `gnosis_safe_deposits` table.
/// This table stores deposits into the monitored gnosis safe.
#[derive(Debug, Deserialize, Eq, Insertable, PartialEq, Queryable, Serialize)]
pub struct GnosisSafeDeposit {
    /// Id (required to keep Diesel happy).
    id: Option<i32>,

    /// Ethereum transaction hash.
    eth_tx_hash: String,

    /// Ethereum block number.
    eth_block_number: i64,

    /// Gnosis safe address receiving the deposit.
    safe_address: String,

    /// Token contract address that is being deposited.
    token_address: String,

    /// Amount deposited.
    amount: i64,
}

impl GnosisSafeDeposit {
    /// Construct a new [GnosisSafeDeposit] object.
    pub fn new(
        id: Option<i32>,
        eth_tx_hash: String,
        eth_block_number: u64,
        safe_address: String,
        token_address: String,
        amount: u64,
    ) -> Self {
        Self {
            id,
            eth_tx_hash,
            eth_block_number: eth_block_number as i64,
            safe_address,
            token_address,
            amount: amount as i64,
        }
    }

    /// Get Ethereum transaction hash.
    pub fn eth_tx_hash(&self) -> &str {
        &self.eth_tx_hash
    }

    /// Get ethereum block number.
    pub fn eth_block_number(&self) -> u64 {
        self.eth_block_number as u64
    }

    /// Get safe address.
    pub fn get_safe_address(&self) -> &str {
        &self.safe_address
    }

    /// Get token address.
    pub fn get_token_address(&self) -> &str {
        &self.token_address
    }

    /// Get amount deposited.
    pub fn amount(&self) -> u64 {
        self.amount as u64
    }

    /// Insert a deposit into the database.
    /// This consumes the object since we are not back-filling the id field.
    pub fn insert(self, conn: &Conn) -> Result<(), Error> {
        diesel::insert_into(gnosis_safe_deposits::table)
            .values(self)
            .execute(conn)?;

        Ok(())
    }
}
