// Copyright (c) 2018-2022 The MobileCoin Foundation

use crate::{
    db::{schema::gnosis_safe_deposits, Conn},
    error::Error,
    gnosis::api_data_types::EthereumTransfer,
};
use diesel::prelude::*;
use serde::{Deserialize, Serialize};

/// Diesel model for the `gnosis_safe_deposits` table.
/// This table stores deposits into the monitored gnosis safe.
#[derive(Debug, Deserialize, Eq, Insertable, PartialEq, Queryable, Serialize)]
pub struct GnosisSafeDeposit {
    /// Id (required to keep Diesel happy).
    pub id: Option<i32>,

    /// Ethereum transaction hash.
    pub eth_tx_hash: String,

    /// Ethereum block number.
    pub eth_block_number: i64,

    /// Gnosis safe address receiving the deposit.
    pub safe_address: String,

    /// Token contract address that is being deposited.
    pub token_address: String,

    /// Amount deposited.
    pub amount: i64,
}

impl GnosisSafeDeposit {
    /// Get amount deposited.
    pub fn amount(&self) -> u64 {
        self.amount as u64
    }

    /// Get ethereum block number.
    pub fn eth_block_number(&self) -> u64 {
        self.eth_block_number as u64
    }

    /// Insert an Ethereum transfer as a deposit into the database.
    pub fn insert_eth_transfer(
        eth_block_number: u64,
        api_obj: &EthereumTransfer,
        conn: &Conn,
    ) -> Result<(), Error> {
        let obj = Self {
            id: None,
            eth_tx_hash: api_obj.tx_hash.to_string(),
            eth_block_number: eth_block_number as i64,
            safe_address: api_obj.to.to_string(),
            // Empty token address means ETH
            token_address: api_obj
                .token_address
                .clone()
                .unwrap_or_default()
                .to_string(),
            amount: u64::from(api_obj.value) as i64,
        };

        diesel::insert_into(gnosis_safe_deposits::table)
            .values(obj)
            .execute(conn)?;

        Ok(())
    }
}
