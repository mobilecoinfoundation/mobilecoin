// Copyright (c) 2018-2022 The MobileCoin FoundationD
//

use crate::{
    db::{schema::gnosis_safe_withdrawals, Conn},
    error::Error,
};
use diesel::prelude::*;
use mc_crypto_keys::CompressedRistrettoPublic;
use serde::{Deserialize, Serialize};

/// Diesel model for the `gnosis_safe_withdrawals` table.
/// This table stores withdrawals into the monitored gnosis safe.
#[derive(
    Clone, Debug, Default, Deserialize, Eq, Hash, Insertable, PartialEq, Queryable, Serialize,
)]
pub struct GnosisSafeWithdrawal {
    /// Id (required to keep Diesel happy).
    id: Option<i32>,

    /// Ethereum transaction hash.
    eth_tx_hash: String,

    /// Ethereum block number.
    eth_block_number: i64,

    /// Gnosis safe address being withdrawn from.
    safe_address: String,

    /// Token contract address that is being withdrawn.
    token_address: String,

    /// Amount withdrawan.
    amount: i64,

    /// Associated mobilecoin transaction public key (hex-encoded).
    mc_tx_out_public_key_hex: String,
}

impl GnosisSafeWithdrawal {
    /// Construct a new [GnosisSafeWithdrawal] object.
    pub fn new(
        id: Option<i32>,
        eth_tx_hash: String,
        eth_block_number: u64,
        safe_address: String,
        token_address: String,
        amount: u64,
        mc_tx_out_public_key_hex: String,
    ) -> Self {
        Self {
            id,
            eth_tx_hash,
            eth_block_number: eth_block_number as i64,
            safe_address,
            token_address,
            amount: amount as i64,
            mc_tx_out_public_key_hex,
        }
    }

    /// Get id.
    pub fn id(&self) -> Option<i32> {
        self.id
    }

    /// Get ethereum transaction hash.
    pub fn eth_tx_hash(&self) -> &str {
        &self.eth_tx_hash
    }

    /// Get ethereum block number.
    pub fn eth_block_number(&self) -> u64 {
        self.eth_block_number as u64
    }

    /// Get safe address.
    pub fn safe_address(&self) -> &str {
        &self.safe_address
    }

    /// Get token address.
    pub fn token_address(&self) -> &str {
        &self.token_address
    }

    /// Get amount withdrawan.
    pub fn amount(&self) -> u64 {
        self.amount as u64
    }

    /// Get associated mobilecoin transaction public key (hex-encoded).
    pub fn mc_tx_out_public_key_hex(&self) -> &str {
        &self.mc_tx_out_public_key_hex
    }

    /// Get the associated mobilecoin transaction public key
    pub fn mc_tx_out_public_key(&self) -> Result<CompressedRistrettoPublic, Error> {
        let key_bytes = hex::decode(&self.mc_tx_out_public_key_hex)?;
        Ok(CompressedRistrettoPublic::try_from(&key_bytes[..])?)
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
