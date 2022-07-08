// Copyright (c) 2018-2022 The MobileCoin FoundationD
//

use crate::{
    db::{
        last_insert_rowid,
        models::{SqlEthAddr, SqlEthTxHash},
        schema::{audited_burns, gnosis_safe_withdrawals},
        Conn,
    },
    error::Error,
    gnosis::{EthAddr, EthTxHash},
};
use diesel::{
    dsl::{exists, not},
    prelude::*,
};
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
    eth_tx_hash: SqlEthTxHash,

    /// Ethereum block number.
    eth_block_number: i64,

    /// Gnosis safe address being withdrawn from.
    safe_addr: SqlEthAddr,

    /// Token contract address that is being withdrawn.
    token_addr: SqlEthAddr,

    /// Amount withdrawan.
    amount: i64,

    /// Associated mobilecoin transaction public key (hex-encoded).
    mc_tx_out_public_key_hex: String,
}

impl GnosisSafeWithdrawal {
    /// Construct a new [GnosisSafeWithdrawal] object.
    pub fn new(
        id: Option<i32>,
        eth_tx_hash: EthTxHash,
        eth_block_number: u64,
        safe_addr: EthAddr,
        token_addr: EthAddr,
        amount: u64,
        mc_tx_out_public_key_hex: String,
    ) -> Self {
        Self {
            id,
            eth_tx_hash: eth_tx_hash.into(),
            eth_block_number: eth_block_number as i64,
            safe_addr: safe_addr.into(),
            token_addr: token_addr.into(),
            amount: amount as i64,
            mc_tx_out_public_key_hex,
        }
    }

    /// Get id.
    pub fn id(&self) -> Option<i32> {
        self.id
    }

    /// Get ethereum transaction hash.
    pub fn eth_tx_hash(&self) -> &EthTxHash {
        &self.eth_tx_hash
    }

    /// Get ethereum block number.
    pub fn eth_block_number(&self) -> u64 {
        self.eth_block_number as u64
    }

    /// Get safe address.
    pub fn safe_addr(&self) -> &EthAddr {
        &self.safe_addr
    }

    /// Get token address.
    pub fn token_addr(&self) -> &EthAddr {
        &self.token_addr
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

    /// Insert a withdrawal into the database.
    pub fn insert(&mut self, conn: &Conn) -> Result<(), Error> {
        if let Some(id) = self.id {
            return Err(Error::AlreadyExists(format!(
                "GnosisSafeWithdrawal already has an id ({})",
                id
            )));
        }

        diesel::insert_into(gnosis_safe_withdrawals::table)
            .values(self.clone())
            .execute(conn)?;

        self.id = Some(diesel::select(last_insert_rowid).get_result::<i32>(conn)?);

        Ok(())
    }

    // TODO tests for this (copy from GnosisSafeWithdrawal)
    /// Attempt to find a [GnosisSafeWithdrawal] that has a given nonce and no
    /// matching entry in the `audited_burns` table.
    pub fn find_unaudited_withdrawal_by_public_key(
        public_key_hex: &str,
        conn: &Conn,
    ) -> Result<Option<Self>, Error> {
        Ok(gnosis_safe_withdrawals::table
            .filter(gnosis_safe_withdrawals::mc_tx_out_public_key_hex.eq(public_key_hex))
            .filter(not(exists(
                audited_burns::table
                    .select(audited_burns::gnosis_safe_withdrawal_id)
                    .filter(
                        audited_burns::gnosis_safe_withdrawal_id
                            .nullable()
                            .eq(gnosis_safe_withdrawals::id),
                    ),
            )))
            .first(conn)
            .optional()?)
    }
}
