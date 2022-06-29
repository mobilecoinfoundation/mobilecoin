// Copyright (c) 2018-2022 The MobileCoin Foundation

use crate::{
    db::{
        last_insert_rowid,
        models::{SqlEthAddr, SqlEthTxHash},
        schema::gnosis_safe_deposits,
        Conn,
    },
    error::Error,
    gnosis::{EthAddr, EthTxHash},
    MintTxNonce,
};
use diesel::prelude::*;
use serde::{Deserialize, Serialize};

/// Diesel model for the `gnosis_safe_deposits` table.
/// This table stores deposits into the monitored gnosis safe.
#[derive(
    Clone, Debug, Default, Deserialize, Eq, Hash, Insertable, PartialEq, Queryable, Serialize,
)]
pub struct GnosisSafeDeposit {
    /// Id (required to keep Diesel happy).
    id: Option<i32>,

    /// Ethereum transaction hash.
    eth_tx_hash: SqlEthTxHash,

    /// Ethereum block number.
    eth_block_number: i64,

    /// Gnosis safe address receiving the deposit.
    safe_addr: SqlEthAddr,

    /// Token contract address that is being deposited.
    token_addr: SqlEthAddr,

    /// Amount deposited.
    amount: i64,

    /// The hex-encoded MintTx nonce we expect to see on the MobileCoin
    /// blockchain
    expected_mc_mint_tx_nonce_hex: String,
}

impl GnosisSafeDeposit {
    /// Construct a new [GnosisSafeDeposit] object.
    pub fn new(
        id: Option<i32>,
        eth_tx_hash: EthTxHash,
        eth_block_number: u64,
        safe_addr: EthAddr,
        token_addr: EthAddr,
        amount: u64,
    ) -> Self {
        let expected_mc_mint_tx_nonce = MintTxNonce::EthereumGnosisDeposit(eth_tx_hash);
        let expected_mc_mint_tx_nonce_hex = hex::encode(expected_mc_mint_tx_nonce.to_bytes());
        Self {
            id,
            eth_tx_hash: eth_tx_hash.into(),
            eth_block_number: eth_block_number as i64,
            safe_addr: safe_addr.into(),
            token_addr: token_addr.into(),
            amount: amount as i64,
            expected_mc_mint_tx_nonce_hex,
        }
    }

    /// Get id.
    pub fn id(&self) -> Option<i32> {
        self.id
    }

    /// Get Ethereum transaction hash.
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

    /// Get amount deposited.
    pub fn amount(&self) -> u64 {
        self.amount as u64
    }

    /// Get the hex-encoded MintTx nonce we expect to see on the MobileCoin
    /// blockchain.
    pub fn expected_mc_mint_tx_nonce_hex(&self) -> &str {
        &self.expected_mc_mint_tx_nonce_hex
    }

    /// Insert a deposit into the database.
    pub fn insert(&mut self, conn: &Conn) -> Result<(), Error> {
        if let Some(id) = self.id {
            return Err(Error::AlreadyExists(format!(
                "GnosisSafeDeposit already has an id ({})",
                id
            )));
        }

        diesel::insert_into(gnosis_safe_deposits::table)
            .values(self.clone())
            .execute(conn)?;

        self.id = Some(diesel::select(last_insert_rowid).get_result::<i32>(conn)?);

        Ok(())
    }
}
