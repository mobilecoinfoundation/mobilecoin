// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Data access abstraction for mint transactions stored in the ledger.
//!
//! This store maintains two LMDB databases:
//! 1) A mapping of block index -> list of mint transactions included in the
//! block.    This is used to provide the mint_txs inside BlockContents.
//! 2) A mapping of hash -> MintTx. This is used to prevent replay attacks.

use crate::{u64_to_key_bytes, Error, MintConfigStore};
use lmdb::{Database, DatabaseFlags, Environment, RwTransaction, Transaction, WriteFlags};
use mc_transaction_core::mint::MintTx;
use mc_util_serial::{decode, encode, Message};

// LMDB Database names.
pub const MINT_TXS_BY_BLOCK_DB_NAME: &str = "mint_tx_store:set_txs_by_block";
pub const MINT_TX_BY_NONCE_DB_NAME: &str = "mint_tx_store:mint_tx_by_nonce";

/// A list of mint-txs that can be prost-encoded. This is needed since that's
/// the only way to encode a Vec<MintTx>.
#[derive(Clone, Message)]
pub struct MintTxList {
    #[prost(message, repeated, tag = "1")]
    pub mint_txs: Vec<MintTx>,
}

#[derive(Clone)]
pub struct MintTxStore {
    /// MintTxs by block.
    mint_txs_by_block: Database,

    /// MintTx by nonce.
    mint_tx_by_nonce: Database,
}

impl MintTxStore {
    /// Opens an existing MintTxStore.
    pub fn new(env: &Environment) -> Result<Self, Error> {
        Ok(MintTxStore {
            mint_txs_by_block: env.open_db(Some(MINT_TXS_BY_BLOCK_DB_NAME))?,
            mint_tx_by_nonce: env.open_db(Some(MINT_TX_BY_NONCE_DB_NAME))?,
        })
    }

    /// Creates a fresh MintTxStore.
    pub fn create(env: &Environment) -> Result<(), Error> {
        env.create_db(Some(MINT_TXS_BY_BLOCK_DB_NAME), DatabaseFlags::empty())?;
        env.create_db(Some(MINT_TX_BY_NONCE_DB_NAME), DatabaseFlags::empty())?;
        Ok(())
    }

    /// Get mint txs in a given block.
    pub fn get_mint_txs_by_block_index(
        &self,
        block_index: u64,
        db_transaction: &impl Transaction,
    ) -> Result<Vec<MintTx>, Error> {
        let mint_txs: MintTxList =
            decode(db_transaction.get(self.mint_txs_by_block, &u64_to_key_bytes(block_index))?)?;
        Ok(mint_txs.mint_txs)
    }

    /// Returns true if the Ledger contains the given mint tx nonce
    pub fn contains_mint_tx_nonce(
        &self,
        nonce: &[u8],
        db_transaction: &impl Transaction,
    ) -> Result<bool, Error> {
        match db_transaction.get(self.mint_tx_by_nonce, &nonce) {
            Ok(_db_bytes) => Ok(true),
            Err(lmdb::Error::NotFound) => Ok(false),
            Err(e) => Err(Error::Lmdb(e)),
        }
    }

    /// Write mint txs in a given block.
    pub fn write_mint_txs(
        &self,
        block_index: u64,
        mint_txs: &[MintTx],
        mint_config_store: &MintConfigStore,
        db_transaction: &mut RwTransaction,
    ) -> Result<(), Error> {
        let block_index_bytes = u64_to_key_bytes(block_index);

        // Store the list of MintTxs.
        let mint_tx_list = MintTxList {
            mint_txs: mint_txs.to_vec(),
        };

        db_transaction.put(
            self.mint_txs_by_block,
            &block_index_bytes,
            &encode(&mint_tx_list),
            WriteFlags::empty(),
        )?;

        // For each mint transaction, we need to locate the matching mint configuration
        // and update the total minted count. We also need to ensure the nonce is
        // unique.
        for mint_tx in mint_txs {
            // Update total minted.
            let active_mint_config =
                mint_config_store.get_active_mint_config_for_mint_tx(mint_tx, db_transaction)?;

            let new_total_minted = active_mint_config.total_minted.checked_add(mint_tx.prefix.amount).expect("shouldn't have failed because get_active_mint_config_for_mint_tx guards against this");

            mint_config_store.update_total_minted(
                &active_mint_config.mint_config,
                new_total_minted,
                db_transaction,
            )?;

            // Ensure nonce uniqueness
            db_transaction.put(
                self.mint_tx_by_nonce,
                &mint_tx.prefix.nonce,
                &encode(mint_tx),
                WriteFlags::NO_OVERWRITE, /* this ensures we do not overwrite a nonce that was
                                           * already used */
            )?;
        }

        Ok(())
    }
}
