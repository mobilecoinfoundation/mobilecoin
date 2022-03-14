// Copyright (c) 2018-2022 The MobileCoin Foundation

//! MintTxManager provides the backend for the mc-consensus-scp validation and
//! combine callbacks.
//!
//! This file contains the actual implementation of the validation and combine
//! logic mint-related transactions.

mod error;
mod traits;

pub use error::{MintTxManagerError, MintTxManagerResult};
pub use traits::MintTxManager;

#[cfg(test)]
pub use traits::MockMintTxManager;

use mc_common::{logger::Logger, HashMap, HashSet};
use mc_crypto_keys::Ed25519Public;
use mc_crypto_multisig::SignerSet;
use mc_ledger_db::Ledger;
use mc_transaction_core::{
    mint::{validate_mint_config_tx, MintConfigTx, MintValidationError},
    BlockVersion, TokenId,
};

#[derive(Clone)]
pub struct MintTxManagerImpl<L: Ledger> {
    /// Ledger DB.
    ledger_db: L,

    /// The configured block version.
    block_version: BlockVersion,

    /// A map of token id -> master minters.
    token_id_to_master_minters: HashMap<TokenId, SignerSet<Ed25519Public>>,

    /// Logger.
    logger: Logger,
}

impl<L: Ledger> MintTxManagerImpl<L> {
    pub fn new(
        ledger_db: L,
        block_version: BlockVersion,
        token_id_to_master_minters: HashMap<TokenId, SignerSet<Ed25519Public>>,
        logger: Logger,
    ) -> Self {
        Self {
            ledger_db,
            block_version,
            token_id_to_master_minters,
            logger,
        }
    }
}

impl<L: Ledger> MintTxManager for MintTxManagerImpl<L> {
    /// Validate a MintConfigTx transaction against the current ledger.
    fn validate_mint_config_tx(&self, mint_config_tx: &MintConfigTx) -> MintTxManagerResult<()> {
        // Ensure that we have not seen this transaction before.
        if self
            .ledger_db
            .check_mint_config_tx_nonce(&mint_config_tx.prefix.nonce)?
            .is_some()
        {
            return Err(MintTxManagerError::MintValidation(
                MintValidationError::NonceAlreadyUsed,
            ));
        }

        // Get the master minters for this token id.
        let token_id = TokenId::from(mint_config_tx.prefix.token_id);
        let master_minters = self.token_id_to_master_minters.get(&token_id).ok_or(
            MintTxManagerError::MintValidation(MintValidationError::NoMasterMinters(token_id)),
        )?;

        // Get the current block index.
        let current_block_index = self.ledger_db.num_blocks()? - 1;

        // Perform the actual validation.
        validate_mint_config_tx(
            mint_config_tx,
            current_block_index,
            self.block_version,
            master_minters,
        )?;

        Ok(())
    }

    fn combine_mint_config_txs(
        &self,
        txs: &[MintConfigTx],
        max_elements: usize,
    ) -> MintTxManagerResult<Vec<MintConfigTx>> {
        let mut seen_nonces = HashSet::default();

        let mut candidates = txs.to_vec();
        candidates.sort();

        let (allowed_txs, _rejected_txs) = candidates.into_iter().partition(|tx| {
            if seen_nonces.len() >= max_elements {
                return false;
            }

            if seen_nonces.contains(&tx.prefix.nonce) {
                return false;
            }

            seen_nonces.insert(tx.prefix.nonce.clone());
            true
        });

        Ok(allowed_txs)
    }
}

// TODO tests
