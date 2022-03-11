// Copyright (c) 2018-2022 The MobileCoin Foundation

//! TODO

mod error;
mod traits;

pub use error::{MintTxManagerError, MintTxManagerResult};
pub use traits::MintTxManager;

#[cfg(test)]
pub use traits::MockMintTxManager;

use mc_common::{
    logger::{log, Logger},
    HashMap,
};
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

        // Ensure that we have not seen this transaction before.

        Ok(())
    }

    fn combine_mint_config_txs(
        &self,
        txs: &[MintConfigTx],
    ) -> MintTxManagerResult<Vec<MintConfigTx>> {
        // TODO actually combine the mint_config_txs
        log::crit!(self.logger, "TODO: Combine {:?}", txs);
        Ok(txs.to_vec())
    }
}
