// Copyright (c) 2018-2022 The MobileCoin Foundation

//! TODO

mod error;
mod traits;

pub use error::{MintTxManagerError, MintTxManagerResult};
pub use traits::MintTxManager;

use mc_common::logger::{log, Logger};
use mc_ledger_db::Ledger;
use mc_transaction_core::mint::SetMintConfigTx;

#[derive(Clone)]
pub struct MintTxManagerImpl<L: Ledger> {
    /// Ledger DB.
    ledger_db: L,

    /// Logger.
    logger: Logger,
}

impl<L: Ledger> MintTxManagerImpl<L> {
    pub fn new(ledger_db: L, logger: Logger) -> Self {
        Self { ledger_db, logger }
    }
}

impl<L: Ledger> MintTxManager for MintTxManagerImpl<L> {
    /// Validate a SetMintConfigTx transaction against the current ledger.
    fn validate_set_mint_config_tx(
        &self,
        set_mint_config_tx: &SetMintConfigTx,
    ) -> MintTxManagerResult<()> {
        // TODO actually validate the set_mint_config_tx
        log::crit!(self.logger, "TODO: Validate {:?}", set_mint_config_tx);
        Ok(())
    }

    fn combine_set_mint_config_txs(
        &self,
        txs: &[SetMintConfigTx],
    ) -> MintTxManagerResult<Vec<SetMintConfigTx>> {
        // TODO actually combine the set_mint_config_txs
        log::crit!(self.logger, "TODO: Combine {:?}", txs);
        Ok(txs.to_vec())
    }
}
