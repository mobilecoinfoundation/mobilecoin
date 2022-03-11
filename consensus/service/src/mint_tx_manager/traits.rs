// Copyright (c) 2018-2022 The MobileCoin Foundation

//! TODO

use crate::mint_tx_manager::MintTxManagerResult;
use mc_transaction_core::mint::MintConfigTx;

#[cfg(test)]
use mockall::*;

#[cfg_attr(test, automock)]
pub trait MintTxManager: Send {
    /// Validate a MintConfigTx transaction against the current ledger.
    fn validate_mint_config_tx(&self, mint_config_tx: &MintConfigTx) -> MintTxManagerResult<()>;

    /// TODO
    fn combine_mint_config_txs(
        &self,
        txs: &[MintConfigTx],
    ) -> MintTxManagerResult<Vec<MintConfigTx>>;
}
