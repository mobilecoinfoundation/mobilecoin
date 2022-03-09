// Copyright (c) 2018-2022 The MobileCoin Foundation

//! TODO

use crate::mint_tx_manager::MintTxManagerResult;
use mc_transaction_core::mint::SetMintConfigTx;

#[cfg(test)]
use mockall::*;

#[cfg_attr(test, automock)]
pub trait MintTxManager: Send {
    /// Validate a SetMintConfigTx transaction against the current ledger.
    fn validate_set_mint_config_tx(
        &self,
        set_mint_config_tx: &SetMintConfigTx,
    ) -> MintTxManagerResult<()>;

    /// TODO
    fn combine_set_mint_config_txs(
        &self,
        txs: &[SetMintConfigTx],
    ) -> MintTxManagerResult<Vec<SetMintConfigTx>>;
}
