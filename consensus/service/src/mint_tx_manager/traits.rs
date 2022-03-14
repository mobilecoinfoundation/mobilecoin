// Copyright (c) 2018-2022 The MobileCoin Foundation

//! MintTxManager provides the backend for the mc-consensus-scp validation and
//! combine callbacks.

use crate::mint_tx_manager::MintTxManagerResult;
use mc_transaction_core::mint::MintConfigTx;

#[cfg(test)]
use mockall::*;

#[cfg_attr(test, automock)]
pub trait MintTxManager: Send {
    /// Validate a MintConfigTx transaction against the current ledger.
    fn validate_mint_config_tx(&self, mint_config_tx: &MintConfigTx) -> MintTxManagerResult<()>;

    /// Combines a set of "candidate values" into a "composite value".
    /// This assumes all values are well-formed and safe to append to the ledger
    /// individually.
    ///
    /// # Arguments
    /// * `txs` - "Candidate" transactions. Each is assumed to be individually
    ///   valid.
    /// * `max_elements` - Maximal number of elements to output.
    ///
    /// Returns a bounded, deterministically-ordered list of transactions that
    /// are safe to append to the ledger.
    fn combine_mint_config_txs(
        &self,
        txs: &[MintConfigTx],
        max_elements: usize,
    ) -> MintTxManagerResult<Vec<MintConfigTx>>;
}
