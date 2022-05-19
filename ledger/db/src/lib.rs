// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Persistent storage for the blockchain.
#![warn(unused_extern_crates)]
#![feature(test)]

#[cfg(test)]
extern crate test;

mod error;
mod ledger_trait;
mod metrics;
mod mint_config_store;
mod mint_tx_store;

pub mod ledger_db;
#[cfg(any(test, feature = "test_utils"))]
pub mod test_utils;
pub mod tx_out_store;

pub use crate::{
    error::Error,
    ledger_db::{key_bytes_to_u64, u64_to_key_bytes, LedgerDB},
    ledger_trait::{Ledger, MockLedger},
    metrics::LedgerMetrics,
    mint_config_store::{ActiveMintConfig, ActiveMintConfigs, MintConfigStore},
    mint_tx_store::MintTxStore,
    tx_out_store::TxOutStore,
};
pub use mc_util_lmdb::{MetadataStore, MetadataStoreError, MetadataStoreSettings};
