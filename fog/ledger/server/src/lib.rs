// Copyright (c) 2018-2022 The MobileCoin Foundation

#![allow(clippy::result_large_err)]
pub use block_service::BlockService;
pub use config::{LedgerRouterConfig, LedgerStoreConfig, ShardingStrategy};
pub use key_image_service::KeyImageService;
pub use key_image_store_server::KeyImageStoreServer;
pub use merkle_proof_service::MerkleProofService;
pub use router_server::LedgerRouterServer;
pub use untrusted_tx_out_service::UntrustedTxOutService;

pub mod sharding_strategy;

mod block_service;
mod config;
mod counters;
mod db_fetcher;
mod error;
mod key_image_service;
mod key_image_store_server;
mod merkle_proof_service;
mod router_admin_service;
mod router_handlers;
mod router_server;
mod router_service;
mod untrusted_tx_out_service;

use mc_util_metrics::ServiceMetrics;

lazy_static::lazy_static! {
    pub static ref SVC_COUNTERS: ServiceMetrics = ServiceMetrics::new_and_registered("fog_ledger_service");
}

/// State that we want to expose from the db poll thread
#[derive(Debug, Default)]
pub struct DbPollSharedState {
    /// The highest block count for which we can guarantee we have loaded all
    /// available data.
    pub highest_processed_block_count: u64,

    /// The cumulative txo count of the last known block.
    pub last_known_block_cumulative_txo_count: u64,

    /// The latest value of `block_version` in the blockchain
    pub latest_block_version: u32,
}
