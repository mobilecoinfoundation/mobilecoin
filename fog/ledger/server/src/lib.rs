// Copyright (c) 2018-2022 The MobileCoin Foundation

#![allow(clippy::result_large_err)]
mod block_service;
mod config;
mod counters;
mod db_fetcher;
mod error;
mod key_image_service;
mod merkle_proof_service;
mod router_admin_service;
mod router_handlers;
mod router_server;
mod router_service;
mod server;
mod untrusted_tx_out_service;

use mc_util_metrics::ServiceMetrics;

pub use block_service::BlockService;
pub use config::{LedgerRouterConfig, LedgerServerConfig};
pub use key_image_service::KeyImageService;
pub use merkle_proof_service::MerkleProofService;
pub use server::LedgerServer;
pub use untrusted_tx_out_service::UntrustedTxOutService;

lazy_static::lazy_static! {
    pub static ref SVC_COUNTERS: ServiceMetrics = ServiceMetrics::new_and_registered("fog_ledger");
}
pub use router_server::LedgerRouterServer;
