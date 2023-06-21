// Copyright (c) 2018-2023 The MobileCoin Foundation

use clap::Parser;
use grpcio::EnvBuilder;
use mc_attest_verifier::{Verifier, DEBUG_ENCLAVE};
use mc_common::logger::{create_root_logger, log, Logger};
use mc_fog_uri::{ConnectionUri, FogViewUri};
use mc_fog_view_connection::FogViewGrpcClient;
use mc_fog_view_protocol::FogViewConnection;
use mc_util_grpc::GrpcRetryConfig;
use std::sync::Arc;

/// Parser for fog-view-client binary
#[derive(Clone, Debug, Parser)]
#[clap(
    name = "fog-view-client",
    about = "Test client for Fog view service.",
    version
)]
struct Config {
    /// Fog View service URI.
    #[clap(long, env = "MC_FOG_VIEW")]
    pub fog_view: FogViewUri,
}

fn main() {
    // Logging must go to stderr to not interfere with STDOUT
    std::env::set_var("MC_LOG_STDERR", "1");
    let config = Config::parse();
    let logger = create_root_logger();

    let mut grpc_client = build_fog_view_conn(config.fog_view, logger.clone());

    match grpc_client.request(0, 0, vec![]) {
        Ok(resp) => {
            log::info!(logger, "Got response:\n{:?}", resp);
            log::info!(
                logger,
                "Highest processed block count: {}",
                resp.highest_processed_block_count
            );
            log::info!(logger, "Num rng records: {}", resp.rng_records.len());
            log::info!(
                logger,
                "Num rng decommissioned: {}",
                resp.decommissioned_ingest_invocations.len()
            );
            log::info!(
                logger,
                "Num missed block events: {}",
                resp.missed_block_ranges.len()
            );
            let total_missed_blocks: u64 = resp
                .missed_block_ranges
                .iter()
                .map(|range| range.end_block - range.start_block + 1)
                .sum();
            log::info!(logger, "Total missed blocks: {}", total_missed_blocks);
        }
        Err(err) => {
            log::error!(logger, "Got error:\n{}", err);
        }
    }
}

fn build_fog_view_conn(fog_view_address: FogViewUri, logger: Logger) -> FogViewGrpcClient {
    let verifier = get_fog_view_verifier();

    let chain_id = "".to_owned();
    let grpc_retry_config = GrpcRetryConfig::default();

    let grpc_env = Arc::new(
        EnvBuilder::new()
            .name_prefix(format!("client-{}", fog_view_address.addr()))
            .build(),
    );

    log::info!(logger, "Fog view attestation verifier: {:?}", verifier);

    FogViewGrpcClient::new(
        chain_id,
        fog_view_address,
        grpc_retry_config,
        verifier,
        grpc_env,
        logger,
    )
}

// Get fog view verifier (dynamic or build time, MRSIGNER)
fn get_fog_view_verifier() -> Verifier {
    //let mr_signer_verifier =
    // mc_fog_view_enclave_measurement::get_mr_signer_verifier(None);

    let mut verifier = Verifier::default();
    verifier.debug(DEBUG_ENCLAVE); //.mr_signer(mr_signer_verifier);
    verifier
}
