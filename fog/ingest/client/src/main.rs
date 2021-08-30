// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Fog Ingest client

use mc_common::logger::{create_root_logger, log, Logger};
use mc_crypto_keys::CompressedRistrettoPublic;
use mc_fog_api::ingest_common::IngestSummary;
use mc_fog_ingest_client::{
    config::{IngestConfig, IngestConfigCommand},
    ClientResult, FogIngestGrpcClient,
};
use mc_fog_uri::FogIngestUri;
use serde_json::json;
use std::{str::FromStr, sync::Arc};
use structopt::StructOpt;

fn main() -> ClientResult<()> {
    // Logging must go to stderr to not interfere with STDOUT
    std::env::set_var("MC_LOG_STDERR", "1");
    let logger = create_root_logger();

    let config = IngestConfig::from_args();

    let grpcio_env = Arc::new(grpcio::EnvBuilder::new().build());

    let uri = FogIngestUri::from_str(&config.uri).expect("failed to parse uri");

    let ingest_client =
        FogIngestGrpcClient::new(uri, config.retry_seconds, grpcio_env, logger.clone());

    match config.cmd {
        IngestConfigCommand::GetStatus => get_status(&logger, &ingest_client),

        IngestConfigCommand::NewKeys => new_keys(&logger, &ingest_client),

        IngestConfigCommand::SetPubkeyExpiryWindow {
            pubkey_expiry_window,
        } => set_pubkey_expiry_window(&logger, &ingest_client, pubkey_expiry_window),

        IngestConfigCommand::SetPeers { peer_uris } => {
            set_peers(&logger, &ingest_client, &peer_uris)
        }
        IngestConfigCommand::Activate => activate(&logger, &ingest_client),
        IngestConfigCommand::Retire => retire(&logger, &ingest_client),
        IngestConfigCommand::Unretire => unretire(&logger, &ingest_client),

        IngestConfigCommand::ReportLostIngressKey { key } => {
            report_lost_ingress_key(&logger, &ingest_client, key)
        }

        IngestConfigCommand::GetMissedBlockRanges => {
            get_missed_block_ranges(&logger, &ingest_client)
        }
    }
}

fn get_status(logger: &Logger, ingest_client: &FogIngestGrpcClient) -> ClientResult<()> {
    let status = ingest_client.get_status().expect("rpc failed");
    log::info!(logger, "Status: {:?}", status);
    println!("{}", ingest_summary_to_json(&status));
    Ok(())
}

fn new_keys(logger: &Logger, ingest_client: &FogIngestGrpcClient) -> ClientResult<()> {
    let status = ingest_client.new_keys().expect("rpc failed");
    log::info!(logger, "Done, status: {:?}", status);
    println!("{}", ingest_summary_to_json(&status));
    Ok(())
}

fn set_pubkey_expiry_window(
    logger: &Logger,
    ingest_client: &FogIngestGrpcClient,
    pubkey_expiry_window: u64,
) -> ClientResult<()> {
    let status = ingest_client
        .set_pubkey_expiry_window(pubkey_expiry_window)
        .expect("rpc failed");
    log::info!(logger, "Done, status: {:?}", status);
    println!("{}", ingest_summary_to_json(&status));
    Ok(())
}

fn set_peers(
    logger: &Logger,
    ingest_client: &FogIngestGrpcClient,
    peer_uris: &[String],
) -> ClientResult<()> {
    let status = ingest_client.set_peers(peer_uris).expect("rpc failed");
    log::info!(logger, "Done, status: {:?}", status);
    println!("{}", ingest_summary_to_json(&status));
    Ok(())
}

fn activate(logger: &Logger, ingest_client: &FogIngestGrpcClient) -> ClientResult<()> {
    let status = ingest_client.activate().expect("rpc failed");
    log::info!(logger, "Done, status: {:?}", status);
    println!("{}", ingest_summary_to_json(&status));
    Ok(())
}

fn retire(logger: &Logger, ingest_client: &FogIngestGrpcClient) -> ClientResult<()> {
    let status = ingest_client.retire().expect("rpc failed");
    log::info!(logger, "Done, status: {:?}", status);
    println!("{}", ingest_summary_to_json(&status));
    Ok(())
}

fn unretire(logger: &Logger, ingest_client: &FogIngestGrpcClient) -> ClientResult<()> {
    let status = ingest_client.unretire().expect("rpc failed");
    log::info!(logger, "Done, status: {:?}", status);
    println!("{}", ingest_summary_to_json(&status));
    Ok(())
}

fn report_lost_ingress_key(
    logger: &Logger,
    ingest_client: &FogIngestGrpcClient,
    key: CompressedRistrettoPublic,
) -> ClientResult<()> {
    ingest_client
        .report_lost_ingress_key(key)
        .expect("Failed reporting lost ingress key");
    log::info!(logger, "Ingress key {:?} reported lost successfully", key);
    Ok(())
}

fn get_missed_block_ranges(
    logger: &Logger,
    ingest_client: &FogIngestGrpcClient,
) -> ClientResult<()> {
    let missed_block_ranges = ingest_client
        .get_missed_block_ranges()
        .expect("Failed getting missed block ranges");

    for range in missed_block_ranges.iter() {
        log::info!(logger, "[{}-{})", range.start_block, range.end_block);
    }

    println!(
        "{}",
        json!(missed_block_ranges
            .iter()
            .map(|range| json!({
                "start_block": range.start_block,
                "end_block": range.end_block,
            }))
            .collect::<Vec<_>>())
    );

    Ok(())
}

fn ingest_summary_to_json(summary: &IngestSummary) -> String {
    json!({
        "mode": format!("{:?}", summary.mode),
        "next_block_index": summary.next_block_index,
        "pubkey_expiry_window": summary.pubkey_expiry_window,
        "ingress_pubkey": hex::encode(summary.get_ingress_pubkey().get_data()),
        "egress_pubkey": hex::encode(summary.get_egress_pubkey()),
        "kex_rng_version": summary.kex_rng_version,
        "peers": summary.get_peers(),
        "ingest_invocation_id": summary.ingest_invocation_id,
    })
    .to_string()
}
