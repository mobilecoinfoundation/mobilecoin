// Copyright (c) 2018-2023 The MobileCoin Foundation

use clap::{Parser, Subcommand};
use clio::Output;
use grpcio::{ChannelBuilder, EnvBuilder};
use mc_api::blockchain::ArchiveBlocks;
use mc_blockchain_types::{BlockID, BlockIndex};
use mc_common::{
    logger::{create_app_logger, log, o, Logger},
    ResponderId,
};
use mc_consensus_api::{
    consensus_client_grpc::ConsensusClientApiClient, consensus_common_grpc::BlockchainApiClient,
};
use mc_ledger_sync::ReqwestTransactionsFetcher;
use mc_light_client_verifier::{
    HexKeyNodeID, LightClientVerifier, LightClientVerifierConfig, QuorumSet,
    TrustedValidatorSetConfig,
};
use mc_util_grpc::ConnectionUriGrpcioChannel;
use mc_util_uri::ConsensusClientUri;
use protobuf::Message;
use rayon::{iter::ParallelIterator, prelude::IntoParallelIterator};
use std::{collections::BTreeSet, fs, io::Write, path::PathBuf, str::FromStr, sync::Arc};

/// File formats supported by the `FetchBlocks` command.
#[derive(Clone, Copy, Debug, PartialEq, clap::ValueEnum)]
pub enum FileFormat {
    /// ArchiveBlocks protobuf
    ArchiveBlocksProtobuf,

    /// JSON containing an array of arrays, where each inner array is a list of
    /// bytes containing a protobuf-encoded BlockData.
    JsonBlockDataBytesArray,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Generate a light client verifier config from a list of nodes.
    /// This does not include any historical data.
    GenerateConfig {
        /// Node URIs to use for generating the config.
        #[clap(long = "node", use_value_delimiter = true, env = "MC_NODES")]
        nodes: Vec<ConsensusClientUri>,

        /// File to write the config to.
        #[clap(long, env = "MC_OUT_FILE", value_parser, default_value = "-")]
        out_file: Output,

        /// Known valid block ids to include in the config.
        #[clap(
            long = "known-valid-block-id",
            use_value_delimiter = true,
            env = "MC_KNOWN_VALID_BLOCK_IDS",
            value_parser = block_id_from_hex_str,
        )]
        known_valid_block_ids: Vec<BlockID>,
    },

    /// Fetch blocks from a list of tx source urls and store them in a file.
    FetchBlocks {
        /// URLs to use for fetching blocks.
        ///
        /// For example: https://ledger.mobilecoinww.com/node1.prod.mobilecoinww.com
        #[clap(
            long = "tx-source-url",
            use_value_delimiter = true,
            env = "MC_TX_SOURCE_URLS"
        )]
        tx_source_urls: Vec<String>,

        /// Block index we are interested in.
        #[clap(long, env = "MC_BLOCK_INDEX")]
        block_index: BlockIndex,

        /// File to write the fetched ArchiveBlocks protobuf to.
        #[clap(long, env = "MC_OUT_FILE", value_parser)]
        out_file: Output,

        /// File format to use for the output file.
        #[clap(long, env = "MC_OUT_FILE_FORMAT")]
        out_file_format: FileFormat,

        /// Optional LightClientVerifierConfig to use for verifying the fetched
        /// blocks before writing them to disk.
        #[clap(long, env = "MC_LIGHT_CLIENT_VERIFIER_CONFIG")]
        light_client_verifier_config: Option<PathBuf>,
    },
}

#[derive(Parser)]
#[clap(
    name = "mc-light-client-cli",
    about = "MobileCoin Light Client CLI utility"
)]
pub struct Config {
    #[clap(subcommand)]
    pub command: Commands,
}

fn main() {
    let (logger, _global_logger_guard) = create_app_logger(o!());
    let config = Config::parse();

    match config.command {
        Commands::GenerateConfig {
            nodes,
            out_file,
            known_valid_block_ids,
        } => {
            cmd_generate_config(nodes, out_file, known_valid_block_ids, logger);
        }

        Commands::FetchBlocks {
            tx_source_urls,
            block_index,
            out_file,
            out_file_format,
            light_client_verifier_config,
        } => {
            cmd_fetch_blocks(
                tx_source_urls,
                block_index,
                out_file,
                out_file_format,
                light_client_verifier_config,
                logger,
            );
        }
    }
}

fn cmd_generate_config(
    nodes: Vec<ConsensusClientUri>,
    mut out_file: Output,
    known_valid_block_ids: Vec<BlockID>,
    logger: Logger,
) {
    let env = Arc::new(EnvBuilder::new().name_prefix("light-client-grpc").build());

    let (node_configs, last_block_infos): (Vec<_>, Vec<_>) = nodes
        .iter()
        .map(|node_uri| {
            // TODO should this use ThickClient and chain-id?
            let ch = ChannelBuilder::default_channel_builder(env.clone())
                .connect_to_uri(node_uri, &logger);

            let client_api = ConsensusClientApiClient::new(ch.clone());
            let config = client_api
                .get_node_config(&Default::default())
                .expect("get_node_config failed");

            let blockchain_api = BlockchainApiClient::new(ch);
            let last_block_info = blockchain_api
                .get_last_block_info(&Default::default())
                .expect("get_last_block_info failed");

            (config, last_block_info)
        })
        .unzip();

    let node_ids = node_configs
        .iter()
        .map(|node_config| HexKeyNodeID {
            responder_id: ResponderId::from_str(node_config.get_peer_responder_id()).unwrap(),
            public_key: node_config
                .get_scp_message_signing_key()
                .try_into()
                .unwrap(),
        })
        .collect::<Vec<_>>();

    let quorum_set = QuorumSet {
        threshold: node_configs.len() as u32,
        members: node_ids.into_iter().map(Into::into).collect(),
    };

    let trusted_validator_set = TrustedValidatorSetConfig { quorum_set };

    let trusted_validator_set_start_block = last_block_infos
        .iter()
        .map(|last_block_info| last_block_info.index)
        .max()
        .unwrap_or_default();

    let light_client_verifier = LightClientVerifierConfig {
        trusted_validator_set,
        trusted_validator_set_start_block,
        historical_validator_sets: Default::default(),
        known_valid_block_ids: BTreeSet::from_iter(known_valid_block_ids),
    };

    out_file
        .write_all(
            serde_json::to_string_pretty(&light_client_verifier)
                .unwrap()
                .as_bytes(),
        )
        .expect("failed writing config to file");
}

fn cmd_fetch_blocks(
    tx_source_urls: Vec<String>,
    block_index: u64,
    mut out_file: Output,
    out_file_format: FileFormat,
    light_client_verifier_config_path: Option<PathBuf>,
    logger: Logger,
) {
    let block_data = tx_source_urls
        .into_par_iter()
        .map(|url| {
            log::info!(logger, "Fetching block data from {}", url);
            let rts = ReqwestTransactionsFetcher::new(vec![url], logger.clone())
                .expect("failed creating ReqwestTransactionsFetcher");
            rts.get_block_data_by_index(block_index, None)
                .expect("failed fetching block data")
        })
        .collect::<Vec<_>>();

    if let Some(path) = light_client_verifier_config_path {
        let json_data =
            fs::read_to_string(path).expect("failed reading LightClientVerifierConfig file");
        let light_client_verifier_config: LightClientVerifierConfig =
            serde_json::from_str(&json_data).expect("failed parsing LightClientVerifierConfig");
        let light_client_verifier = LightClientVerifier::from(light_client_verifier_config);

        light_client_verifier
            .verify_block_data(&block_data[..])
            .expect("failed verifying block data");
    }

    let bytes = match out_file_format {
        FileFormat::ArchiveBlocksProtobuf => {
            let archive_blocks = ArchiveBlocks::from(&block_data[..]);
            archive_blocks
                .write_to_bytes()
                .expect("failed serializing ArchiveBlocks")
        }

        FileFormat::JsonBlockDataBytesArray => {
            let block_data_bytes = block_data
                .iter()
                .map(|block_data| mc_util_serial::encode(block_data))
                .collect::<Vec<_>>();
            serde_json::to_vec(&block_data_bytes).expect("failed serializing block data bytes")
        }
    };

    out_file
        .write_all(&bytes)
        .expect("failed writing blocks to file");
    log::info!(logger, "Wrote blocks to file {}", out_file.path());

    // Give the logger time to flush :/
    std::thread::sleep(std::time::Duration::from_millis(100));
}

fn block_id_from_hex_str(src: &str) -> Result<BlockID, String> {
    let bytes = hex::decode(src).map_err(|e| format!("failed decoding hex: {}", e))?;
    let block_id =
        BlockID::try_from(bytes).map_err(|e| format!("failed parsing BlockID: {}", e))?;
    Ok(block_id)
}
