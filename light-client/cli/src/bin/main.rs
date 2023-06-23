// Copyright (c) 2018-2023 The MobileCoin Foundation

use clap::{Parser, Subcommand};
use grpcio::{ChannelBuilder, EnvBuilder};
use mc_api::blockchain::ArchiveBlocks;
use mc_blockchain_types::BlockIndex;
use mc_common::{
    logger::{create_app_logger, log, o, Logger},
    ResponderId,
};
use mc_consensus_api::{
    consensus_client_grpc::ConsensusClientApiClient, consensus_common_grpc::BlockchainApiClient,
};
use mc_consensus_scp_types::QuorumSet;
use mc_ledger_sync::ReqwestTransactionsFetcher;
use mc_light_client_verifier::{
    HexKeyNodeID, LightClientVerifierConfig, TrustedValidatorSetConfig,
};
use mc_util_grpc::ConnectionUriGrpcioChannel;
use mc_util_uri::ConsensusClientUri;
use protobuf::Message;
use std::{fs, path::PathBuf, str::FromStr, sync::Arc};

#[derive(Subcommand)]
pub enum Commands {
    /// Generate a light client verifier config from a list of nodes.
    /// This does not include any historical data.
    GenerateConfig {
        /// Node URIs to use for generating the config.
        #[clap(long = "node", use_value_delimiter = true, env = "MC_NODES")]
        nodes: Vec<ConsensusClientUri>,
    },

    /// Fetch one or more `[ArchiveBlock]`s from a list of tx source urls and
    /// store them in a Protobuf file.
    FetchArchiveBlocks {
        /// URLs to use for fetching blocks.
        ///
        /// For example: https://ledger.mobilecoinww.com/node1.prod.mobilecoinww.com
        #[clap(
            long = "tx-source-url",
            use_value_delimiter = true,
            env = "MC_TX_SOURCE_URL"
        )]
        tx_source_urls: Vec<String>,

        /// Block index we are interested in.
        #[clap(long, env = "MC_BLOCK_INDEX")]
        block_index: BlockIndex,

        /// File to write the fetched ArchiveBlocks protobuf to.
        #[clap(long, env = "MC_OUT_FILE")]
        out_file: PathBuf,
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
        Commands::GenerateConfig { nodes } => {
            cmd_generate_config(nodes, logger);
        }

        Commands::FetchArchiveBlocks {
            tx_source_urls,
            block_index,
            out_file,
        } => {
            cmd_fetch_archive_blocks(tx_source_urls, block_index, out_file, logger);
        }
    }
}

fn cmd_generate_config(nodes: Vec<ConsensusClientUri>, logger: Logger) {
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
        known_valid_block_ids: Default::default(),
    };

    println!(
        "{}",
        serde_json::to_string_pretty(&light_client_verifier).unwrap()
    );
}

fn cmd_fetch_archive_blocks(
    tx_source_urls: Vec<String>,
    block_index: u64,
    out_file: PathBuf,
    logger: Logger,
) {
    let block_datas = tx_source_urls
        .into_iter()
        .map(|url| {
            log::info!(logger, "Fetching block data from {}", url);
            let rts = ReqwestTransactionsFetcher::new(vec![url], logger.clone())
                .expect("failed creating ReqwestTransactionsFetcher");
            rts.get_block_data_by_index(block_index, None)
                .expect("failed fetching block data")
        })
        .collect::<Vec<_>>();

    let archive_blocks = ArchiveBlocks::from(&block_datas[..]);
    let bytes = archive_blocks
        .write_to_bytes()
        .expect("failed serializing ArchiveBlocks");
    fs::write(&out_file, bytes).expect("failed writing ArchiveBlocks to file");
    log::info!(
        logger,
        "Wrote ArchiveBlocks to file {}",
        out_file.to_string_lossy()
    );

    // Give the logger time to flush :/
    std::thread::sleep(std::time::Duration::from_millis(100));
}
