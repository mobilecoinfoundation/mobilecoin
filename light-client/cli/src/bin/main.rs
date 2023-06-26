// Copyright (c) 2018-2023 The MobileCoin Foundation

use clap::{Parser, Subcommand};
use grpcio::{ChannelBuilder, EnvBuilder};
use mc_common::{
    logger::{create_app_logger, o},
    ResponderId,
};
use mc_consensus_api::{
    consensus_client_grpc::ConsensusClientApiClient, consensus_common_grpc::BlockchainApiClient,
};
use mc_consensus_scp_types::QuorumSet;
use mc_light_client_verifier::{
    HexKeyNodeID, LightClientVerifierConfig, TrustedValidatorSetConfig,
};
use mc_util_grpc::ConnectionUriGrpcioChannel;
use mc_util_uri::ConsensusClientUri;
use std::{str::FromStr, sync::Arc};

#[derive(Subcommand)]
pub enum Commands {
    GenerateConfig {
        #[clap(long = "node", use_value_delimiter = true, env = "MC_NODES")]
        nodes: Vec<ConsensusClientUri>,
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

    let env = Arc::new(EnvBuilder::new().name_prefix("light-client-grpc").build());

    match config.command {
        Commands::GenerateConfig { nodes } => {
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
                    responder_id: ResponderId::from_str(node_config.get_peer_responder_id())
                        .unwrap(),
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
    }
}
