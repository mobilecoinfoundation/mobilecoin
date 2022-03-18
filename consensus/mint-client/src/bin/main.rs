// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Entrypoint for the consensus mint client.

use clap::Parser;
use grpcio::{ChannelBuilder, EnvBuilder};
use mc_common::logger::{create_app_logger, o};
use mc_consensus_api::{
    consensus_client_grpc::ConsensusClientApiClient, consensus_common_grpc::BlockchainApiClient,
    empty::Empty,
};
use mc_consensus_mint_client::{Commands, Config};
use mc_transaction_core::constants::MAX_TOMBSTONE_BLOCKS;
use mc_util_grpc::ConnectionUriGrpcioChannel;
use std::sync::Arc;

fn main() {
    let (logger, _global_logger_guard) = create_app_logger(o!());
    let config = Config::parse();

    match config.command {
        Commands::GenerateAndSubmitMintConfigTx { node, params } => {
            let env = Arc::new(EnvBuilder::new().name_prefix("mint-client-grpc").build());
            let ch = ChannelBuilder::default_channel_builder(env).connect_to_uri(&node, &logger);
            let client_api = ConsensusClientApiClient::new(ch.clone());
            let blockchain_api = BlockchainApiClient::new(ch);

            let tx = params
                .try_into_mint_config_tx(|| {
                    let last_block_info = blockchain_api
                        .get_last_block_info(&Empty::new())
                        .expect("get last block info");
                    last_block_info.index + MAX_TOMBSTONE_BLOCKS - 1
                })
                .expect("failed creating tx");

            let resp = client_api
                .propose_mint_config_tx(&(&tx).into())
                .expect("propose tx");
            println!("response: {:?}", resp);
        }

        Commands::GenerateAndSubmitMintTx { node, params } => {
            let env = Arc::new(EnvBuilder::new().name_prefix("mint-client-grpc").build());
            let ch = ChannelBuilder::default_channel_builder(env).connect_to_uri(&node, &logger);
            let client_api = ConsensusClientApiClient::new(ch.clone());
            let blockchain_api = BlockchainApiClient::new(ch);

            let tx = params
                .try_into_mint_tx(|| {
                    let last_block_info = blockchain_api
                        .get_last_block_info(&Empty::new())
                        .expect("get last block info");
                    last_block_info.index + MAX_TOMBSTONE_BLOCKS - 1
                })
                .expect("failed creating tx");

            let resp = client_api
                .propose_mint_tx(&(&tx).into())
                .expect("propose tx");
            println!("response: {:?}", resp);
        }
    }
}
