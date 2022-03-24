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
use mc_crypto_multisig::MultiSig;
use mc_transaction_core::{
    constants::MAX_TOMBSTONE_BLOCKS,
    mint::{MintConfigTx, MintTx},
};
use mc_util_grpc::ConnectionUriGrpcioChannel;
use serde::de::DeserializeOwned;
use serde_json::to_string_pretty;
use std::{fs, path::PathBuf, sync::Arc};

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

        Commands::GenerateMintConfigTx { out, params } => {
            let tx = params
                .try_into_mint_config_tx(|| panic!("missing tombstone block"))
                .expect("failed creating tx");

            let json = to_string_pretty(&tx).expect("failed serializing tx");

            fs::write(out, json).expect("failed writing output file");
        }

        Commands::SubmitMintConfigTx { node, tx_filenames } => {
            // Load all txs.
            let txs: Vec<MintConfigTx> = load_json_files(&tx_filenames);

            // All tx prefixes should be the same.
            if !txs.windows(2).all(|pair| pair[0].prefix == pair[1].prefix) {
                panic!("All txs must have the same prefix");
            }

            // Collect all signatures.
            let mut signatures = txs
                .iter()
                .flat_map(|tx| tx.signature.signatures())
                .cloned()
                .collect::<Vec<_>>();
            signatures.sort();
            signatures.dedup();

            let merged_tx = MintConfigTx {
                prefix: txs[0].prefix.clone(),
                signature: MultiSig::new(signatures),
            };

            let env = Arc::new(EnvBuilder::new().name_prefix("mint-client-grpc").build());
            let ch = ChannelBuilder::default_channel_builder(env).connect_to_uri(&node, &logger);
            let client_api = ConsensusClientApiClient::new(ch);

            let resp = client_api
                .propose_mint_config_tx(&(&merged_tx).into())
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

        Commands::GenerateMintTx { out, params } => {
            let tx = params
                .try_into_mint_tx(|| panic!("missing tombstone block"))
                .expect("failed creating tx");

            let json = to_string_pretty(&tx).expect("failed serializing tx");

            fs::write(out, json).expect("failed writing output file");
        }

        Commands::SubmitMintTx { node, tx_filenames } => {
            // Load all txs.
            let txs: Vec<MintTx> = load_json_files(&tx_filenames);

            // All tx prefixes should be the same.
            if !txs.windows(2).all(|pair| pair[0].prefix == pair[1].prefix) {
                panic!("All txs must have the same prefix");
            }

            // Collect all signatures.
            let mut signatures = txs
                .iter()
                .flat_map(|tx| tx.signature.signatures())
                .cloned()
                .collect::<Vec<_>>();
            signatures.sort();
            signatures.dedup();

            let merged_tx = MintTx {
                prefix: txs[0].prefix.clone(),
                signature: MultiSig::new(signatures),
            };

            let env = Arc::new(EnvBuilder::new().name_prefix("mint-client-grpc").build());
            let ch = ChannelBuilder::default_channel_builder(env).connect_to_uri(&node, &logger);
            let client_api = ConsensusClientApiClient::new(ch);

            let resp = client_api
                .propose_mint_tx(&(&merged_tx).into())
                .expect("propose tx");
            println!("response: {:?}", resp);
        }
    }
}

fn load_json_files<T: DeserializeOwned>(filenames: &[PathBuf]) -> Vec<T> {
    filenames
        .iter()
        .map(|filename| {
            let json = fs::read_to_string(filename)
                .unwrap_or_else(|err| panic!("Failed reading file {:?}: {}", filename, err));
            serde_json::from_str(&json)
                .unwrap_or_else(|err| panic!("Failed parsing tx from file {:?}: {}", filename, err))
        })
        .collect()
}
