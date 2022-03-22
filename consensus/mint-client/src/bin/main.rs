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
use mc_crypto_keys::{Ed25519Pair, Signer};
use mc_crypto_multisig::{MultiSig, SignerSet};
use mc_transaction_core::{
    constants::MAX_TOMBSTONE_BLOCKS,
    mint::{
        constants::NONCE_LENGTH, MintConfig, MintConfigTx, MintConfigTxPrefix, MintTx, MintTxPrefix,
    },
};
use mc_util_grpc::ConnectionUriGrpcioChannel;
use rand::{thread_rng, RngCore};
use std::sync::Arc;

fn main() {
    let (logger, _global_logger_guard) = create_app_logger(o!());
    let config = Config::parse();

    match config.command {
        Commands::GenerateAndSubmitMintConfigTx {
            node,
            signing_key,
            token_id,
            tombstone,
            nonce,
        } => {
            let env = Arc::new(EnvBuilder::new().name_prefix("mint-client-grpc").build());
            let ch = ChannelBuilder::default_channel_builder(env).connect_to_uri(&node, &logger);
            let client_api = ConsensusClientApiClient::new(ch.clone());
            let blockchain_api = BlockchainApiClient::new(ch);

            let signer = Ed25519Pair::from(signing_key);

            let tombstone_block = tombstone.unwrap_or_else(|| {
                let last_block_info = blockchain_api
                    .get_last_block_info(&Empty::new())
                    .expect("get last block info");
                last_block_info.index + MAX_TOMBSTONE_BLOCKS - 1
            });

            let nonce = nonce.map(|n| n.to_vec()).unwrap_or_else(|| {
                let mut rng = thread_rng();
                let mut nonce: Vec<u8> = vec![0u8; NONCE_LENGTH];
                rng.fill_bytes(&mut nonce);
                nonce
            });

            let prefix = MintConfigTxPrefix {
                token_id,
                configs: vec![MintConfig {
                    token_id,
                    signer_set: SignerSet::new(vec![signer.public_key()], 1),
                    mint_limit: 1000,
                }],
                nonce,
                tombstone_block,
            };

            let message = prefix.hash();
            let signature = MultiSig::new(vec![signer.try_sign(message.as_ref()).unwrap()]);
            let tx = MintConfigTx { prefix, signature };

            let resp = client_api
                .propose_mint_config_tx(&(&tx).into())
                .expect("propose tx");
            println!("response: {:?}", resp);
        }

        Commands::GenerateAndSubmitMintTx {
            node,
            signing_key,
            recipient,
            token_id,
            amount,
            tombstone,
            nonce,
        } => {
            let env = Arc::new(EnvBuilder::new().name_prefix("mint-client-grpc").build());
            let ch = ChannelBuilder::default_channel_builder(env).connect_to_uri(&node, &logger);
            let client_api = ConsensusClientApiClient::new(ch.clone());
            let blockchain_api = BlockchainApiClient::new(ch);

            let signer = Ed25519Pair::from(signing_key);

            let tombstone_block = tombstone.unwrap_or_else(|| {
                let last_block_info = blockchain_api
                    .get_last_block_info(&Empty::new())
                    .expect("get last block info");
                last_block_info.index + MAX_TOMBSTONE_BLOCKS - 1
            });

            let nonce = nonce.map(|n| n.to_vec()).unwrap_or_else(|| {
                let mut rng = thread_rng();
                let mut nonce: Vec<u8> = vec![0u8; NONCE_LENGTH];
                rng.fill_bytes(&mut nonce);
                nonce
            });

            let prefix = MintTxPrefix {
                token_id,
                amount,
                view_public_key: *recipient.view_public_key(),
                spend_public_key: *recipient.spend_public_key(),
                nonce,
                tombstone_block,
            };

            let message = prefix.hash();
            let signature = MultiSig::new(vec![signer.try_sign(message.as_ref()).unwrap()]);
            let tx = MintTx { prefix, signature };

            let resp = client_api
                .propose_mint_tx(&(&tx).into())
                .expect("propose tx");
            println!("response: {:?}", resp);
        }
    }
}
