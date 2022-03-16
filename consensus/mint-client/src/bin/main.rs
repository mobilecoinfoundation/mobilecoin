// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Entrypoint for the consensus mint client.

use clap::Parser;
use grpcio::{ChannelBuilder, EnvBuilder};
use mc_common::logger::{create_app_logger, o};
use mc_consensus_api::consensus_client_grpc::ConsensusClientApiClient;
use mc_consensus_mint_client::{Commands, Config};
use mc_crypto_keys::{Ed25519Pair, Signer};
use mc_crypto_multisig::{MultiSig, SignerSet};
use mc_transaction_core::mint::{
    constants::NONCE_LENGTH, MintConfig, MintConfigTx, MintConfigTxPrefix, MintTx, MintTxPrefix,
};
use mc_util_grpc::ConnectionUriGrpcioChannel;
use rand::{rngs::StdRng, thread_rng, RngCore, SeedableRng};
use std::sync::Arc;

fn main() {
    let (logger, _global_logger_guard) = create_app_logger(o!());
    let config = Config::parse();

    match config.command {
        Commands::GenerateAndSubmitMintConfigTx { node, signing_key } => {
            let env = Arc::new(EnvBuilder::new().name_prefix("mint-client-grpc").build());
            let ch = ChannelBuilder::default_channel_builder(env).connect_to_uri(&node, &logger);
            let api_client = ConsensusClientApiClient::new(ch);

            let signer = Ed25519Pair::from(signing_key);

            let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
            let mut nonce: Vec<u8> = vec![0u8; NONCE_LENGTH];
            rng.fill_bytes(&mut nonce);

            let prefix = MintConfigTxPrefix {
                token_id: 1,
                configs: vec![MintConfig {
                    token_id: 1,
                    signer_set: SignerSet::new(vec![signer.public_key()], 1),
                    mint_limit: 1000,
                }],
                nonce,
                tombstone_block: 10,
            };

            let message = prefix.hash();
            let signature = MultiSig::new(vec![signer.try_sign(message.as_ref()).unwrap()]);
            let tx = MintConfigTx { prefix, signature };

            let resp = api_client
                .propose_mint_config_tx(&(&tx).into())
                .expect("propose tx");
            println!("response: {:?}", resp);
        }

        Commands::GenerateAndSubmitMintTx {
            node,
            signing_key,
            recipient,
        } => {
            let env = Arc::new(EnvBuilder::new().name_prefix("mint-client-grpc").build());
            let ch = ChannelBuilder::default_channel_builder(env).connect_to_uri(&node, &logger);
            let api_client = ConsensusClientApiClient::new(ch);

            let signer = Ed25519Pair::from(signing_key);

            let mut rng = thread_rng();
            let mut nonce: Vec<u8> = vec![0u8; NONCE_LENGTH];
            rng.fill_bytes(&mut nonce);

            let prefix = MintTxPrefix {
                token_id: 1,
                amount: 123,
                view_public_key: *recipient.view_public_key(),
                spend_public_key: *recipient.spend_public_key(),
                nonce,
                tombstone_block: 10,
            };

            let message = prefix.hash();
            let signature = MultiSig::new(vec![signer.try_sign(message.as_ref()).unwrap()]);
            let tx = MintTx { prefix, signature };

            let resp = api_client
                .propose_mint_tx(&(&tx).into())
                .expect("propose tx");
            println!("response: {:?}", resp);
        }
    }
}
