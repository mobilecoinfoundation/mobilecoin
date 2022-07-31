// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Entrypoint for the consensus mint client.

use clap::Parser;
use grpcio::{CallOption, ChannelBuilder, EnvBuilder, MetadataBuilder};
use mc_common::logger::{create_app_logger, o};
use mc_consensus_api::{
    consensus_client_grpc::ConsensusClientApiClient, consensus_common_grpc::BlockchainApiClient,
    empty::Empty,
};
use mc_consensus_enclave_api::GovernorsSigner;
use mc_consensus_mint_client::{printers, Commands, Config, TxFile};
use mc_crypto_keys::{Ed25519Pair, Signer};
use mc_crypto_multisig::MultiSig;
use mc_transaction_core::{
    constants::MAX_TOMBSTONE_BLOCKS,
    mint::{MintConfigTx, MintTx},
};
use mc_util_grpc::{ConnectionUriGrpcioChannel, CHAIN_ID_GRPC_HEADER};
use protobuf::ProtobufEnum;
use std::{fs, process::exit, sync::Arc};

// Make a "call option" object which includes appropriate grpc headers
fn call_option(chain_id: &str) -> CallOption {
    let mut metadata_builder = MetadataBuilder::new();

    // Add the chain id header if we have a chain id specified
    if !chain_id.is_empty() {
        metadata_builder
            .add_str(CHAIN_ID_GRPC_HEADER, chain_id)
            .expect("Could not add chain-id header");
    }

    CallOption::default().headers(metadata_builder.build())
}

fn main() {
    let (logger, _global_logger_guard) = create_app_logger(o!());
    let config = Config::parse();

    match config.command {
        Commands::GenerateAndSubmitMintConfigTx {
            node,
            params,
            chain_id,
        } => {
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

            if tx.signature.signatures().is_empty() {
                panic!("tx contains no signatures");
            }

            let resp = client_api
                .propose_mint_config_tx_opt(&(&tx).into(), call_option(&chain_id))
                .expect("propose tx");
            println!("response: {:?}", resp);

            // Relying on the success result code being 0, we terminate ourselves in a way
            // that allows whoever started this binary to easily determine if submitting the
            // transaction succeeded.
            exit(resp.get_result().get_code().value());
        }

        Commands::GenerateMintConfigTx { out, params } => {
            let tx = params
                .try_into_mint_config_tx(|| panic!("missing tombstone block"))
                .expect("failed creating tx");

            TxFile::from(tx)
                .write_json(&out)
                .expect("failed writing output file");
        }

        Commands::HashMintConfigTx { params } => {
            let tx_prefix = params
                .try_into_mint_config_tx_prefix(|| panic!("missing tombstone block"))
                .expect("failed creating tx prefix");

            // Print the nonce, since if we generated it randomlly then there is no way to
            // reconstruct the tx prefix that is being hashed without it.
            println!("Nonce: {}", hex::encode(&tx_prefix.nonce));

            let hash = tx_prefix.hash();
            println!("Hash: {}", hex::encode(hash));
        }

        Commands::SubmitMintConfigTx {
            node,
            tx_filenames,
            chain_id,
        } => {
            // Load all txs.
            let txs =
                TxFile::load_multiple::<MintConfigTx>(&tx_filenames).expect("failed loading txs");

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
            if signatures.is_empty() {
                panic!("tx contains no signatures");
            }

            let merged_tx = MintConfigTx {
                prefix: txs[0].prefix.clone(),
                signature: MultiSig::new(signatures),
            };

            let env = Arc::new(EnvBuilder::new().name_prefix("mint-client-grpc").build());
            let ch = ChannelBuilder::default_channel_builder(env).connect_to_uri(&node, &logger);
            let client_api = ConsensusClientApiClient::new(ch);

            let resp = client_api
                .propose_mint_config_tx_opt(&(&merged_tx).into(), call_option(&chain_id))
                .expect("propose tx");
            println!("response: {:?}", resp);

            // Relying on the success result code being 0, we terminate ourselves in a way
            // that allows whoever started this binary to easily determine if submitting the
            // transaction succeeded.
            exit(resp.get_result().get_code().value());
        }

        Commands::GenerateAndSubmitMintTx {
            node,
            params,
            chain_id,
        } => {
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

            if tx.signature.signatures().is_empty() {
                panic!("tx contains no signatures");
            }

            let resp = client_api
                .propose_mint_tx_opt(&(&tx).into(), call_option(&chain_id))
                .expect("propose tx");
            println!("response: {:?}", resp);

            // Relying on the success result code being 0, we terminate ourselves in a way
            // that allows whoever started this binary to easily determine if submitting the
            // transaction succeeded.
            exit(resp.get_result().get_code().value());
        }

        Commands::GenerateMintTx { out, params } => {
            let tx = params
                .try_into_mint_tx(|| panic!("missing tombstone block"))
                .expect("failed creating tx");

            TxFile::from(tx)
                .write_json(&out)
                .expect("failed writing output file");
        }

        Commands::HashMintTx { params } => {
            let tx_prefix = params
                .try_into_mint_tx_prefix(|| panic!("missing tombstone block"))
                .expect("failed creating tx prefix");

            // Print the nonce, since if we generated it randomlly then there is no way to
            // reconstruct the tx prefix that is being hashed without it.
            println!("Nonce: {}", hex::encode(&tx_prefix.nonce));

            let hash = tx_prefix.hash();
            println!("Hash: {}", hex::encode(hash));
        }

        Commands::SubmitMintTx {
            node,
            tx_filenames,
            chain_id,
        } => {
            // Load all txs.
            let txs = TxFile::load_multiple::<MintTx>(&tx_filenames).expect("failed loading txs");

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
            if signatures.is_empty() {
                panic!("tx contains no signatures");
            }

            let merged_tx = MintTx {
                prefix: txs[0].prefix.clone(),
                signature: MultiSig::new(signatures),
            };

            let env = Arc::new(EnvBuilder::new().name_prefix("mint-client-grpc").build());
            let ch = ChannelBuilder::default_channel_builder(env).connect_to_uri(&node, &logger);
            let client_api = ConsensusClientApiClient::new(ch);

            let resp = client_api
                .propose_mint_tx_opt(&(&merged_tx).into(), call_option(&chain_id))
                .expect("propose tx");
            println!("response: {:?}", resp);

            // Relying on the success result code being 0, we terminate ourselves in a way
            // that allows whoever started this binary to easily determine if submitting the
            // transaction succeeded.
            exit(resp.get_result().get_code().value());
        }

        Commands::SignGovernors {
            signing_key,
            mut tokens,
            output_toml,
            output_json,
        } => {
            let governors_map = tokens
                .token_id_to_governors()
                .expect("governors configuration error");
            let signature = Ed25519Pair::from(signing_key)
                .sign_governors_map(&governors_map)
                .expect("failed signing governors map");
            println!("Signature: {}", hex::encode(signature.as_ref()));
            println!("Put this signature in the governors configuration file in the key \"governors_signature\".");

            tokens.governors_signature = Some(signature);

            if let Some(path) = output_toml {
                let toml_str = toml::to_string_pretty(&tokens).expect("failed serializing toml");
                fs::write(path, toml_str).expect("failed writing output file");
            }

            if let Some(path) = output_json {
                let json_str =
                    serde_json::to_string_pretty(&tokens).expect("failed serializing json");
                fs::write(path, json_str).expect("failed writing output file");
            }
        }

        Commands::Dump { tx_file } => match tx_file {
            TxFile::MintConfigTx(tx) => {
                printers::print_mint_config_tx(&tx, 0);
            }
            TxFile::MintTx(tx) => {
                printers::print_mint_tx(&tx, 0);
            }
        },

        Commands::Sign {
            tx_file: tx_file_path,
            signing_keys,
            mut signatures,
        } => {
            let mut tx_file =
                TxFile::from_json_file(&tx_file_path).expect("failed loading tx file");

            // Append any existing signatures.
            signatures.extend(match &tx_file {
                TxFile::MintConfigTx(tx) => tx.signature.signatures().to_vec(),
                TxFile::MintTx(tx) => tx.signature.signatures().to_vec(),
            });

            // The message we are signing.
            let message = match &tx_file {
                TxFile::MintConfigTx(tx) => tx.prefix.hash(),
                TxFile::MintTx(tx) => tx.prefix.hash(),
            };

            // Append signatures using the keys provided.
            signatures.extend(
                signing_keys
                    .into_iter()
                    .map(|signer| {
                        Ed25519Pair::from(signer)
                            .try_sign(message.as_ref())
                            .map_err(|e| format!("Failed to sign: {}", e))
                    })
                    .collect::<Result<Vec<_>, _>>()
                    .expect("failed signing"),
            );

            // De-dupe.
            signatures.sort();
            signatures.dedup();

            // Update the tx file signature.
            let signature = MultiSig::new(signatures);
            match &mut tx_file {
                TxFile::MintConfigTx(ref mut tx) => {
                    tx.signature = signature;
                }
                TxFile::MintTx(ref mut tx) => {
                    tx.signature = signature;
                }
            }

            // Write the file.
            tx_file
                .write_json(&tx_file_path)
                .expect("failed writing tx file");
        }
    }
}
