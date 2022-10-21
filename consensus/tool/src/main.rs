// Copyright (c) 2018-2022 The MobileCoin Foundation

//! A cli tool for interrogating a mobilecoin consensus node.

#![deny(missing_docs)]

use clap::{Parser, Subcommand};
use grpcio::{ChannelBuilder, EnvBuilder};
use mc_common::logger::{create_app_logger, o};
use mc_connection::BlockInfo;
use mc_consensus_api::{consensus_common_grpc::BlockchainApiClient, empty::Empty};
use mc_util_grpc::ConnectionUriGrpcioChannel;
use mc_util_uri::ConsensusClientUri;
use serde_json::to_string_pretty;
use std::{sync::Arc, time::Duration};

/// A cli tool for interrogating one or more consensus nodes.
///
/// Example usage:
///
/// $ mc-consensus-tool status mc://localhost:3200 | jq .index
///
/// $ mc-consensus-tool status mc://localhost:3200 | jq .network_block_version
///
/// $ STOP_BLOCK=$(mc-consensus-tool wait-for-quiet \
/// mc://localhost:3200 mc://localhost:3201 mc://localhost:3202)
///
/// $ MC_PEERS=mc://localhost:3200,mc://localhost:3201 \
/// mc-consensus-tool wait-for-block --index=$(STOP_BLOCK)
#[derive(Clone, Debug, Parser)]
#[clap(name = "mc-consensus-tool")]
pub struct Config {
    /// Command to use
    #[clap(subcommand)]
    pub tool_command: ToolCommand,

    /// Consensus_uri's to connect to
    #[clap(global = true, use_value_delimiter = true, env = "MC_PEERS")]
    pub consensus_uris: Vec<ConsensusClientUri>,
}

/// Commands that the tool recognizes
#[derive(Clone, Debug, Subcommand)]
pub enum ToolCommand {
    /// Status: Prints the network status, including block count and block
    /// version, in json format on STDOUT.
    Status,
    /// Wait-for-block: Blocks until all specified nodes have externalized the
    /// given block index.
    WaitForBlock {
        /// Block index which must appear
        #[clap(long, env = "MC_INDEX")]
        index: u64,

        /// Polling period in seconds
        #[clap(long, env = "MC_PERIOD", default_value = "1")]
        period: u64,
    },
    /// Wait-for-quiet: Blocks until the network is 'quiet'. This means that the
    /// block count doesn't move for some time. Prints the final
    /// block_index on STDOUT.
    WaitForQuiet {
        /// Number of seconds the network must stop moving for.
        #[clap(long, env = "MC_PERIOD", default_value = "20")]
        period: u64,

        /// Wait for quiet at some block index greater than this number.
        /// For example, of `--beyond-block=19` is the argument, then this
        /// command will block until the network is quiet and block
        /// index 20 has appeared.
        #[clap(long, env = "MC_BEYOND_BLOCK")]
        beyond_block: Option<u64>,
    },
}

fn main() {
    let (logger, _global_logger_guard) = create_app_logger(o!());
    let config = Config::parse();

    let env = Arc::new(EnvBuilder::new().name_prefix("consensus-tool-grpc").build());

    let blockchain_conns: Vec<_> = config
        .consensus_uris
        .iter()
        .map(|uri| {
            let ch =
                ChannelBuilder::default_channel_builder(env.clone()).connect_to_uri(uri, &logger);
            (uri.clone(), BlockchainApiClient::new(ch))
        })
        .collect();

    match config.tool_command {
        ToolCommand::Status => {
            for (uri, conn) in &blockchain_conns {
                let last_block_info = conn
                    .get_last_block_info(&Empty::new())
                    .expect("get last block info");

                let block_info = BlockInfo::from(last_block_info);

                println!(
                    "{}: {}",
                    uri,
                    to_string_pretty(&block_info).expect("json error")
                )
            }
        }
        ToolCommand::WaitForBlock { index, period } => loop {
            let mut needs_retry = false;
            for (uri, conn) in &blockchain_conns {
                match conn.get_last_block_info(&Empty::new()) {
                    Ok(last_block_info) => {
                        if last_block_info.index < index {
                            needs_retry = true;
                        }
                    }
                    Err(err) => {
                        eprintln!("{}: get_last_block_info(): {}", uri, err);
                        needs_retry = true;
                    }
                };
            }
            if needs_retry {
                std::thread::sleep(Duration::from_secs(period));
            } else {
                break;
            }
        },
        ToolCommand::WaitForQuiet {
            period,
            beyond_block,
        } => {
            let mut last_block_index = Option::<u64>::default();

            let last_block_index = loop {
                let mut was_updated = false;
                for (uri, conn) in &blockchain_conns {
                    match conn.get_last_block_info(&Empty::new()) {
                        Ok(last_block_info) => {
                            if last_block_index != Some(last_block_info.index) {
                                last_block_index = Some(last_block_info.index);
                                was_updated = true;
                            }
                        }
                        Err(err) => {
                            eprintln!("{}: get_last_block_info(): {}", uri, err);
                            was_updated = true;
                        }
                    };
                }
                if !was_updated {
                    if let Some(last_block_index) = last_block_index.as_ref() {
                        if beyond_block.is_none()
                            || beyond_block.as_ref().unwrap() < last_block_index
                        {
                            break last_block_index;
                        }
                    }
                }
                std::thread::sleep(Duration::from_secs(period));
            };
            // Print the stopping point on STDOUT so that scripts can capture this easily
            print!("{}", last_block_index)
        }
    }
}
