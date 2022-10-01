// Copyright (c) 2018-2022 The MobileCoin Foundation

//! A cli tool for interrogating a mobilecoin consensus node.

#![deny(missing_docs)]

use clap::{Parser, Subcommand};
use grpcio::{ChannelBuilder, EnvBuilder};
use mc_common::logger::{create_app_logger, o};
use mc_consensus_api::{
    consensus_common_grpc::BlockchainApiClient,
    empty::Empty,
};
use mc_util_grpc::{ConnectionUriGrpcioChannel};
use mc_util_uri::{ConsensusClientUri};
use std::{sync::Arc, time::Duration};

/// Command line config, set with defaults that will work with
/// a standard mobilecoind instance
#[derive(Clone, Debug, Parser)]
#[clap(
    name = "mc-consensus-tool",
    about = "A cli tool for interrogating one or more consensus nodes"
)]
pub struct Config {
    /// Command to use
    #[clap(subcommand)]
    pub tool_command: ToolCommand,
    
    /// Consensus_uri's to connect to
    #[clap(global = true)]
    pub consensus_uris: Vec<ConsensusClientUri>,
}

/// Commands that the tool recognizes
#[derive(Clone, Debug, Subcommand)]
pub enum ToolCommand {
    /// Status: Prints the network status, including block count and block version
    Status,
    /// Wait-for-quiet: Blocks until the network is 'quiet'. This means that the block count doesn't move for some time.
    WaitForQuiet { 
        /// Number of seconds the network must stop moving for. Defaults to 5.
        #[clap(long)]
        period: Option<u64>,
    },
}

fn main() {
    let (logger, _global_logger_guard) = create_app_logger(o!());
    let config = Config::parse();

    let env = Arc::new(EnvBuilder::new().name_prefix("consensus-tool-grpc").build());

    let blockchain_conns: Vec<_> = config.consensus_uris.iter().map(|uri| {
       let ch = ChannelBuilder::default_channel_builder(env.clone()).connect_to_uri(uri, &logger);
       BlockchainApiClient::new(ch)
    }).collect();

    match &config.tool_command {
        ToolCommand::Status => {
            for conn in &blockchain_conns {
                let last_block_info = conn
                        .get_last_block_info(&Empty::new())
                        .expect("get last block info");
                println!("{:?}", last_block_info)
            }
        },
        ToolCommand::WaitForQuiet { period } => {
            let mut last_block_index = 0u64;
            let mut was_updated = true;
            let period = period.clone().unwrap_or(5u64);
            
            while was_updated {
                std::thread::sleep(Duration::from_secs(period));
                was_updated = false;
                for conn in &blockchain_conns {
                    match conn
                        .get_last_block_info(&Empty::new()) {
                        Ok(last_block_info) => {
                            if last_block_index != last_block_info.index {
                                last_block_index = last_block_info.index;
                                was_updated = true;
                            }
                        },
                        Err(err) => { eprintln!("get_last_block_info(): {}", err); was_updated = true; }
                    };
                }
            }
            println!("Network at quiet for {} seconds at block index: {}", period, last_block_index);
        }
    }
}
