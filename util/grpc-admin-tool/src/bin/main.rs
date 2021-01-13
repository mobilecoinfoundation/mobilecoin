// Copyright (c) 2018-2021 The MobileCoin Foundation

//! A utility for issueing admin GRPC requests.

use grpcio::ChannelBuilder;
use mc_util_grpc::{
    admin::SetRustLogRequest, admin_grpc::AdminApiClient, empty::Empty, ConnectionUriGrpcioChannel,
};
use mc_util_uri::AdminUri;
use std::{str::FromStr, sync::Arc};
use structopt::StructOpt;

#[derive(Clone, StructOpt)]
pub struct Config {
    /// URI to connect to
    #[structopt(long)]
    pub uri: String,

    #[structopt(subcommand)]
    pub cmd: Command,
}

#[derive(Clone, StructOpt)]
pub enum Command {
    /// Get Prometheus metrics.
    Metrics,

    /// Get information such as build info, logging configuration, etc.
    GetInfo,

    /// Update the logging level (RUST_LOG).
    SetRustLog {
        /// New RUST_LOG value to use
        rust_log: String,
    },

    /// Logs a test error message.
    TestLogError,
}

fn main() {
    mc_common::setup_panic_handler();
    let (logger, _global_logger_guard) =
        mc_common::logger::create_app_logger(mc_common::logger::o!());
    let config = Config::from_args();

    let env = Arc::new(grpcio::EnvBuilder::new().build());
    let uri = AdminUri::from_str(&config.uri).expect("failed to parse uri");
    let ch = ChannelBuilder::default_channel_builder(env).connect_to_uri(&uri, &logger);
    let client = AdminApiClient::new(ch);

    match config.cmd {
        Command::Metrics => {
            let response = client
                .get_prometheus_metrics(&Empty::new())
                .expect("failed calling get_prometheus_metrics");
            println!("{}", response.metrics);
        }

        Command::GetInfo => {
            let response = client
                .get_info(&Empty::new())
                .expect("failed calling get_info");

            println!("Service name: {}", response.name);
            println!("Service id:   {}", response.id);
            println!("RUST_LOG:     {}", response.rust_log);
            println!("Build info:   {}", response.build_info_json);
            println!("Config json:  {}", response.config_json);
        }

        Command::SetRustLog { rust_log } => {
            let mut request = SetRustLogRequest::new();
            request.set_rust_log(rust_log);

            let _ = client
                .set_rust_log(&request)
                .expect("failed calling set_rust_log");
            println!("Done.");
        }

        Command::TestLogError => {
            let _ = client
                .test_log_error(&Empty::new())
                .expect("failed calling test_log_error");
            println!("Done.");
        }
    };

    // Give logger a moment to flush :/
    std::thread::sleep(std::time::Duration::from_millis(500));
}
