// Copyright (c) 2018-2022 The MobileCoin Foundation
#![deny(missing_docs)]

//! Main Method for the stub server

use clap::Parser;
use fog_stub_server::{Config, Server};
use mc_common::logger;

fn main() {
    mc_common::setup_panic_handler();

    let (logger, _global_logger_guard) = logger::create_app_logger(logger::o!());

    let config = Config::parse();

    let mut server = Server::new(
        &config.client_listen_uri,
        config.chain_id.clone(),
        logger.clone(),
    );
    server.start();

    loop {
        std::thread::sleep(std::time::Duration::from_millis(1000));
    }
}
