// Copyright 2018-2021 MobileCoin, Inc.

//! Main Method for the stub server

use fog_stub_server::{Config, Server};
use mc_common::logger;
use structopt::StructOpt;

fn main() {
    mc_common::setup_panic_handler();

    let (logger, _global_logger_guard) = logger::create_app_logger(logger::o!());

    let config = Config::from_args();

    let mut server = Server::new(&config.client_listen_uri, logger.clone());
    server.start();

    loop {
        std::thread::sleep(std::time::Duration::from_millis(1000));
    }
}
