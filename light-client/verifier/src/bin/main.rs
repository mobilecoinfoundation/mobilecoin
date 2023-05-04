// Copyright (c) 2018-2023 The MobileCoin Foundation

use clap::Parser;
use light_client_verifier::{VerifierConfig, VerifierServer};
use mc_common::logger::o;
use std::{thread::sleep, time::Duration};

fn main() {
    let _sentry_guard = mc_common::sentry::init();
    let config = VerifierConfig::parse();
    let (logger, _global_logger_guard) = mc_common::logger::create_app_logger(o!());
    mc_common::setup_panic_handler();

    let mut server = VerifierServer::new(config.client_listen_uri, logger);
    server
        .start()
        .expect("Failed starting Verifier GRPC server");

    // Keep the server alive
    loop {
        sleep(Duration::from_secs(1));
    }
}
