// Copyright (c) 2018-2020 MobileCoin Inc.

//! An HTTP frontend for a Consensus Service's admin GRPC interface.

use mc_common::logger::{create_app_logger, log, o};
use mc_util_uri::ConsensusAdminUri;
use structopt::StructOpt;

#[derive(Clone, Debug, StructOpt)]
#[structopt(
    name = "mc-consensus-admin-http-gateway",
    about = "An HTTP frontend for a Consensus Service's admin GRPC interface."
)]
pub struct Config {
    /// Post to start webserver on.
    #[structopt(long)]
    pub listen_port: u16,

    /// Consensus service admin URI to connect to.
    #[structopt(long)]
    pub admin_uri: ConsensusAdminUri,
}

fn main() {
    mc_common::setup_panic_handler();
    let _sentry_guard = mc_common::sentry::init();

    let config = Config::from_args();

    let (logger, _global_logger_guard) = create_app_logger(o!());
    log::info!(
        logger,
        "Starting consensus admin HTTP gateway on port {}, connecting to {}",
        config.listen_port,
        config.admin_uri
    );
}
