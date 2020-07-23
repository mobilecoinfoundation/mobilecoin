// Copyright (c) 2018-2020 MobileCoin Inc.

//! The private side of mobilecoind-mirror.
//! This program forms outgoing connections to both a mobilecoind instance, as well as a public
//! mobilecoind-mirror instance. It then proceeds to poll the public side of the mirror for
//! requests which it then forwards to mobilecoind. When a response is received it is then
//! forwarded back to the mirror.

use mc_common::logger::{create_app_logger, log, o};
use mc_mobilecoind_mirror::uri::MobilecoindMirrorUri;
use std::{str::FromStr, time::Duration};
use structopt::StructOpt;

/// Command line config, set with defaults that will work with
/// a standard mobilecoind instance
#[derive(Clone, Debug, StructOpt)]
#[structopt(
    name = "mobilecoind-mirror-private",
    about = "The private side of mobilecoind-mirror, receiving requests from the public side and forwarding them to mobilecoind"
)]
pub struct Config {
    /// MobileCoinD URI.
    #[structopt(long, default_value = "127.0.0.1:4444")]
    pub mobilecoind_host: String,

    /// Use SSL when connecting to mobilecoind.
    #[structopt(long)]
    pub mobilecoind_ssl: bool,

    /// URI for the public side of the mirror.
    #[structopt(long)]
    pub mirror_public_uri: MobilecoindMirrorUri,

    /// How many seconds to wait between polling.
    #[structopt(long, default_value = "1", parse(try_from_str=parse_duration_in_seconds))]
    pub poll_interval: Duration,
}

fn main() {
    mc_common::setup_panic_handler();
    let _sentry_guard = mc_common::sentry::init();

    let config = Config::from_args();

    let (logger, _global_logger_guard) = create_app_logger(o!());
    log::info!(
        logger,
        "Starting mobilecoind mirror private forwarder on {}, connecting to mobilecoind {}",
        config.mirror_public_uri,
        config.mobilecoind_host
    );
}

fn parse_duration_in_seconds(src: &str) -> Result<Duration, std::num::ParseIntError> {
    Ok(Duration::from_secs(u64::from_str(src)?))
}
