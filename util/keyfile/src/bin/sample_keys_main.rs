// Copyright (c) 2018-2022 The MobileCoin Foundation
#![deny(missing_docs)]
//! Create some default keys for use in demos and testing
use clap::Parser;
use mc_util_keyfile::config::Config as GeneralConfig;

#[derive(Debug, Parser)]
struct Config {
    #[clap(flatten)]
    pub general: GeneralConfig,

    /// Number of user keys to generate.
    #[clap(short, long, default_value = "10", env = "MC_NUM")]
    pub num: usize,
}

fn main() {
    let config = Config::parse();

    let path = config
        .general
        .output_dir
        .clone()
        .unwrap_or_else(|| std::env::current_dir().unwrap().join("keys"));

    let spki = config
        .general
        .fog_authority_root
        .as_ref()
        .or(config.general.fog_authority_spki.as_ref())
        .cloned();

    if config.general.fog_report_url.is_some() && spki.is_none() {
        panic!("Fog report url was passed, so fog is enabled, but no fog authority spki was provided. This is needed for the fog authority signature scheme. Use --fog-authority-root to pass a .pem file or --fog-authority-spki to pass base64 encoded bytes specifying this.")
    }

    println!("Writing {} keys to {:?}", config.num, path);

    mc_util_keyfile::keygen::write_default_keyfiles(
        path,
        config.num,
        config.general.fog_report_url.as_deref(),
        &config.general.fog_report_id,
        spki.as_deref(),
        config.general.seed,
    )
    .unwrap();
}
