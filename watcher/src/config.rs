// Copyright (c) 2018-2020 MobileCoin Inc.

//! Configuration parameters for the watcher test utility.

use std::path::PathBuf;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(
    name = "watcher",
    about = "Sync data from multiple sources, reconcile blocks, and verify signatures."
)]
/// Configuration for the Watcher Node.
pub struct WatcherConfig {
    /// Path to watcher db (lmdb).
    #[structopt(long, default_value = "/tmp/watcher-db", parse(from_os_str))]
    pub watcher_db: PathBuf,

    /// URLs to use to pull blocks.
    ///
    /// For example: https://s3-us-west-1.amazonaws.com/mobilecoin.chain/node1.master.mobilecoin.com/
    #[structopt(long = "tx-source-url", required = true, min_values = 1)]
    pub tx_source_urls: Vec<String>,

    /// (Optional) Number of blocks to sync
    #[structopt(long)]
    pub max_block_height: Option<u64>,
}
