// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Configuration parameters to reconstitute the ledger

use clap::Parser;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[clap(
    name = "ledger_from_archive",
    about = "Create local ledger db from archive."
)]
pub struct LedgerFromArchiveConfig {
    /// Path to ledger db (lmdb).
    #[clap(
        long,
        default_value = "/tmp/ledgerdb",
        parse(from_os_str),
        env = "MC_LEDGER_DB"
    )]
    pub ledger_db: PathBuf,

    /// URLs to use to pull blocks.
    ///
    /// For example: https://s3-us-west-1.amazonaws.com/mobilecoin.chain/node1.master.mobilecoin.com/
    #[clap(
        long = "tx-source-url",
        required = true,
        min_values = 1,
        use_value_delimiter = true,
        env = "MC_TX_SOURCE_URL"
    )]
    pub tx_source_urls: Vec<String>,

    /// (Optional) Number of blocks to sync
    #[clap(long, env = "MC_NUM_BLOCKS")]
    pub num_blocks: Option<u64>,
}
