// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Configuration parameters to reconstitute the ledger

use std::path::PathBuf;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(
    name = "ledger_from_archive",
    about = "Create local ledger db from archive."
)]
pub struct LedgerFromArchiveConfig {
    /// Path to ledger db (lmdb).
    #[structopt(long, default_value = "/tmp/ledgerdb", parse(from_os_str))]
    pub ledger_db: PathBuf,

    /// URLs to use to pull blocks.
    ///
    /// For example: https://s3-us-west-1.amazonaws.com/mobilecoin.chain/node1.master.mobilecoin.com/
    #[structopt(long = "tx-source-url", required = true, min_values = 1)]
    pub tx_source_urls: Vec<String>,

    /// (Optional) Number of blocks to sync
    #[structopt(long)]
    pub num_blocks: Option<u64>,
}
