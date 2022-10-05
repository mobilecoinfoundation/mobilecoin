// Copyright (c) 2018-2022 The MobileCoin Foundation

//! A utility to dump a ledger's contents as JSON.

#![deny(missing_docs)]

use clap::Parser;
use mc_ledger_db::LedgerDB;
use mc_util_dump_ledger::{dump_ledger, DumpParams};
use std::path::PathBuf;

/// Configuration.
#[derive(Debug, Parser)]
struct Config {
    /// Path to [LedgerDB].
    #[clap(long, env = "MC_LEDGER_DB")]
    pub ledger_db: PathBuf,

    #[clap(flatten)]
    pub params: DumpParams,
}

fn main() {
    mc_common::setup_panic_handler();

    let config = Config::parse();

    let ledger_db = LedgerDB::open(&config.ledger_db).expect("failed to open LedgerDB");

    let json = dump_ledger(&ledger_db, config.params).expect("failed to dump LedgerDB");

    println!("{}", json);
}
