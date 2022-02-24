// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Ledger migration: Perform updates of LedgerDB to accommodate for
//! backward-incompatible changes.

use clap::Parser;
use mc_common::logger::{create_app_logger, o};
use mc_ledger_migration::migrate;
use std::{path::PathBuf, thread::sleep, time::Duration};

/// Command line configuration
#[derive(Clone, Debug, Parser)]
pub struct Config {
    /// Ledger DB path.
    #[clap(long, parse(from_os_str), env = "MC_LEDGER_DB")]
    pub ledger_db: PathBuf,
}

fn main() {
    let config = Config::parse();

    mc_common::setup_panic_handler();
    let _sentry_guard = mc_common::sentry::init();
    let (logger, _global_logger_guard) = create_app_logger(o!());

    migrate(&config.ledger_db, &logger);

    // Give logger a moment to flush.
    sleep(Duration::from_secs(1));
}
