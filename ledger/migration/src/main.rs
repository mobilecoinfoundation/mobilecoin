// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Ledger migration: Perform updates of LedgerDB to accommodate for
//! backward-incompatible changes.

use mc_common::logger::{create_app_logger, o};
use mc_ledger_migration::migrate;
use std::{path::PathBuf, thread::sleep, time::Duration};
use structopt::StructOpt;

/// Command line configuration
#[derive(Clone, Debug, StructOpt)]
pub struct Config {
    /// Ledger DB path.
    #[structopt(long, parse(from_os_str))]
    pub ledger_db: PathBuf,
}

fn main() {
    let config = Config::from_args();

    mc_common::setup_panic_handler();
    let _sentry_guard = mc_common::sentry::init();
    let (logger, _global_logger_guard) = create_app_logger(o!());

    migrate(&config.ledger_db, &logger);

    // Give logger a moment to flush.
    sleep(Duration::from_secs(1));
}
