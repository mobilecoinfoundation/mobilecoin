// Copyright (c) 2018-2022 The MobileCoin Foundation

//! A utility for keeping track of token minting and burning.

use clap::Parser;
use mc_common::logger::{log, o, Logger};
use mc_ledger_db::{Ledger, LedgerDB};
use mc_mint_auditor::{Error, MintAuditorDb};
use mc_util_parse::parse_duration_in_seconds;
use std::{path::PathBuf, thread::sleep, time::Duration};

/// Coonfiguration for the mint auditor.
#[derive(Clone, Parser)]
#[clap(
    name = "mc-mint-auditor",
    about = "Utility for keeping track of token minting and burning."
)]
pub struct Config {
    /// Path to ledger db. Syncing this ledger should happen externally via
    /// mobilecoind.
    #[clap(long, parse(from_os_str), env = "MC_LEDGER_DB")]
    pub ledger_db: PathBuf,

    /// Path to mint auditor db.
    #[clap(long, parse(from_os_str), env = "MC_MINT_AUDITOR_DB")]
    pub mint_auditor_db: PathBuf,

    /// How many seconds to wait between polling.
    #[clap(long, default_value = "1", parse(try_from_str = parse_duration_in_seconds), env = "MC_POLL_INTERVAL")]
    pub poll_interval: Duration,
}

fn main() {
    mc_common::setup_panic_handler();
    let _sentry_guard = mc_common::sentry::init();
    let config = Config::parse();
    let (logger, _global_logger_guard) = mc_common::logger::create_app_logger(o!());

    let ledger_db = LedgerDB::open(&config.ledger_db).expect("Could not open ledger DB");
    let mint_auditor_db = MintAuditorDb::create_or_open(&config.mint_auditor_db, logger.clone())
        .expect("Could not open mint auditor DB");

    loop {
        sync_loop(&mint_auditor_db, &ledger_db, &logger).expect("sync_loop failed");
        sleep(config.poll_interval);
    }
}

fn sync_loop(
    mint_auditor_db: &MintAuditorDb,
    ledger_db: &LedgerDB,
    logger: &Logger,
) -> Result<(), Error> {
    loop {
        let num_blocks_in_ledger = ledger_db.num_blocks()?;

        let last_synced_block_index = mint_auditor_db.last_synced_block_index()?;
        let num_blocks_synced = last_synced_block_index
            .map(|block_index| block_index + 1)
            .unwrap_or(0);

        if num_blocks_synced == num_blocks_in_ledger {
            // Nothing more to sync.
            break;
        } else if num_blocks_synced > num_blocks_in_ledger {
            log::error!(logger, "Somehow synced more blocks ({}) than what is in the ledger ({}) - this should never happen.", num_blocks_synced, num_blocks_in_ledger);
            break;
        }

        // Sync the next block.
        let block_data = ledger_db.get_block_data(num_blocks_synced)?;
        mint_auditor_db.sync_block(block_data.block(), block_data.contents())?;
    }

    Ok(())
}
