// Copyright (c) 2018-2022 The MobileCoin Foundation

//! A utility for keeping track of token minting and burning.

use clap::{Parser, Subcommand};
use mc_common::logger::{log, o, Logger};
use mc_ledger_db::{Ledger, LedgerDB};
use mc_mint_auditor::{Error, MintAuditorDb};
use mc_util_parse::parse_duration_in_seconds;
use std::{path::PathBuf, thread::sleep, time::Duration};

/// Clap configuration for each subcommand this program supports.
#[derive(Clone, Subcommand)]
pub enum Command {
    /// Scan the ledger and audit the minting and burning of tokens in blocks as
    /// they come in.
    ScanLedger {
        /// Path to ledger db. Syncing this ledger should happen externally via
        /// mobilecoind.
        #[clap(long, parse(from_os_str), env = "MC_LEDGER_DB")]
        ledger_db: PathBuf,

        /// Path to mint auditor db.
        #[clap(long, parse(from_os_str), env = "MC_MINT_AUDITOR_DB")]
        mint_auditor_db: PathBuf,

        /// How many seconds to wait between polling.
        #[clap(long, default_value = "1", parse(try_from_str = parse_duration_in_seconds), env = "MC_POLL_INTERVAL")]
        poll_interval: Duration,
    },

    /// Get the audit data for a specific block, optionally in JSON format
    /// (serialized `BlockAuditData`).
    GetBlockAuditData {
        /// Path to mint auditor db.
        #[clap(long, parse(from_os_str), env = "MC_MINT_AUDITOR_DB")]
        mint_auditor_db: PathBuf,

        /// Block index (optional, defaults to last synced block).
        #[clap(long, env = "MC_BLOCK_INDEX")]
        block_index: Option<u64>,

        /// Output JSON (serialized `BlockAuditData`).
        #[clap(long, env = "MC_JSON")]
        json: bool,
    },
}

/// Configuration for the mint auditor.
#[derive(Clone, Parser)]
#[clap(
    name = "mc-mint-auditor",
    about = "Utility for keeping track of token minting and burning."
)]
pub struct Config {
    #[clap(subcommand)]
    pub command: Command,
}

fn main() {
    mc_common::setup_panic_handler();
    let _sentry_guard = mc_common::sentry::init();
    let config = Config::parse();
    let (logger, _global_logger_guard) = mc_common::logger::create_app_logger(o!());

    match config.command {
        Command::ScanLedger {
            ledger_db: ledger_db_path,
            mint_auditor_db: mint_auditor_db_path,
            poll_interval,
        } => {
            let ledger_db = LedgerDB::open(&ledger_db_path).expect("Could not open ledger DB");
            let mint_auditor_db =
                MintAuditorDb::create_or_open(&mint_auditor_db_path, logger.clone())
                    .expect("Could not open mint auditor DB");

            loop {
                sync_loop(&mint_auditor_db, &ledger_db, &logger).expect("sync_loop failed");
                sleep(poll_interval);
            }
        }

        Command::GetBlockAuditData {
            mint_auditor_db: mint_auditor_db_path,
            block_index,
            json,
        } => {
            let mint_auditor_db = MintAuditorDb::open(&mint_auditor_db_path, logger.clone())
                .expect("Could not open mint auditor DB");

            let block_index = block_index
                .or_else(|| {
                    mint_auditor_db
                        .last_synced_block_index()
                        .expect("Could not get last synced block index")
                })
                .expect("No blocks synced");

            let audit_data = mint_auditor_db
                .get_block_audit_data(block_index)
                .expect("Could not get audit data for block");

            if json {
                println!(
                    "{}",
                    serde_json::to_string(&audit_data).expect("failed serializing json")
                );
            } else {
                println!("Block index: {}", block_index);
                for (token_id, balance) in audit_data.balance_map.iter() {
                    println!("Token {}: {}", token_id, balance);
                }
            }
        }
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
