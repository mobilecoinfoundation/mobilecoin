// Copyright (c) 2018-2022 The MobileCoin Foundation

//! A utility for keeping track of token minting and burning.

use clap::{Parser, Subcommand};
use grpcio::{EnvBuilder, ServerBuilder};
use mc_common::logger::{log, o, Logger};
use mc_ledger_db::{Ledger, LedgerDB};
use mc_mint_auditor::{counters, Error, MintAuditorDb, MintAuditorService};
use mc_mint_auditor_api::MintAuditorUri;
use mc_util_grpc::{AdminServer, BuildInfoService, ConnectionUriGrpcioServer, HealthService};
use mc_util_parse::parse_duration_in_seconds;
use mc_util_uri::AdminUri;
use std::{cmp::Ordering, path::PathBuf, sync::Arc, thread::sleep, time::Duration};

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

        /// Oprtional GRPC listen URI, to be used when API access is desired.
        #[clap(long, env = "MC_LISTEN_URI")]
        listen_uri: Option<MintAuditorUri>,

        /// Optional admin service listening URI.
        #[clap(long, env = "MC_ADMIN_LISTEN_URI")]
        admin_listen_uri: Option<AdminUri>,
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

#[tokio::main]
async fn main() {
    mc_common::setup_panic_handler();
    let _sentry_guard = mc_common::sentry::init();
    let (logger, _global_logger_guard) = mc_common::logger::create_app_logger(o!());

    {
        use mc_mint_auditor::gnosis::fetcher::GnosisSafeFetcher;
        use std::str::FromStr;

        let fetcher = GnosisSafeFetcher::new(
            url::Url::from_str("https://safe-transaction.rinkeby.gnosis.io/").unwrap(),
            logger.clone(),
        )
        .unwrap();
        let x = fetcher
            .get_transaction_data("0x90213de428E9Ce4C77dD4943755Aa69cb2F803b7")
            .await
            .unwrap();
        for tx in x{
            if tx.tx_hash().is_err() {
                panic!("{:#?}", tx);
            }
            println!("{}", tx.tx_hash().unwrap());
        }
    }

    let config = Config::parse();
    match config.command {
        Command::ScanLedger {
            ledger_db,
            mint_auditor_db,
            poll_interval,
            listen_uri,
            admin_listen_uri,
        } => {
            cmd_scan_ledger(
                ledger_db,
                mint_auditor_db,
                poll_interval,
                listen_uri,
                admin_listen_uri,
                logger,
            );
        }

        Command::GetBlockAuditData {
            mint_auditor_db,
            block_index,
            json,
        } => {
            cmd_get_block_audit_data(mint_auditor_db, block_index, json, logger);
        }
    }
}

/// Implementation of the ScanLedger CLI command.
fn cmd_scan_ledger(
    ledger_db_path: PathBuf,
    mint_auditor_db_path: PathBuf,
    poll_interval: Duration,
    listen_uri: Option<MintAuditorUri>,
    admin_listen_uri: Option<AdminUri>,
    logger: Logger,
) {
    let ledger_db = LedgerDB::open(&ledger_db_path).expect("Could not open ledger DB");
    let mint_auditor_db = MintAuditorDb::create_or_open(&mint_auditor_db_path, logger.clone())
        .expect("Could not open mint auditor DB");

    let _api_server = listen_uri.map(|listen_uri| {
        // Create RPC services.
        let build_info_service = BuildInfoService::new(logger.clone()).into_service();
        let health_service = HealthService::new(None, logger.clone()).into_service();
        let mint_auditor_service =
            MintAuditorService::new(mint_auditor_db.clone(), logger.clone()).into_service();

        // Package services into grpc server.
        log::info!(logger, "Starting API service on {}", listen_uri);
        let env = Arc::new(EnvBuilder::new().name_prefix("RPC".to_string()).build());

        let server_builder = ServerBuilder::new(env)
            .register_service(build_info_service)
            .register_service(health_service)
            .register_service(mint_auditor_service)
            .bind_using_uri(&listen_uri, logger.clone());

        let mut server = server_builder.build().unwrap();
        server.start();

        server
    });

    let _admin_server = admin_listen_uri.map(|admin_listen_uri| {
        let local_hostname = hostname::get()
            .expect("failed getting local hostname")
            .to_str()
            .expect("failed getting hostname as str")
            .to_string();

        AdminServer::start(
            None,
            &admin_listen_uri,
            "Mint Auditor".to_owned(),
            local_hostname,
            None,
            logger.clone(),
        )
        .expect("Failed starting admin grpc server")
    });

    loop {
        sync_loop(&mint_auditor_db, &ledger_db, &logger).expect("sync_loop failed");
        sleep(poll_interval);
    }
}

/// Implementation of the GetBlockAuditData CLI command.
fn cmd_get_block_audit_data(
    mint_auditor_db_path: PathBuf,
    block_index: Option<u64>,
    json: bool,
    logger: Logger,
) {
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

/// Synchronizes the mint auditor database with the ledger database.
/// Will run until all blocks in the ledger database have been synced.
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

        match num_blocks_synced.cmp(&num_blocks_in_ledger) {
            Ordering::Equal => {
                // Nothing more to sync.
                break;
            }
            Ordering::Greater => {
                log::error!(logger, "Somehow synced more blocks ({}) than what is in the ledger ({}) - this should never happen.", num_blocks_synced, num_blocks_in_ledger);
                break;
            }

            Ordering::Less => {
                // Sync the next block.
                let block_data = ledger_db.get_block_data(num_blocks_synced)?;
                mint_auditor_db.sync_block(block_data.block(), block_data.contents())?;
                update_counters(mint_auditor_db)?;
            }
        };
    }

    Ok(())
}

// Update prometheus counters.
fn update_counters(mint_auditor_db: &MintAuditorDb) -> Result<(), Error> {
    let counters = mint_auditor_db.get_counters()?;

    counters::NUM_BLOCKS_SYNCED.set(counters.num_blocks_synced as i64);
    counters::NUM_BURNS_EXCEEDING_BALANCE.set(counters.num_burns_exceeding_balance as i64);
    counters::NUM_MINT_TXS_WITHOUT_MATCHING_MINT_CONFIG
        .set(counters.num_mint_txs_without_matching_mint_config as i64);

    Ok(())
}
