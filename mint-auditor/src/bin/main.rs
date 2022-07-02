// Copyright (c) 2018-2022 The MobileCoin Foundation

//! A utility for keeping track of token minting and burning.

use clap::{Parser, Subcommand};
use grpcio::{EnvBuilder, ServerBuilder};
use mc_common::logger::{log, o, Logger};
use mc_ledger_db::{Ledger, LedgerDB};
use mc_mint_auditor::{
    counters,
    db::{transaction, BlockAuditData, BlockBalance, Counters, MintAuditorDb},
    gnosis::{GnosisSafeConfig, GnosisSyncThread},
    Error, MintAuditorService,
};
use mc_mint_auditor_api::MintAuditorUri;
use mc_util_grpc::{AdminServer, BuildInfoService, ConnectionUriGrpcioServer, HealthService};
use mc_util_parse::parse_duration_in_seconds;
use mc_util_uri::AdminUri;
use serde_json::json;
use std::{cmp::Ordering, path::PathBuf, sync::Arc, thread::sleep, time::Duration};

/// Maximum number of concurrent connections in the database pool.
const DB_POOL_SIZE: u32 = 10;

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

        /// Gnosis safe configuration file (json/toml).
        /// When provided, the configured gnosis safe(s) will be audited.
        #[clap(long, env = "MC_GNOSIS_SAFE_CONFIG", parse(try_from_str = parse_gnosis_safe_config))]
        gnosis_safe_config: Option<GnosisSafeConfig>,
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
            ledger_db,
            mint_auditor_db,
            poll_interval,
            listen_uri,
            admin_listen_uri,
            gnosis_safe_config,
        } => {
            cmd_scan_ledger(
                ledger_db,
                mint_auditor_db,
                poll_interval,
                listen_uri,
                admin_listen_uri,
                gnosis_safe_config,
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
    gnosis_safe_config: Option<GnosisSafeConfig>,
    logger: Logger,
) {
    let ledger_db = LedgerDB::open(&ledger_db_path).expect("Could not open ledger DB");
    let mint_auditor_db = MintAuditorDb::new_from_path(
        &mint_auditor_db_path.into_os_string().into_string().unwrap(),
        DB_POOL_SIZE,
        logger.clone(),
    )
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

    let _gnosis_safe_fetcher_threads = gnosis_safe_config.map(|gnosis_safe_config| {
        gnosis_safe_config
            .safes
            .iter()
            .map(|safe_config| {
                GnosisSyncThread::start(
                    safe_config,
                    mint_auditor_db.clone(),
                    poll_interval,
                    logger.clone(),
                )
                .expect("Failed starting gnosis safe fetcher thread")
            })
            .collect::<Vec<_>>()
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
    let mint_auditor_db = MintAuditorDb::new_from_path(
        &mint_auditor_db_path.into_os_string().into_string().unwrap(),
        DB_POOL_SIZE,
        logger.clone(),
    )
    .expect("Could not open mint auditor DB");

    let conn = mint_auditor_db
        .get_conn()
        .expect("Could not get db connection");

    transaction(&conn, |conn| -> Result<(), Error> {
        let last_synced_block_index = BlockAuditData::last_synced_block_index(conn)?;
        let block_index = block_index
            .or(last_synced_block_index)
            .ok_or_else(|| Error::Other("Failed figuring out the last block index".into()))?;

        let audit_data = BlockAuditData::get(conn, block_index)?;
        let balance_map = BlockBalance::get_balances_for_block(conn, block_index)?;

        if json {
            let obj = json!({
                "block_audit_data": audit_data,
                "balances": balance_map,
            });
            println!(
                "{}",
                serde_json::to_string(&obj)
                    .map_err(|err| Error::Other(format!("failed serializing json: {}", err)))?
            );
        } else {
            println!("Block index: {}", block_index);
            for (token_id, balance) in balance_map.iter() {
                println!("Token {}: {}", token_id, balance);
            }
        }

        Ok(())
    })
    .expect("db transaction failed");
}

/// Synchronizes the mint auditor database with the ledger database.
/// Will run until all blocks in the ledger database have been synced.
fn sync_loop(
    mint_auditor_db: &MintAuditorDb,
    ledger_db: &LedgerDB,
    logger: &Logger,
) -> Result<(), Error> {
    loop {
        let conn = mint_auditor_db.get_conn()?;
        let num_blocks_in_ledger = ledger_db.num_blocks()?;

        let last_synced_block_index = BlockAuditData::last_synced_block_index(&conn)?;
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

                // SQLite3 does not like concurrent writes. Since we are going to be writing to
                // the database, ensure we are the only writers.
                conn.exclusive_transaction(|| {
                    mint_auditor_db.sync_block_with_conn(
                        &conn,
                        block_data.block(),
                        block_data.contents(),
                    )
                })?;
                update_counters(&Counters::get(&conn)?);
            }
        };
    }

    Ok(())
}

/// Update prometheus counters.
fn update_counters(counters: &Counters) {
    counters::NUM_BLOCKS_SYNCED.set(counters.num_blocks_synced as i64);
    counters::NUM_BURNS_EXCEEDING_BALANCE.set(counters.num_burns_exceeding_balance as i64);
    counters::NUM_MINT_TXS_WITHOUT_MATCHING_MINT_CONFIG
        .set(counters.num_mint_txs_without_matching_mint_config as i64);
}

/// Load a gnosis safe config file.
fn parse_gnosis_safe_config(path: &str) -> Result<GnosisSafeConfig, Error> {
    Ok(GnosisSafeConfig::load_from_path(path)?)
}
