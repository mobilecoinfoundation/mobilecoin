// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Runs a cleanup utility for the Fog Sql Recovery DB.

use crate::{config::SqlRecoveryDbCleanupConfig, db_cleaner::DbCleaner};
use chrono::Duration;
use clap::Parser;
use mc_common::logger::create_app_logger;
use mc_fog_sql_recovery_db::SqlRecoveryDb;
use std::env;

mod config;
mod db_cleaner;

static EXPIRATION_DAYS: i64 = 2;

fn main() {
    let config = SqlRecoveryDbCleanupConfig::parse();
    let (logger, _global_logger_guard) = create_app_logger(mc_common::logger::o!());

    let database_url = env::var("DATABASE_URL").expect("Missing DATABASE_URL environment variable");
    let db = SqlRecoveryDb::new_from_url(&database_url, Default::default(), logger.clone())
        .expect("failed connecting to database");

    let db_cleaner = DbCleaner::new(db, logger);

    if config.egress_keys {
        db_cleaner.cleanup_egress_keys(config.dry_run, Duration::days(EXPIRATION_DAYS));
    }
}
