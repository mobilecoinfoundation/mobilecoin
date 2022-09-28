// Copyright (c) 2018-2022 The MobileCoin Foundation

//! A cleanup utility for the Fog SQL DB.

use chrono::{prelude::*, Duration};
use mc_common::logger::{log, Logger};
use mc_fog_recovery_db_iface::RecoveryDb;
use mc_fog_sql_recovery_db::SqlRecoveryDb;

/// Contains helper methods that cleanup the Fog SQL DB.
pub struct DbCleaner {
    /// The Fog DB being cleaned up.
    db: SqlRecoveryDb,

    /// Logger instance.
    logger: Logger,
}

impl DbCleaner {
    pub fn new(db: SqlRecoveryDb, logger: Logger) -> Self {
        Self { db, logger }
    }

    /// Identifies expired egress keys and either deletes their associated
    /// ingest invocations or prints them out.
    pub fn cleanup_egress_keys(&self, is_dry_run: bool, expiration: Duration) {
        let expired_date_time = Utc::now()
            .naive_utc()
            .checked_sub_signed(expiration)
            .expect("Expiration should always be in the past");

        let expired_ingest_invocations = self
            .db
            .get_expired_invocations(expired_date_time)
            .expect("Could not retrieve expired ingest invocations.");

        log::info!(
            self.logger,
            "There are {} expired ingest invocations",
            expired_ingest_invocations.len()
        );
        for (i, expired_ingest_invocation) in expired_ingest_invocations.iter().enumerate() {
            log::info!(
                    self.logger,
                    "Expired Egress key {}\n  ingest_invocation_id: {}\n  egress_public_key: {:?}\n  last_active_at: {:?}",
                    i + 1,
                    expired_ingest_invocation.ingest_invocation_id,
                    expired_ingest_invocation.egress_public_key,
                    expired_ingest_invocation.last_active_at,
                );
            if !is_dry_run {
                match self.db.decommission_ingest_invocation(
                    &expired_ingest_invocation.ingest_invocation_id.into(),
                ) {
                    Ok(_) => {
                        log::info!(
                            self.logger,
                            "Expired Egress key {:?} with id {} has been deleted.",
                            expired_ingest_invocation.egress_public_key,
                            expired_ingest_invocation.ingest_invocation_id
                        )
                    }
                    Err(err) => log::error!(
                        self.logger,
                        "Could not decommission expired egress key {:?} with id {}: {}",
                        expired_ingest_invocation.egress_public_key,
                        expired_ingest_invocation.ingest_invocation_id,
                        err
                    ),
                }
            }
        }
    }
}
