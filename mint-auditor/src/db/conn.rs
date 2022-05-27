// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Database connection utilities.

use diesel::{
    connection::SimpleConnection,
    r2d2,
    r2d2::{ConnectionManager, PooledConnection},
    SqliteConnection,
};
use std::time::Duration;

/// A type alias for a pooled SQLite connection.
pub type Conn = PooledConnection<ConnectionManager<SqliteConnection>>;

/// Database connection options.
#[derive(Debug)]
pub struct ConnectionOptions {
    /// Whether to enable the SQLite  WAL.
    /// See https://sqlite.org/wal.html for details.
    pub enable_wal: bool,

    /// Time to wait while table is locked.
    pub busy_timeout: Option<Duration>,
}

impl r2d2::CustomizeConnection<SqliteConnection, r2d2::Error> for ConnectionOptions {
    fn on_acquire(&self, conn: &mut SqliteConnection) -> Result<(), r2d2::Error> {
        (|| {
            if let Some(d) = self.busy_timeout {
                conn.batch_execute(&format!("PRAGMA busy_timeout = {};", d.as_millis()))?;
            }
            if self.enable_wal {
                conn.batch_execute("
                    PRAGMA journal_mode = WAL;          -- better write-concurrency
                    PRAGMA synchronous = NORMAL;        -- fsync only in critical moments
                    PRAGMA wal_autocheckpoint = 1000;   -- write WAL changes back every 1000 pages, for an in average 1MB WAL file. May affect readers if number is increased
                    PRAGMA wal_checkpoint(TRUNCATE);    -- free some space by truncating possibly massive WAL files from the last run.
                ")?;
            }
            conn.batch_execute("PRAGMA foreign_keys = ON;")?;

            Ok(())
        })()
        .map_err(r2d2::Error::QueryError)
    }
}
