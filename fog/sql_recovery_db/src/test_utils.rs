// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Utilities for testing.

use crate::{SqlRecoveryDb, SqlRecoveryDbConnectionConfig};
use diesel::{prelude::*, PgConnection};
use diesel_migrations::embed_migrations;
use mc_common::logger::{log, Logger};
use rand::{distributions::Alphanumeric, thread_rng, Rng};
use retry::{
    delay::{jitter, Fixed},
    retry,
};
use std::time::Duration;

embed_migrations!("migrations/");

const DB_CONNECTION_SLEEP_PERIOD: Duration = Duration::from_secs(3);
const TOTAL_RETRY_COUNT: usize = 5;

/// Context for tests.
pub struct SqlRecoveryDbTestContext {
    base_url: String,
    db_name: String,
    logger: Logger,
}

impl SqlRecoveryDbTestContext {
    /// Intantiate a context.
    pub fn new(logger: Logger) -> Self {
        let db_name: String = format!(
            "fog_test_{}",
            thread_rng()
                .sample_iter(&Alphanumeric)
                .take(10)
                .map(char::from)
                .collect::<String>()
                .to_lowercase()
        );
        let base_url =
            std::env::var("TEST_DATABASE_URL").expect("env.TEST_DATABASE_URL must be set");

        // First, connect to postgres db to be able to create our test
        // database.
        let postgres_url = format!("{}/postgres", base_url);
        log::info!(&logger, "Connecting to root PG DB {}", postgres_url);
        let conn = SqlRecoveryDbTestContext::establish_connection(&postgres_url);
        // Create a new database for the test
        let query = diesel::sql_query(format!("CREATE DATABASE {};", db_name).as_str());
        let _ = query
            .execute(&conn)
            .unwrap_or_else(|err| panic!("Could not create database {}: {:?}", db_name, err));

        // Now we can connect to the database and run the migrations
        let db_url = format!("{}/{}", base_url, db_name);
        log::info!(&logger, "Connecting to newly created PG DB '{}'", db_url);

        let conn = SqlRecoveryDbTestContext::establish_connection(&db_url);
        embedded_migrations::run(&conn).expect("failed running migrations");

        // Success
        Self {
            base_url,
            db_name,
            logger,
        }
    }

    /// Get DB name.
    pub fn db_name(&self) -> &str {
        &self.db_name
    }

    /// Get DB URL.
    pub fn db_url(&self) -> String {
        format!("{}/{}", self.base_url, self.db_name)
    }

    /// Get DB instance.
    pub fn get_db_instance(&self) -> SqlRecoveryDb {
        SqlRecoveryDb::new_from_url(
            &self.db_url(),
            SqlRecoveryDbConnectionConfig::default(),
            self.logger.clone(),
        )
        .expect("failed creating new SqlRecoveryDb")
    }

    /// Establish a connection.
    pub fn new_conn(&self) -> PgConnection {
        let db_url = self.db_url();
        PgConnection::establish(&db_url)
            .unwrap_or_else(|err| panic!("Cannot connect to database {}: {}", db_url, err))
    }

    fn establish_connection(url: &str) -> PgConnection {
        retry(
            Fixed::from(DB_CONNECTION_SLEEP_PERIOD)
                .map(jitter)
                .take(TOTAL_RETRY_COUNT),
            || PgConnection::establish(url),
        )
        .unwrap_or_else(|err| panic!("Cannot connect to PG database '{}: {}'", url, err))
    }
}

impl Drop for SqlRecoveryDbTestContext {
    fn drop(&mut self) {
        let postgres_url = format!("{}/postgres", self.base_url);
        let conn =
            PgConnection::establish(&postgres_url).expect("Cannot connect to postgres database.");

        let disconnect_users = format!(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '{}';",
            self.db_name
        );

        diesel::sql_query(disconnect_users.as_str())
            .execute(&conn)
            .unwrap();

        let query = diesel::sql_query(format!("DROP DATABASE {};", self.db_name).as_str());
        query
            .execute(&conn)
            .unwrap_or_else(|err| panic!("Couldn't drop database {}: {:?}", self.db_name, err));
    }
}
