// Copyright (c) 2018-2021 The MobileCoin Foundation

use crate::SqlRecoveryDb;
use diesel::{prelude::*, PgConnection};
use diesel_migrations::embed_migrations;
use mc_common::logger::Logger;
use rand::{distributions::Alphanumeric, thread_rng, Rng};

embed_migrations!("migrations/");

pub struct SqlRecoveryDbTestContext {
    base_url: String,
    db_name: String,
    logger: Logger,
}

impl SqlRecoveryDbTestContext {
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
        let base_url = std::env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL must be set");

        // First, connect to postgres db to be able to create our test
        // database.
        let postgres_url = format!("{}/postgres", base_url);
        let conn =
            PgConnection::establish(&postgres_url).expect("Cannot connect to postgres database.");

        // Create a new database for the test
        let query = diesel::sql_query(format!("CREATE DATABASE {};", db_name).as_str());
        let _ = query
            .execute(&conn)
            .unwrap_or_else(|err| panic!("Could not create database {}: {:?}", db_name, err));

        // Now we can connect to the database and run the migrations
        let conn = PgConnection::establish(&format!("{}/{}", base_url, db_name))
            .unwrap_or_else(|err| panic!("Cannot connect to {} database: {:?}", db_name, err));

        embedded_migrations::run(&conn).expect("failed running migrations");

        // Success
        Self {
            base_url,
            db_name,
            logger,
        }
    }

    pub fn db_name(&self) -> &str {
        &self.db_name
    }

    pub fn db_url(&self) -> String {
        format!("{}/{}", self.base_url, self.db_name)
    }

    pub fn get_db_instance(&self) -> SqlRecoveryDb {
        SqlRecoveryDb::new_from_url(&self.db_url(), self.logger.clone())
            .expect("failed creating new SqlRecoveryDb")
    }

    pub fn new_conn(&self) -> PgConnection {
        PgConnection::establish(&self.db_url()).expect("cannot connect to database")
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
