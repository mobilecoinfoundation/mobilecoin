// Copyright (c) 2018-2022 The MobileCoin Foundation

//! A helper utility for running migrations on a database configured via
//! DATABASE_URL.

use diesel::prelude::*;
use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};
use std::env;

const MIGRATIONS: EmbeddedMigrations = embed_migrations!("./migrations");

fn main() {
    let database_url = env::var("DATABASE_URL").expect("Missing DATABASE_URL environment variable");

    let conn = &mut PgConnection::establish(&database_url)
        .expect("fog-sql-recovery-db-migrations cannot connect to PG database");

    conn.run_pending_migrations(MIGRATIONS)
        .expect("Failed running migrations");

    println!("Done migrating Fog recovery DB!");
}
