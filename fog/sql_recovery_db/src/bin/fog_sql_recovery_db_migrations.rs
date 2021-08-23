// Copyright (c) 2018-2021 The MobileCoin Foundation

//! A helper utility for running migrations on a database configured via
//! DATABASE_URL.

#[macro_use]
extern crate diesel_migrations;

use diesel::{prelude::*, PgConnection};
use diesel_migrations::embed_migrations;
use std::env;

embed_migrations!("migrations/");

fn main() {
    let database_url = env::var("DATABASE_URL").expect("Missing DATABASE_URL environment variable");

    let conn = PgConnection::establish(&database_url).expect("Cannot connect to database");

    embedded_migrations::run(&conn).expect("Failed running migrations");

    println!("Done!");
}
