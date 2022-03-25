// Copyright 2018-2021 MobileCoin, Inc.

//! Server for ingest reports.

#![deny(missing_docs)]

mod config;
mod server;
mod service;

pub use crate::{
    config::{Config, Error, Materials},
    server::Server,
};
