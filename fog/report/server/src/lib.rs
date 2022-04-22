// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Server for ingest reports.

#![deny(missing_docs)]

mod config;
mod server;
mod service;

pub use crate::{
    config::{Config, Error, Materials},
    server::Server,
};
