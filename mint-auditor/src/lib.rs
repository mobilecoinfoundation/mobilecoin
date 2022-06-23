// Copyright (c) 2018-2022 The MobileCoin Foundation

//! A utility for keeping track of token minting and burning.

#![feature(proc_macro_hygiene, decl_macro)]
#![deny(missing_docs)]

pub mod counters;
pub mod db;
pub mod gnosis;

mod convert;
mod error;
mod service;

pub use crate::{error::Error, service::MintAuditorService};

#[macro_use]
extern crate diesel;
#[macro_use]
extern crate diesel_migrations;
