// Copyright (c) 2018-2020 MobileCoin Inc.

#![feature(external_doc)]
#![doc(include = "../README.md")]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

pub mod config;
pub mod watcher;
pub mod watcher_db;

pub use watcher_db::WatcherTimestampResultCode;

mod error;
