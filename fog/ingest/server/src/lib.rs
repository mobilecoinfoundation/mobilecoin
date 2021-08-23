// Copyright (c) 2018-2021 The MobileCoin Foundation

//! The fog ingest server
//!
//! The ingest server functions as the "engine" of fog.
//! It enables fog to post-process the blockchain and figure out which
//! transactions were going to which fog users, and then tag these transactions
//! with random values that those users know to search for, so that they can
//! find their transactions without revealing to the node operator which
//! transactions were theirs. It uses an SGX enclave to do all of this
//! decryption, and this enclave also contains an RNG per user that it is
//! supporting.

#![deny(missing_docs)]

pub mod config;
pub mod connection;
pub mod connection_error;
pub mod connection_traits;
pub mod error;
pub mod ingest_peer_service;
pub mod ingest_service;
pub mod server;
pub mod state_file;

mod attested_api_service;
mod controller;
mod controller_state;
mod counters;
mod worker;

use core::fmt::Display;
use itertools::Itertools;

// Helper to format a sequence as a comma-separated list
// (This is used with lists of Ingest peer uris in logs,
// because the debug logging of that object is harder to read)
struct SeqDisplay<T: Display, I: Iterator<Item = T> + Clone>(I);

impl<T: Display, I: Iterator<Item = T> + Clone> Display for SeqDisplay<T, I> {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(fmt, "[{}]", self.0.clone().format(", "))
    }
}
