// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Common types and methods. no_std-compatible crate.

#![cfg_attr(not(any(test, feature = "std")), no_std)]
#![deny(missing_docs)]
#![warn(unused_extern_crates)]
extern crate alloc;

pub mod hash;
pub mod hasher_builder;
pub mod logger;
pub mod lru;
pub mod node_id;
pub mod responder_id;
pub mod time;

pub use crate::{
    hash::{fast_hash, Hash, HashMap, HashSet},
    hasher_builder::HasherBuilder,
    lru::LruCache,
    node_id::{NodeID, NodeIDError},
    responder_id::{ResponderId, ResponderIdParseError},
};

// Loggers
cfg_if::cfg_if! {
    if #[cfg(feature = "loggers")] {
        mod panic_handler;

        pub mod sentry;

        pub use crate::panic_handler::setup_panic_handler;
    }
}
