// Copyright (c) 2018-2021 The MobileCoin Foundation

#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use prost::Message;
use serde::{Deserialize, Serialize};

pub mod common;
pub mod ingest;
pub mod ledger;
pub mod view;

/// An Encrypted Tx Out Record, consisting of a fog search_key (rng output),
/// and an mc-crypto-box encrypted payload, containing the FogTxOutRecord
/// protobuf.
///
/// Note: This is a database and enclave interface type, and is not sent to the
/// user. TxOutSearchResult is the corresponding user-facing object
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Message)]
pub struct ETxOutRecord {
    /// The query the user sends to the View Enclave (an RNG output)
    #[prost(bytes, required, tag = "1")]
    pub search_key: Vec<u8>,
    /// The TxOutRecord body, encrypted using user's view key
    #[prost(bytes, required, tag = "2")]
    pub payload: Vec<u8>,
}

/// A newtype for numbers representing a BlockCount
/// This is different from BlockIndex to help make it clear when something is
/// an index vs. a count and avoid off-by-one errors.
///
/// This type can't be used in protobuf types because prost doesn't allow user
/// types to be treated as u64, but if that changes then we could use it in
/// those types also.
#[derive(Copy, Clone, Default, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
pub struct BlockCount(u64);

impl From<u64> for BlockCount {
    fn from(src: u64) -> Self {
        Self(src)
    }
}

impl From<BlockCount> for u64 {
    fn from(src: BlockCount) -> u64 {
        src.0
    }
}

impl core::fmt::Display for BlockCount {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        self.0.fmt(f)
    }
}

impl BlockCount {
    pub const MAX: BlockCount = BlockCount(u64::MAX);
}
