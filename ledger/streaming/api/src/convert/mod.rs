// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Conversions between "API types" and "domain/persistence types" for Ledger
//! Streaming API.
//!
//! gRPC and Protobuf provide a reduced selection of types, and so there are
//! some differences between values stored in the ledger and values transmitted
//! over the API. This module provides conversions between "equivalent" types,
//! such as `mc_ledger_streaming_api::QuorumSet` and
//! `mc_consensus_scp::QuorumSet`.

mod archive_block;
mod components;
mod quorum_set;

pub use self::{archive_block::*, components::*, quorum_set::*};
pub use mc_api::ConversionError;
