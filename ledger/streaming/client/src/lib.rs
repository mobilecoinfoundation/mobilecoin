// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Clients for the Ledger Streaming API.

#![feature(generic_associated_types)]
#![feature(type_alias_impl_trait)]
#![deny(missing_docs)]

pub mod backfill;
pub mod error;
pub mod grpc;
pub mod http_fetcher;
pub mod block_validator;
pub mod ledger_sink;
pub mod scp_validator;
pub mod url;

#[cfg(any(test, feature = "test_utils"))]
pub mod test_utils;

pub use crate::{
    backfill::BackfillingStream, grpc::GrpcBlockSource, http_fetcher::HttpBlockFetcher,
    url::BlockchainUrl,
};
