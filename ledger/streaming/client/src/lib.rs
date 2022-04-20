// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Clients for the Ledger Streaming API.

#![feature(generic_associated_types)]
#![feature(type_alias_impl_trait)]
#![deny(missing_docs)]

pub mod backfill;
pub mod grpc;
pub mod http_fetcher;
pub mod url;

pub mod block_validator;
pub mod error;
pub mod streaming_futures;

#[cfg(any(test, feature = "test_utils"))]
pub mod test_utils;

pub use crate::{
    backfill::BackfillingStream, grpc::GrpcBlockSource, http_fetcher::HttpBlockFetcher,
    url::BlockchainUrl,
};
