// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Clients for the Ledger Streaming API.

#![deny(missing_docs)]
#![feature(type_alias_impl_trait)]

mod grpc;

#[cfg(any(test, feature = "test_utils"))]
pub mod test_utils;

pub use self::grpc::GrpcBlockSource;
