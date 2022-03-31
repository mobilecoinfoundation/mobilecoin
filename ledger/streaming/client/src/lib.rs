// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Clients for the Ledger Streaming API.

#![feature(generic_associated_types)]
#![feature(type_alias_impl_trait)]
#![deny(missing_docs)]

mod backfill;
mod grpc;

#[cfg(any(test, feature = "test_utils"))]
pub mod test_utils;

pub use self::{backfill::BackfillingStream, grpc::GrpcBlockSource};
