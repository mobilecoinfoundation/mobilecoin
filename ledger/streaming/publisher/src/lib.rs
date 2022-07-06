// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Publishers for the Ledger Streaming API.

#![feature(async_closure)]
#![feature(generic_associated_types)]
#![feature(type_alias_impl_trait)]
#![deny(missing_docs)]

pub mod archive_sink;
pub mod grpc;
pub mod proto_writer;

pub use crate::{archive_sink::ArchiveBlockSink, grpc::GrpcServerSink, proto_writer::ProtoWriter};

#[cfg(feature = "s3")]
pub mod s3;
#[cfg(feature = "s3")]
pub use s3::{Config as S3Config, Region as S3Region, S3ClientProtoWriter};

#[cfg(feature = "local")]
pub mod local;
#[cfg(feature = "local")]
pub use local::LocalFileProtoWriter;

#[cfg(any(test, feature = "test_utils"))]
pub mod test_utils;
