// Copyright (c) 2018-2020 MobileCoin Inc.

//! A gRPC API module for attestation

pub mod attest;
pub mod attest_grpc;
pub mod conversions;

pub mod empty {
    pub use protobuf::well_known_types::Empty;
}
