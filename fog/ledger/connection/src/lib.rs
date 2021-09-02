// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Rust objects wrapping the grpc interface

#![deny(missing_docs)]
mod error;
pub use error::Error;

mod key_image;
pub use key_image::{FogKeyImageGrpcClient, KeyImageQueryError, KeyImageResultExtension};

mod merkle_proof;
pub use merkle_proof::{FogMerkleProofGrpcClient, OutputError, OutputResultExtension};

mod untrusted;
pub use untrusted::FogUntrustedLedgerGrpcClient;
