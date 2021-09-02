// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Ingest client error types.

use displaydoc::Display;
use grpcio::Error as GrpcError;
use mc_api::ConversionError;
use mc_crypto_keys::CompressedRistrettoPublic;

#[derive(Debug, Display)]
pub enum Error {
    /// GRPC: {0}
    Grpc(GrpcError),

    /// ApiConversion: {0}
    ApiConversion(ConversionError),

    /// Some users were not successfully added: {0:?}
    AddUsersFailed(Vec<CompressedRistrettoPublic>),
}

impl From<GrpcError> for Error {
    fn from(src: GrpcError) -> Self {
        Self::Grpc(src)
    }
}

impl From<ConversionError> for Error {
    fn from(src: ConversionError) -> Self {
        Self::ApiConversion(src)
    }
}
