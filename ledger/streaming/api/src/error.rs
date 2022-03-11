// Copyright (c) 2018-2022 The MobileCoin Foundation

use displaydoc::Display;
use grpcio::Error as GrpcError;
use mc_api::ConversionError;

#[derive(Debug, Display)]
pub enum LedgerStreamingError {
    /// gRPC: {0}
    Grpc(GrpcError),

    /// Conversion: {0}
    Conversion(ConversionError),

    /// Invalid block ID
    InvalidBlockId,
}

impl From<GrpcError> for LedgerStreamingError {
    fn from(src: GrpcError) -> Self {
        Self::Grpc(src)
    }
}

impl From<ConversionError> for LedgerStreamingError {
    fn from(src: ConversionError) -> Self {
        Self::Conversion(src)
    }
}

pub type StreamResult<T> = core::result::Result<T, LedgerStreamingError>;
