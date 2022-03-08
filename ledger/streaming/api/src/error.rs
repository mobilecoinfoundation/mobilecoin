// Copyright (c) 2018-2022 The MobileCoin Foundation

use displaydoc::Display;
use grpcio::Error as GrpcError;
use mc_api::ConversionError;

#[derive(Debug, Display)]
pub enum Error {
    /// gRPC: {0}
    Grpc(GrpcError),

    /// Conversion: {0}
    Conversion(ConversionError),
}

impl From<GrpcError> for Error {
    fn from(src: GrpcError) -> Self {
        Self::Grpc(src)
    }
}

impl From<ConversionError> for Error {
    fn from(src: ConversionError) -> Self {
        Self::Conversion(src)
    }
}

pub type Result<T> = core::result::Result<T, Error>;
