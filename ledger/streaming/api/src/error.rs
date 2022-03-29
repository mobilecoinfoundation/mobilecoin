// Copyright (c) 2018-2022 The MobileCoin Foundation

use displaydoc::Display;
use grpcio::Error as GrpcError;
use mc_api::ConversionError;
use mc_crypto_keys::SignatureError;
use protobuf::ProtobufError;

/// Wrapper enum for errors.
#[derive(Clone, Debug, Display)]
pub enum Error {
    /// gRPC: {0}
    Grpc(String),

    /// Conversion: {0}
    Conversion(ConversionError),

    /// Protobuf de/serialization: {0}
    Protobuf(String),

    /// Invalid signature: {0}
    Signature(String),

    /// IO Error: {0}
    IO(String, std::io::ErrorKind),

    /// {0}
    Other(String),
}

impl std::error::Error for Error {}

impl From<GrpcError> for Error {
    fn from(src: GrpcError) -> Self {
        Self::Grpc(src.to_string())
    }
}

impl From<ConversionError> for Error {
    fn from(src: ConversionError) -> Self {
        Self::Conversion(src)
    }
}

impl From<SignatureError> for Error {
    fn from(src: SignatureError) -> Self {
        Self::Signature(src.to_string())
    }
}

impl From<ProtobufError> for Error {
    fn from(src: ProtobufError) -> Self {
        Self::Protobuf(src.to_string())
    }
}

/// Alias for Result with our Error type.
pub type Result<T> = core::result::Result<T, Error>;
