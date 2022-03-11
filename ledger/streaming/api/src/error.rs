// Copyright (c) 2018-2022 The MobileCoin Foundation

use displaydoc::Display;
use grpcio::Error as GrpcError;
use mc_api::ConversionError;
use mc_crypto_keys::SignatureError;
use protobuf::ProtobufError;

#[derive(Debug, Display)]
pub enum Error {
    /// gRPC: {0}
    Grpc(GrpcError),

    /// Conversion: {0}
    Conversion(ConversionError),

    /// Protobuf de/serialization: {0}
    Protobuf(ProtobufError),

    /// Invalid signature: {0}
    Signature(SignatureError),
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

impl From<SignatureError> for Error {
    fn from(src: SignatureError) -> Self {
        Self::Signature(src)
    }
}

impl From<ProtobufError> for Error {
    fn from(src: ProtobufError) -> Self {
        Self::Protobuf(src)
    }
}

pub type Result<T> = core::result::Result<T, Error>;
