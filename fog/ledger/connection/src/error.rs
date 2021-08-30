// Copyright (c) 2018-2021 The MobileCoin Foundation

use displaydoc::Display;
use protobuf::error::ProtobufError;

use mc_api::ConversionError;

use mc_fog_enclave_connection::Error as EnclaveConnectionError;

/// Error type returned by LedgerServerConn
#[derive(Debug, Display)]
pub enum Error {
    /// Enclave Connection Error: {0}
    Connection(EnclaveConnectionError),
    /// Protobuf Error: {0}
    Protobuf(ProtobufError),
    /// Deserialization failed
    DeserializationFailed,
    /// Mobilecoin API Conversion Error: {0}
    Conversion(ConversionError),
    /// grpcio error: {0}
    Grpc(grpcio::Error),
}

impl From<EnclaveConnectionError> for Error {
    fn from(err: EnclaveConnectionError) -> Self {
        Error::Connection(err)
    }
}

impl From<ProtobufError> for Error {
    fn from(err: ProtobufError) -> Self {
        Error::Protobuf(err)
    }
}

impl From<ConversionError> for Error {
    fn from(err: ConversionError) -> Self {
        Error::Conversion(err)
    }
}

impl From<grpcio::Error> for Error {
    fn from(err: grpcio::Error) -> Self {
        Error::Grpc(err)
    }
}
