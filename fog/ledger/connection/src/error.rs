// Copyright (c) 2018-2021 The MobileCoin Foundation

use displaydoc::Display;
use protobuf::error::ProtobufError;
use retry::Error as RetryError;

use mc_api::ConversionError;

use mc_fog_enclave_connection::Error as EnclaveConnectionError;

/// Error type returned by LedgerServerConn
#[derive(Debug, Display)]
pub enum Error {
    /// Enclave Connection Error: {0}
    Connection(RetryError<EnclaveConnectionError>),
    /// Protobuf Error: {0}
    Protobuf(ProtobufError),
    /// Deserialization failed
    DeserializationFailed,
    /// Mobilecoin API Conversion Error: {0}
    Conversion(ConversionError),
    /// grpcio error: {0}
    Grpc(grpcio::Error),
}

impl From<RetryError<EnclaveConnectionError>> for Error {
    fn from(err: RetryError<EnclaveConnectionError>) -> Self {
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
