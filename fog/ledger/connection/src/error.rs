// Copyright (c) 2018-2022 The MobileCoin Foundation

use displaydoc::Display;
use protobuf::error::ProtobufError;
use retry::Error as RetryError;

use mc_api::ConversionError;

use mc_fog_enclave_connection::Error as EnclaveConnectionError;
use mc_fog_uri::FogLedgerUri;
use mc_util_uri::UriConversionError;

/// Error type returned by LedgerServerConn
#[derive(Debug, Display)]
pub enum Error {
    /// Enclave Connection Error ({0}): {1}
    Connection(FogLedgerUri, RetryError<EnclaveConnectionError>),
    /// Protobuf Error: {0}
    Protobuf(ProtobufError),
    /// Deserialization failed
    DeserializationFailed,
    /// Mobilecoin API Conversion Error: {0}
    Conversion(ConversionError),
    /// grpcio error ({0}): {1}
    Grpc(FogLedgerUri, RetryError<grpcio::Error>),
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

impl From<UriConversionError> for Error {
    fn from(err: UriConversionError) -> Self {
        Self::UriConversionError(err)
    }
}
