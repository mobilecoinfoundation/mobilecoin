// Copyright (c) 2018-2022 The MobileCoin Foundation

use crate::BlockIndex;
use displaydoc::Display;
use grpcio::Error as GrpcError;
use mc_api::ConversionError;
use mc_crypto_keys::SignatureError;
use mc_ledger_db::Error as LedgerDBError;
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

    /// DB Access Error: {0}
    DBAccess(String),

    /// Block validation failed: {0}
    BlockValidation(String),

    /// SCP Consensus Behind: last externalized block {0} - highest block {1}
    ConsensusBlocked(BlockIndex, BlockIndex),
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

impl From<mc_ledger_db::Error> for Error {
    fn from(src: LedgerDBError) -> Self {
        Self::DBAccess(src.to_string())
    }
}

/// Alias for Result with our Error type.
pub type Result<T> = core::result::Result<T, Error>;
