// Copyright (c) 2018-2023 The MobileCoin Foundation

use displaydoc::Display;
use grpcio::RpcStatusCode;
use mc_api::ConversionError;

#[derive(Debug, Display)]
pub enum Error {
    /// Not found
    NotFound,

    /// LedgerDb: {0}
    LedgerDb(mc_ledger_db::Error),

    /// GRPC: {0}
    Grpc(grpcio::Error),

    /// Conversion: {0}
    Conversion(ConversionError),
}

impl From<mc_ledger_db::Error> for Error {
    fn from(err: mc_ledger_db::Error) -> Self {
        match err {
            mc_ledger_db::Error::NotFound => Self::NotFound,
            _ => Self::LedgerDb(err),
        }
    }
}

impl From<grpcio::Error> for Error {
    fn from(err: grpcio::Error) -> Self {
        match err {
            grpcio::Error::RpcFailure(ref status) => {
                if status.code() == RpcStatusCode::NOT_FOUND {
                    Self::NotFound
                } else {
                    Self::Grpc(err)
                }
            }
            _ => Self::Grpc(err),
        }
    }
}

impl From<ConversionError> for Error {
    fn from(err: ConversionError) -> Self {
        Self::Conversion(err)
    }
}
