// Copyright (c) 2018-2023 The MobileCoin Foundation

use displaydoc::Display;
use grpcio::RpcStatusCode;

#[derive(Debug, Display)]
pub enum Error {
    /// Not found
    NotFound,

    /// LedgerDb: {0}
    LedgerDb(mc_ledger_db::Error),

    /// GRPC: {0}
    Grpc(grpcio::Error),
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
