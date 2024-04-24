// Copyright (c) 2018-2023 The MobileCoin Foundation

use displaydoc::Display;

#[derive(Display, Debug)]
pub enum Error {
    /// GRPC: {0}
    Rpc(grpcio::Error),
}

impl From<grpcio::Error> for Error {
    fn from(src: grpcio::Error) -> Self {
        Self::Rpc(src)
    }
}

impl From<Error> for mc_connection::Error {
    fn from(src: Error) -> Self {
        match src {
            Error::Rpc(src) => mc_connection::Error::Grpc(src),
        }
    }
}
