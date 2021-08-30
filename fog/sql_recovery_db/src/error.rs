// Copyright (c) 2018-2021 The MobileCoin Foundation

use diesel::{result::Error as DieselError, ConnectionError};
use displaydoc::Display;
use mc_crypto_keys::CompressedRistrettoPublic;
use mc_fog_types::common::BlockRange;
use prost::{DecodeError, EncodeError};
use r2d2::Error as R2d2Error;

#[derive(Display, Debug)]
pub enum Error {
    /// Orm: {0}
    Orm(DieselError),

    /// R2d2: {0}
    R2d2(R2d2Error),

    /// Connection error: {0}
    Connection(ConnectionError),

    /// The following ingress key was not found: {0:?}
    MissingIngressKey(CompressedRistrettoPublic),

    /// UserEvent schema violation on row #{0}: {1}
    UserEventSchemaViolation(i64, &'static str),

    /// IngressKeys schema violation: {0}
    IngressKeysSchemaViolation(String),

    /// IngestedBlock schema violation: {0}
    IngestedBlockSchemaViolation(String),

    /// Invalid missed blocks range: {0:?}
    InvalidMissedBlocksRange(BlockRange),

    /// Overlapping missed block range: {0:?} overlaps with {0:?}
    OverlappingMissedBlocksRange(BlockRange, BlockRange),

    /**
     * The data in the database could not be decoded as a
     * VerificationReport: {0:?}
     */
    Decode(DecodeError),

    /// The data could not be encoded for storage in the database: {0:?}
    Encode(EncodeError),
}

impl Error {
    /// Policy decision, whether the call should be retried.
    pub fn should_retry(&self) -> bool {
        match self {
            Self::Orm(DieselError::DatabaseError(_, info)) => {
                info.message() == "no connection to the server\n"
                    || info.message() == "terminating connection due to administrator command"
            }
            _ => false,
        }
    }
}

impl From<DieselError> for Error {
    fn from(src: DieselError) -> Self {
        Self::Orm(src)
    }
}

impl From<R2d2Error> for Error {
    fn from(src: R2d2Error) -> Self {
        Self::R2d2(src)
    }
}

impl From<ConnectionError> for Error {
    fn from(src: ConnectionError) -> Self {
        Self::Connection(src)
    }
}

impl From<DecodeError> for Error {
    fn from(src: DecodeError) -> Self {
        Self::Decode(src)
    }
}

impl From<EncodeError> for Error {
    fn from(src: EncodeError) -> Self {
        Self::Encode(src)
    }
}
