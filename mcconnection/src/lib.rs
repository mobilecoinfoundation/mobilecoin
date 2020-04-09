// Copyright (c) 2018-2020 MobileCoin Inc.

//! Connection support

mod error;
mod grpcio_utils;
mod manager;
mod sync;
mod thick;
mod traits;

pub use self::{
    error::{Error, Result, RetryError, RetryResult},
    grpcio_utils::{ConnectionUriGrpcioChannel, ConnectionUriGrpcioServer},
    manager::ConnectionManager,
    sync::SyncConnection,
    thick::{ThickClient, ThickClientAttestationError},
    traits::{
        AttestationError, AttestedConnection, BlockchainConnection, Connection,
        RetryableBlockchainConnection, RetryableUserTxConnection, UserTxConnection,
    },
};

pub use common::trace_time as _trace_time;
pub use retry as _retry;
