// Copyright (c) 2018-2022 The MobileCoin Foundation

use displaydoc::Display;
use grpcio::RpcStatus;
use mc_common::logger::Logger;
use mc_fog_ledger_enclave_api::Error as LedgerEnclaveError;
use mc_sgx_report_cache_untrusted::Error as ReportCacheError;
use mc_util_grpc::{rpc_internal_error, rpc_permissions_error};

#[derive(Debug, Display)]
pub enum RouterServerError {
    /// Error related to contacting Fog Ledger Store: {0}
    LedgerStoreError(String),
    /// Ledger Enclave error: {0}
    Enclave(LedgerEnclaveError),
}

impl From<grpcio::Error> for RouterServerError {
    fn from(src: grpcio::Error) -> Self {
        RouterServerError::LedgerStoreError(format!("{}", src))
    }
}

impl From<mc_common::ResponderIdParseError> for RouterServerError {
    fn from(src: mc_common::ResponderIdParseError) -> Self {
        RouterServerError::LedgerStoreError(format!("{}", src))
    }
}

impl From<mc_util_uri::UriParseError> for RouterServerError {
    fn from(src: mc_util_uri::UriParseError) -> Self {
        RouterServerError::LedgerStoreError(format!("{}", src))
    }
}

impl From<mc_util_uri::UriConversionError> for RouterServerError {
    fn from(src: mc_util_uri::UriConversionError) -> Self {
        RouterServerError::LedgerStoreError(format!("{}", src))
    }
}

pub fn router_server_err_to_rpc_status(
    context: &str,
    src: RouterServerError,
    logger: Logger,
) -> RpcStatus {
    match src {
        RouterServerError::LedgerStoreError(_) => {
            rpc_internal_error(context, format!("{}", src), &logger)
        }
        RouterServerError::Enclave(_) => {
            rpc_permissions_error(context, format!("{}", src), &logger)
        }
    }
}

impl From<LedgerEnclaveError> for RouterServerError {
    fn from(src: LedgerEnclaveError) -> Self {
        RouterServerError::Enclave(src)
    }
}

#[allow(dead_code)] // FIXME when the ledger router is more than just a skeleton.
#[derive(Debug, Display)]
pub enum LedgerServerError {
    /// Ledger Enclave error: {0}
    Enclave(LedgerEnclaveError),
    /// Failed to join thread: {0}
    ThreadJoin(String),
    /// RPC shutdown failure: {0}
    RpcShutdown(String),
    /// Report cache error: {0}
    ReportCache(ReportCacheError),
}

impl From<LedgerEnclaveError> for LedgerServerError {
    fn from(src: LedgerEnclaveError) -> Self {
        LedgerServerError::Enclave(src)
    }
}

impl From<ReportCacheError> for LedgerServerError {
    fn from(src: ReportCacheError) -> Self {
        Self::ReportCache(src)
    }
}
