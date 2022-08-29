// Copyright (c) 2018-2022 The MobileCoin Foundation

use displaydoc::Display;
use grpcio::RpcStatus;
use mc_common::logger::Logger;
use mc_fog_view_enclave::Error as ViewEnclaveError;
use mc_sgx_report_cache_untrusted::Error as ReportCacheError;
use mc_util_grpc::{rpc_internal_error, rpc_permissions_error};

#[derive(Debug, Display)]
pub enum RouterServerError {
    /// Error related to contacting Fog View Store: {0}
    ViewStoreError(String),
    /// View Enclave error: {0}
    Enclave(ViewEnclaveError),
}

impl From<grpcio::Error> for RouterServerError {
    fn from(src: grpcio::Error) -> Self {
        RouterServerError::ViewStoreError(format!("{}", src))
    }
}

impl From<mc_common::ResponderIdParseError> for RouterServerError {
    fn from(src: mc_common::ResponderIdParseError) -> Self {
        RouterServerError::ViewStoreError(format!("{}", src))
    }
}

impl From<mc_util_uri::UriParseError> for RouterServerError {
    fn from(src: mc_util_uri::UriParseError) -> Self {
        RouterServerError::ViewStoreError(format!("{}", src))
    }
}

impl From<mc_util_uri::UriConversionError> for RouterServerError {
    fn from(src: mc_util_uri::UriConversionError) -> Self {
        RouterServerError::ViewStoreError(format!("{}", src))
    }
}

pub fn router_server_err_to_rpc_status(
    context: &str,
    src: RouterServerError,
    logger: Logger,
) -> RpcStatus {
    match src {
        RouterServerError::ViewStoreError(_) => {
            rpc_internal_error(context, format!("{}", src), &logger)
        }
        RouterServerError::Enclave(_) => {
            rpc_permissions_error(context, format!("{}", src), &logger)
        }
    }
}

impl From<ViewEnclaveError> for RouterServerError {
    fn from(src: ViewEnclaveError) -> Self {
        RouterServerError::Enclave(src)
    }
}

#[derive(Debug, Display)]
pub enum ViewServerError {
    /// View Enclave error: {0}
    Enclave(ViewEnclaveError),
    /// Failed to join thread: {0}
    ThreadJoin(String),
    /// RPC shutdown failure: {0}
    RpcShutdown(String),
    /// Report cache error: {0}
    ReportCache(ReportCacheError),
}

impl From<ViewEnclaveError> for ViewServerError {
    fn from(src: ViewEnclaveError) -> Self {
        ViewServerError::Enclave(src)
    }
}

impl From<ReportCacheError> for ViewServerError {
    fn from(src: ReportCacheError) -> Self {
        Self::ReportCache(src)
    }
}
