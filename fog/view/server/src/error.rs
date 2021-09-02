// Copyright (c) 2018-2021 The MobileCoin Foundation

use displaydoc::Display;
use mc_fog_view_enclave::Error as ViewEnclaveError;
use mc_sgx_report_cache_untrusted::Error as ReportCacheError;

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
