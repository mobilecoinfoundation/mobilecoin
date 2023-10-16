// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Untrusted attestation support

use displaydoc::Display;
use mc_attest_core::SgxError;
use mc_sgx_dcap_types::QlError;
use mc_sgx_types::sgx_status_t;

cfg_if::cfg_if! {
    if #[cfg(feature = "sgx-sim")] {
        mod sim;
        pub type DcapQuotingEnclave = crate::sim::SimQuotingEnclave;
    } else {
        mod hw;
        pub type DcapQuotingEnclave = crate::hw::HwQuotingEnclave;
    }
}

#[derive(Clone, Debug, Display, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum TargetInfoError {
    /// SGX error: {0}
    Sgx(SgxError),
    /// Quote library error: {0}
    Ql(mc_sgx_dcap_ql::Error),
    /// Quoting enclave busy
    QeBusy,
    /// Error retrying: {0}
    Retry(String),
}

impl From<mc_sgx_dcap_ql::Error> for TargetInfoError {
    fn from(src: mc_sgx_dcap_ql::Error) -> Self {
        match src {
            mc_sgx_dcap_ql::Error::QuoteLibrary(QlError::Busy) => TargetInfoError::QeBusy,
            e => TargetInfoError::Ql(e),
        }
    }
}

impl From<SgxError> for TargetInfoError {
    fn from(src: SgxError) -> Self {
        TargetInfoError::Sgx(src)
    }
}

impl From<sgx_status_t> for TargetInfoError {
    fn from(src: sgx_status_t) -> TargetInfoError {
        TargetInfoError::Sgx(src.into())
    }
}
