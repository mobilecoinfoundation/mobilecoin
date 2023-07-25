// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Untrusted attestation support

use displaydoc::Display;
use mc_sgx_dcap_types::Quote3;
use mc_sgx_dcap_ql::TryFromReport;
use mc_attest_core::{
    QuoteError, Report, SgxError, TargetInfo,
};
#[cfg(not(feature = "sgx-sim"))]
use mc_sgx_dcap_ql::QeTargetInfo;
use mc_sgx_dcap_types::QlError;

pub struct QuotingEnclave;

impl QuotingEnclave {
    /// Request the Quoting Enclave create a new quote based on the given
    /// parameters.
    ///
    /// This method is only valid when called from outside an enclave,
    /// and will return the requested quote, as well as the quoting
    /// enclave's own Report.
    pub fn quote_report(
        report: &Report,
    ) -> Result<(Quote3<Vec<u8>>, Report), QuoteError> {
        let quote = Quote3::try_from_report(report.clone()).map_err(|_| QuoteError::DcapQuoteLibrary)?;
        Ok((quote, report.clone()))
    }

    pub fn target_info() -> Result<TargetInfo, TargetInfoError> {
        #[cfg(feature = "sgx-sim")]
        {
            // The Intel QE and PCE provided with `libsgx-dcap-ql` only work on SGX
            // hardware. For EPID there is a simulator implementation of
            // [sgx_init_quote()](https://github.com/intel/linux-sgx/blob/1efe23c20e37f868498f8287921eedfbcecdc216/sdk/simulation/uae_service_sim/quoting_sim.cpp#L138)
            // Unfortunately there doesn't seem to be a DCAP equivalent.
            Ok(TargetInfo::default())
        }
        #[cfg(not(feature = "sgx-sim"))]
        {
            Ok(TargetInfo::for_quoting_enclave()?)
        }
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
