// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Untrusted attestation support

use displaydoc::Display;
use mc_sgx_dcap_types::Quote3;
use mc_attest_core::{
    EpidGroupId, PibError, PlatformInfoBlob, ProviderId, Quote, QuoteError, QuoteNonce,
    QuoteSignType, Report, SgxError, SigRL, TargetInfo, UpdateInfo,
};
#[cfg(not(feature = "sgx-sim"))]
use mc_sgx_dcap_ql::QeTargetInfo;
use mc_sgx_dcap_types::QlError;
use mc_sgx_types::{
    sgx_calc_quote_size, sgx_get_extended_epid_group_id, sgx_get_quote,
    sgx_report_attestation_status, sgx_status_t,
};

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
        let quote = Quote3::try_From_report(report.clone())?;
        Ok((quote, report.clone()))
    }

    pub fn target_info() -> Result<(TargetInfo, EpidGroupId), TargetInfoError> {
        let gid = Self::epid_group_id()?;
        #[cfg(feature = "sgx-sim")]
        {
            // The Intel QE and PCE provided with `libsgx-dcap-ql` only work on SGX
            // hardware. For EPID there is a simulator implementation of
            // [sgx_init_quote()](https://github.com/intel/linux-sgx/blob/1efe23c20e37f868498f8287921eedfbcecdc216/sdk/simulation/uae_service_sim/quoting_sim.cpp#L138)
            // Unfortunately there doesn't seem to be a DCAP equivalent.
            Ok((TargetInfo::default(), gid))
        }
        #[cfg(not(feature = "sgx-sim"))]
        {
            Ok((TargetInfo::for_quoting_enclave()?, gid))
        }
    }

    pub fn epid_group_id() -> Result<EpidGroupId, SgxError> {
        let mut value: u32 = 0;
        match unsafe { sgx_get_extended_epid_group_id(&mut value) } {
            sgx_status_t::SGX_SUCCESS => Ok(EpidGroupId::from(value)),
            status => Err(status.into()),
        }
    }

    pub fn update_tcb(pib: &PlatformInfoBlob) -> Result<(), PibError> {
        let mut update_info = UpdateInfo::default();
        match unsafe { sgx_report_attestation_status(pib.as_ref(), 1, update_info.as_mut()) } {
            sgx_status_t::SGX_SUCCESS => Ok(()),
            sgx_status_t::SGX_ERROR_UPDATE_NEEDED => Err(update_info.into()),
            status => Err(status.into()),
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

impl From<sgx_status_t> for TargetInfoError {
    fn from(src: sgx_status_t) -> TargetInfoError {
        TargetInfoError::Sgx(src.into())
    }
}
