// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Untrusted attestation support

use displaydoc::Display;
use mc_attest_core::{
    EnclaveReportDataContents, EpidGroupId, PibError, PlatformInfoBlob, ProviderId, Quote,
    QuoteError, QuoteSignType, Report, SgxError, SigRL, TargetInfo, UpdateInfo,
};
use mc_sgx_dcap_types::QlError;
use mc_sgx_types::{
    sgx_calc_quote_size, sgx_get_extended_epid_group_id, sgx_get_quote,
    sgx_report_attestation_status, sgx_status_t,
};

cfg_if::cfg_if! {
    if #[cfg(feature = "sgx-sim")] {
        mod sim;
        pub type DcapQuotingEnclave = crate::sim::SimQuotingEnclave;
    } else {
        mod hw;
        pub type DcapQuotingEnclave = crate::hw::HwQuotingEnclave;
    }
}

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
        quote_sign_type: QuoteSignType,
        spid: &ProviderId,
        report_data: &EnclaveReportDataContents,
        sigrl: &SigRL,
    ) -> Result<(Quote, Report), QuoteError> {
        let mut quote_size: u32 = 0;
        let mut quote =
            match unsafe { sgx_calc_quote_size(sigrl.as_ptr(), sigrl.size(), &mut quote_size) } {
                sgx_status_t::SGX_SUCCESS => Quote::with_capacity(quote_size),
                status => Err(status.into()),
            }?;

        let mut qe_report = Report::default();

        match unsafe {
            sgx_get_quote(
                report.as_ref(),
                quote_sign_type.into(),
                spid.as_ref(),
                report_data.nonce().as_ref(),
                sigrl.as_ptr(),
                sigrl.size(),
                qe_report.as_mut(),
                quote.as_mut_ptr(),
                quote_size,
            )
        } {
            sgx_status_t::SGX_SUCCESS => Ok((quote, qe_report)),
            status => Err(status.into()),
        }
    }

    pub fn target_info() -> Result<(TargetInfo, EpidGroupId), TargetInfoError> {
        let gid = Self::epid_group_id()?;
        Ok((DcapQuotingEnclave::target_info()?, gid))
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
