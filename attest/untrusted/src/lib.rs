// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Untrusted attestation support

use mc_attest_core::{
    EpidGroupId, PibError, PlatformInfoBlob, ProviderId, Quote, QuoteError, QuoteNonce,
    QuoteSignType, Report, SgxError, SigRL, TargetInfo, TargetInfoError, UpdateInfo,
};
use mc_sgx_types::{
    sgx_calc_quote_size, sgx_get_extended_epid_group_id, sgx_get_quote, sgx_init_quote,
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
        quote_sign_type: QuoteSignType,
        spid: &ProviderId,
        nonce: &QuoteNonce,
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
                nonce.as_ref(),
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
        let mut qe_info = TargetInfo::default();
        let mut gid = EpidGroupId::default();
        match unsafe { sgx_init_quote(qe_info.as_mut(), gid.as_mut()) } {
            sgx_status_t::SGX_SUCCESS => Ok((qe_info, gid)),
            sgx_status_t::SGX_ERROR_BUSY => Err(TargetInfoError::QeBusy),
            other_status => Err(TargetInfoError::Sgx(other_status.into())),
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

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
