// Copyright (c) 2018-2020 MobileCoin Inc.

//! Traits and support for EPID-based remote attestation.

#![deny(missing_docs)]

use bitflags::bitflags;
use mc_sgx_core_types::{Report, Result as SgxResult, SgxStatusToResult, TargetInfo};
use mc_sgx_core_types_sys::{SGX_ERROR_UPDATE_NEEDED, SGX_SUCCESS};
use mc_sgx_epid_sys::{
    sgx_calc_quote_size, sgx_check_update_status, sgx_get_quote, sgx_init_quote,
};
use mc_sgx_epid_types::{
    EpidGroupId, PlatformInfo, ProviderId, Quote, QuoteNonce, QuoteSign, SignatureRevocationList,
    UpdateInfo,
};

/// Monkey-patch an existing structure to allow creation by Intel's EPID Quoting Enclave.
pub trait EpidQuotingEnclave: Sized {
    /// Create a new structure initialized for communications with Intel's EPID Quoting Enclave.
    ///
    /// This method wraps the [`sgx_init_quote`] FFI method to return the structure used for the
    /// communications with the EPID Quoting Enclave. In particular, the [`TargetInfo`] and
    /// [`EpidGroupId`] structures.
    fn for_epid_qe() -> SgxResult<Self>;
}

/// Retrieve the target info structure for the Quoting Enclave.
///
/// This target info is then used inside an enclave to create a new [`Report`] structure for remote
/// attestation use.
impl EpidQuotingEnclave for TargetInfo {
    fn for_epid_qe() -> SgxResult<TargetInfo> {
        let mut target_info = TargetInfo::default();
        let mut epid_gid = EpidGroupId::default();

        unsafe { sgx_init_quote(target_info.as_mut(), epid_gid.as_mut()) }.into_result(target_info)
    }
}

/// Retrieve the EpidGroupId of the current Quoting Enclave.
///
/// This is used to contact IAS and retrieve the [`SignatureRevocationList`] data structure.
impl EpidQuotingEnclave for EpidGroupId {
    fn for_epid_qe() -> SgxResult<EpidGroupId> {
        let mut target_info = TargetInfo::default();
        let mut epid_gid = EpidGroupId::default();

        unsafe { sgx_init_quote(target_info.as_mut(), epid_gid.as_mut()) }.into_result(epid_gid)
    }
}

/// Create a new quote from an existing enclave's report.
pub trait EpidQuoteReport {
    /// Contact the Quoting Enclave to create a new quote from the given report.
    ///
    /// Given a report created inside an enclave using the Quoting Enclave's target info, this
    /// method will contact the Quoting Enclave, and return a tuple containing the quote and the
    /// Quoting Enclave's own report, targeting the original enclave.
    ///
    /// Therefore, the stages are:
    ///
    ///  1. Create a new report inside Enclave A targeting the Quoting Enclave.
    ///  1. Enclave A exports the report to the untrusted code.
    ///  1. Untrusted code calls this method to create a new quote, using the given nonce.
    ///  1. Untrusted code provides the resulting quote and QE enclave's report to enclave A.
    ///  1. Enclave A verifies the QE enclave's report targets Enclave A.
    ///  1. Enclave A verifies the QE enclave's report data contains the hash of the nonce and the
    ///     quote.
    ///  1. Enclave A verifies the contents of the quote.
    fn quote(
        sigrl: &SignatureRevocationList,
        report: &Report,
        quote_type: QuoteSign,
        provider_id: &ProviderId,
        nonce: &QuoteNonce,
    ) -> SgxResult<(Quote, Report)>;
}

impl EpidQuoteReport for Quote {
    fn quote(
        sigrl: &SignatureRevocationList,
        report: &Report,
        quote_type: QuoteSign,
        provider_id: &ProviderId,
        nonce: &QuoteNonce,
    ) -> SgxResult<(Quote, Report)> {
        let sigrl_ref = sigrl.as_ref();
        let mut quote_size = 0u32;
        unsafe { sgx_calc_quote_size(sigrl_ref.as_ptr(), sigrl_ref.len() as u32, &mut quote_size) }
            .into_result(())?;

        let mut quote = Quote::with_capacity(quote_size as usize)
            .expect("SGX SDK requested a quote larger than we are allowed to use");

        let mut qe_report = Report::default();

        unsafe {
            sgx_get_quote(
                report.as_ref(),
                quote_type.into(),
                provider_id.as_ref(),
                nonce.as_ref(),
                sigrl_ref.as_ptr(),
                sigrl_ref.len() as u32,
                qe_report.as_mut(),
                quote.as_mut(),
                quote_size,
            )
        }
        .into_result((quote, qe_report))
    }
}

bitflags! {
    /// A set of bitflags describing what kind of reprovisioning to perform, if any.
    pub struct EpidUpdateConfig: u32 {
        /// Set if the caller wants to trigger Intel EPID provisioning if it is needed/pending.
        const PROVISION_EPID = 1 << 1;
        /// Set if the caller wants to trigger PSE provisioning/long-term pairing if it is
        /// needed/pending.
        const PROVISION_PSE = 1 << 2;
    }
}

bitflags! {
    /// A set of bitflags indicating what, if any updates were done/required.
    pub struct EpidUpdateStatus: u32 {
        /// Set if any update is available, the adjacent update_info field will have the details.
        const UPDATE_NEEDED = 1;
        /// Set if Intel EPID provisioning is or was needed/pending. Set or cleared independent of
        /// config input.
        const EPID_NEEDED = 1 << 1;
        /// Set if PSE provisioning/long-term pairing is or was needed/pending. Set or cleared
        /// independent of config input.
        const PSE_NEEDED = 1 << 2;
    }
}

/// An optional update return, indicating what updates, if any are available or were performed.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TcbUpdate {
    /// A description of what updates are needed/pending.
    pub status: EpidUpdateStatus,
    /// The update info describing whether software updates must be performed out-of band.
    pub update_info: UpdateInfo,
}

/// A trait encapsulating the various means of interacting with the TCB update process.
pub trait EpidPlatformInfo: Sized {
    /// Check if there is a TCB update available, potentially updating it.
    ///
    /// This is fairly complex machinery: the given configuration will alternatively check for any
    /// available updates, update some of the TCB, or update all of the TCB which can be updated.
    ///
    /// The outer `Result` indicates whether the API calls succeeded, and the inner `Option` on
    /// the `Ok` branch indicates whether there is an update available, and/or whether one was
    /// performed.
    fn check_update_status(&self, config: EpidUpdateConfig) -> SgxResult<Option<TcbUpdate>>;
}

impl EpidPlatformInfo for PlatformInfo {
    fn check_update_status(&self, config: EpidUpdateConfig) -> SgxResult<Option<TcbUpdate>> {
        let mut update_info = UpdateInfo::default();
        let mut p_status = 0u32;

        match unsafe {
            sgx_check_update_status(
                self.as_ref(),
                update_info.as_mut(),
                config.bits,
                &mut p_status,
            )
        } {
            SGX_SUCCESS => Ok(None),
            SGX_ERROR_UPDATE_NEEDED => {
                let tcb_update = TcbUpdate {
                    status: EpidUpdateStatus::from_bits(p_status)
                        .expect("Unknown bitflag found in check_update_status p_status"),
                    update_info,
                };

                Ok(Some(tcb_update))
            }
            other => other.into_result(None),
        }
    }
}
