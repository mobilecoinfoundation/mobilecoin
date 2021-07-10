// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Attestation verification code and data structures shared between the
//! SDK, node, and enclave

#![no_std]
#![feature(core_intrinsics)]

extern crate alloc;

use cfg_if::cfg_if;

mod error;
mod ias;
mod nonce;
mod quote;
mod report;
mod seal;
mod sigrl;
mod traits;
mod types;

pub use crate::{
    error::{
        EpidPseudonymError, IasQuoteError, IasQuoteResult, JsonError, NonceError, PibError,
        PseManifestError, PseManifestHashError, PseManifestResult, QuoteError, QuoteSignTypeError,
        QuoteVerifyError, ReportBodyVerifyError, ReportDetailsError, RevocationCause, SgxError,
        SgxResult, SignatureError, TargetInfoError, VerifyError,
    },
    ias::{
        verifier::{Error as VerifierError, MrEnclaveVerifier, MrSignerVerifier, Verifier},
        verify::{
            EpidPseudonym, VerificationReport, VerificationReportData, VerificationSignature,
        },
    },
    nonce::{IasNonce, Nonce, QuoteNonce},
    quote::{Quote, QuoteSignType},
    report::Report,
    seal::{IntelSealed, ParseSealedError, Sealed},
    sigrl::SigRL,
    types::{
        attributes::Attributes,
        basename::Basename,
        config_id::ConfigId,
        cpu_svn::CpuSecurityVersion,
        epid_group_id::EpidGroupId,
        ext_prod_id::ExtendedProductId,
        family_id::FamilyId,
        key_id::KeyId,
        mac::Mac,
        measurement::{Measurement, MrEnclave, MrSigner},
        pib::PlatformInfoBlob,
        report_body::ReportBody,
        report_data::{ReportData, ReportDataMask},
        spid::ProviderId,
        target_info::TargetInfo,
        update_info::*,
        ConfigSecurityVersion, MiscSelect, ProductId, SecurityVersion,
    },
};

#[cfg(feature = "sgx-sim")]
pub use crate::ias::sim::{
    IAS_SIM_MODULUS, IAS_SIM_ROOT_ANCHORS, IAS_SIM_SIGNING_CHAIN, IAS_SIM_SIGNING_KEY,
};

/// The IAS version we support
pub const IAS_VERSION: f64 = 4.0;

cfg_if! {
    if #[cfg(feature = "sgx-sim")] {
        /// Whether or not enclaves should be run and validated in debug mode
        pub const DEBUG_ENCLAVE: bool = true;
        /// An array of zero-terminated signing certificate PEM files used as root anchors.
        pub const IAS_SIGNING_ROOT_CERT_PEMS: &[&str] = &[crate::IAS_SIM_ROOT_ANCHORS];
    } else if #[cfg(feature = "ias-dev")] {
        /// Whether or not enclaves should be run and validated in debug mode
        pub const DEBUG_ENCLAVE: bool = true;
        /// An array of zero-terminated signing certificate PEM files used as root anchors.
        pub const IAS_SIGNING_ROOT_CERT_PEMS: &[&str] = &[concat!(include_str!(
            "../data/Dev_AttestationReportSigningCACert.pem"
        ), "\0")];
    } else {
        /// Debug enclaves in prod mode are not supported.
        pub const DEBUG_ENCLAVE: bool = false;
        /// An array of zero-terminated signing certificate PEM files used as root anchors.
        pub const IAS_SIGNING_ROOT_CERT_PEMS: &[&str] = &[concat!(include_str!(
            "../data/AttestationReportSigningCACert.pem"
        ), "\0")];
    }
}
