// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Attestation verification code and data structures shared between the
//! SDK, node, and enclave

#![no_std]
#![feature(core_intrinsics)]

extern crate alloc;

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
    ias::verify::{
        EpidPseudonym, VerificationReport, VerificationReportData, VerificationSignature,
    },
    nonce::{IasNonce, Nonce, QuoteNonce},
    quote::{Quote, QuoteSignType},
    report::Report,
    seal::{IntelSealed, IntelSealingError, ParseSealedError, Sealed},
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

/// The IAS version we support
pub const IAS_VERSION: f64 = 4.0;
