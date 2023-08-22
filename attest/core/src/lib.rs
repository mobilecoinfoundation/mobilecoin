// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Attestation verification code and data structures shared between the
//! SDK, node, and enclave

#![no_std]
#![feature(core_intrinsics)]
#![allow(clippy::result_large_err)]

extern crate alloc;
#[macro_use]
extern crate mc_util_repr_bytes;

mod error;
mod ias;
mod nonce;
mod quote;
mod seal;
mod sigrl;
mod traits;
mod types;

pub use crate::{
    error::{
        EpidPseudonymError, IasQuoteError, IasQuoteResult, JsonError, NonceError, PibError,
        PseManifestError, PseManifestHashError, PseManifestResult, QuoteError, QuoteSignTypeError,
        QuoteVerifyError, ReportBodyVerifyError, ReportDetailsError, RevocationCause, SgxError,
        SgxResult, SignatureError, VerifyError,
    },
    ias::verify::{EpidPseudonym, VerificationReportData},
    nonce::{IasNonce, Nonce, QuoteNonce},
    quote::{Quote, QuoteSignType},
    seal::{IntelSealed, IntelSealingError, ParseSealedError, Sealed},
    sigrl::SigRL,
    types::{
        basename::Basename, epid_group_id::EpidGroupId, key_id::KeyId, mac::Mac,
        measurement::Measurement, pib::PlatformInfoBlob, report_data::ReportDataMask,
        spid::ProviderId, update_info::*,
    },
};

pub use mc_attest_verifier_types::{
    DcapEvidence, EvidenceMessage, VerificationReport, VerificationSignature
};

pub use mc_sgx_core_types::{
    Attributes, ConfigId, ConfigSvn, CpuSvn, ExtendedProductId, FamilyId, IsvProductId, IsvSvn,
    MiscellaneousSelect, MrEnclave, MrSigner, Report, ReportBody, ReportData, TargetInfo,
};

/// The IAS version we support
pub const IAS_VERSION: f64 = 4.0;

// Engine for base64 strings
pub(crate) use base64::engine::general_purpose::STANDARD as BASE64_ENGINE;
