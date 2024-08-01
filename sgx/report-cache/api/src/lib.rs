// Copyright (c) 2018-2022 The MobileCoin Foundation

//! APIs for report-caching enclaves.

#![no_std]
#![allow(clippy::result_large_err)]

use core::result::Result as StdResult;
use displaydoc::Display;
use mc_attest_core::{DcapEvidence, EnclaveReportDataContents, Report, SgxError, TargetInfo};
use mc_attest_enclave_api::Error as AttestEnclaveError;
use mc_util_serial::{decode::Error as RmpDecodeError, encode::Error as RmpEncodeError};
use serde::{Deserialize, Serialize};

/// An enumeration of errors which can be returned by the methods of the
/// `ReportableEnclave` trait.
#[derive(Debug, Display, Deserialize, Serialize)]
pub enum Error {
    /// Attest enclave error: {0}
    AttestEnclave(AttestEnclaveError),

    /// Error while serializing/deserializing
    Serialization,

    /// Error communicating with SGX: {0}
    Sgx(SgxError),
}

impl From<AttestEnclaveError> for Error {
    fn from(src: AttestEnclaveError) -> Self {
        Self::AttestEnclave(src)
    }
}

impl From<RmpEncodeError> for Error {
    fn from(_src: RmpEncodeError) -> Error {
        Error::Serialization
    }
}

impl From<RmpDecodeError> for Error {
    fn from(_src: RmpDecodeError) -> Error {
        Error::Serialization
    }
}

impl From<SgxError> for Error {
    fn from(src: SgxError) -> Self {
        Self::Sgx(src)
    }
}

/// A type alias for a ReportableEnclave result.
pub type Result<T> = StdResult<T, Error>;

/// A trait that report-caching enclaves need to implement in order to benefit
/// from the functionality provided in `mc-sgx-report-cache-untrusted`.
pub trait ReportableEnclave {
    /// Retrieve a new report for this enclave, targeted for the given
    /// quoting enclave. Untrusted code should call this on startup as
    /// part of the initialization process.
    fn new_ereport(&self, qe_info: TargetInfo) -> Result<(Report, EnclaveReportDataContents)>;

    /// Verify (and cache) the attestation evidence for this enclave.
    ///
    /// The enclave will verify the attestation evidence was signed by a trusted
    /// certificate, and the contents match the previously checked quote.
    /// After that check has been performed, the enclave will use the
    /// attestation evidence for all requests until another attestation evidence
    /// has been successfully loaded in it's place.
    fn verify_attestation_evidence(&self, attestation_evidence: DcapEvidence) -> Result<()>;

    /// Retrieve a copy of the cached attestation evidence.
    fn get_attestation_evidence(&self) -> Result<DcapEvidence>;
}
