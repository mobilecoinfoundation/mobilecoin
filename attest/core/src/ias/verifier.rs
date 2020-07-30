// Copyright (c) 2018-2020 MobileCoin Inc.

//! Intel Attestation Report Verifier

use crate::{
    ias::verify::{VerificationReport, VerificationReportData},
    nonce::IasNonce,
    quote::Quote,
    quote::QuoteSignType,
    types::{
        epid_group_id::EpidGroupId,
        measurement::{MrEnclave, MrSigner},
        report_body::ReportBody,
        report_data::ReportDataMask,
        ProductId, SecurityVersion,
    },
    IAS_SIGNING_ROOT_CERT_PEMS,
};
use alloc::{
    boxed::Box,
    string::{String, ToString},
    vec::Vec,
};
use core::convert::TryFrom;
use mbedtls::{x509::Certificate, Error as TlsError};

/// A trait which can be used to verify the JSON contents of an IAS verification
/// report.
trait VerifyIasReportData {
    /// Check the data against the verifier's contents, return true on success,
    /// false on failure.
    fn verify(&self, data: &VerificationReportData) -> bool;
}

/// A structure which can verify a top-level report.
pub struct IasReportVerifier {
    trust_anchors: Vec<Certificate>,
    data_verifiers: Vec<Box<dyn VerifyIasReportData>>,
}

impl IasReportVerifier {
    pub fn verify(&self, report: &VerificationReport) -> bool {
        // verify signature
        // parse report
        let report_data = VerificationReportData::try_from(report);
        false
    }
}

/// A trait which can be used to verify quote contents.
pub trait VerifyQuote {
    fn verify(&self, quote: &Quote) -> bool;
}

struct QuoteBodyVerifier {
    body_verifiers: Vec<Box<dyn VerifyReportBody>>,
}

impl VerifyQuote for QuoteBodyVerifier {
    fn verify(&self, quote: &Quote) -> bool {}
}

/// A trait which can be used to verify the report body within a quote
pub trait VerifyReportBody {
    fn verify(&self, report_body: &ReportBody) -> bool;
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum BuilderError {
    InvalidTrustAnchor(String),
}

pub struct Builder {
    trust_anchors: Vec<Certificate>,
    verifiers: Vec<Box<dyn VerifyReportData>>,
}

/// Construct a new builder using the baked-in IAS root certificates
impl Default for Builder {
    fn default() -> Self {
        Self::new(IAS_SIGNING_ROOT_CERT_PEMS).expect("Invalid hard-coded certificates found")
    }
}

impl Builder {
    pub fn new(pem_trust_anchors: &[&str]) -> Result<Self, BuilderError> {
        let trust_anchors = pem_trust_anchors
            .iter()
            .map(|pem| {
                if !pem.ends_with('\0') {
                    let mut tmp_str = String::from(*pem);
                    tmp_str.push('\0');
                    Certificate::from_pem(tmp_str.as_bytes())
                } else {
                    Certificate::from_pem(pem.as_bytes())
                }
            })
            .collect::<Result<Vec<Certificate>, TlsError>>()
            .map_err(|e| BuilderError::InvalidTrustAnchor(e.to_string()))?;

        Ok(Self {
            trust_anchors,
            verifiers: Default::default(),
        })
    }

    pub fn debug(&mut self, _allow_debug: bool) -> &mut Self {
        self
    }

    pub fn epid_group_id(&mut self, _group_id: &EpidGroupId) -> &mut Self {
        self
    }

    pub fn mrenclave<S: AsRef<str>, I: Iterator<Item = S>>(
        &mut self,
        _enabled: bool,
        _mrenclave: &MrEnclave,
        _mitigated_ids: I,
    ) -> &mut Self {
        self
    }

    pub fn mrsigner<S: AsRef<str>, I: Iterator<Item = S>>(
        &mut self,
        _enabled: bool,
        _mrsigner: &MrSigner,
        _product_id: ProductId,
        _security_version: SecurityVersion,
        _mitigated_ids: I,
    ) -> &mut Self {
        self
    }

    pub fn nonce(&mut self, _nonce: &IasNonce) -> &mut Self {
        self
    }

    pub fn pse_manifest_hash(&mut self, _hash: &[u8]) -> &mut Self {
        self
    }

    pub fn quote_sign(&mut self, _sign_type: QuoteSignType) -> &mut Self {
        self
    }

    pub fn report_data(&mut self, _report_data: &ReportDataMask) -> &mut Self {
        self
    }

    pub fn generate(&mut self) -> ReportVerifier {}
}

/// A ReportVerifier implementation that will check if the enclave in question
/// is running in debug mode
pub struct DebugVerifier {
    /// The nonce to be checked for.
    pub debug: bool,
}

impl ReportDataVerifier for DebugVerifier {
    fn verify(&self, data: &VerificationReportData) -> bool {
        data.quote.report_body
    }
}

/// A ReportVerifier implementation that will check report data for the
/// presence of the given nonce.
pub struct NonceVerifier {
    /// The nonce to be checked for.
    pub nonce: IasNonce,
}

impl ReportDataVerifier for NonceVerifier {
    fn verify(&self, data: &VerificationReportData) -> bool {
        data.nonce
            .as_ref()
            .map(|v| v.eq(&self.nonce))
            .unwrap_or(false)
    }
}
