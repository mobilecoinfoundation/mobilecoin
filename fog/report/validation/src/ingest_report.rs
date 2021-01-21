// Copyright (c) 2018-2021 The MobileCoin Foundation

use core::convert::TryFrom;
use displaydoc::Display;
use mc_attest_core::{
    QuoteSignType, ReportData, ReportDataMask, VerificationReport, VerificationReportData,
    Verifier, VerifierError, VerifyError,
};
use mc_crypto_keys::{KeyError, RistrettoPublic};
use mc_util_encodings::Error as EncodingError;

/// A structure that can validate ingest enclave reports and measurements at runtime.
///
/// This is expected to take the verification report and produce the ias-validated and decompressed RistrettoPublic key.
#[derive(Default, Clone, Debug)]
pub struct IngestReportVerifier {
    verifier: Verifier,
}

impl IngestReportVerifier {
    /// Validate a remote ingest ias report, and extract the pubkey from the report data bytes.
    /// The details of this are tied to the layout of the "identity" object in the ingest enclave impl.
    pub fn validate_ingest_ias_report(
        &self,
        remote_report: VerificationReport,
    ) -> Result<RistrettoPublic, Error> {
        let verification_report_data = VerificationReportData::try_from(&remote_report)?;
        let report_data: ReportData = verification_report_data.quote.report_body()?.report_data();
        let report_data_bytes: &[u8] = report_data.as_ref();

        // Extract the pubkey from the signed evidence
        let report_pubkey: RistrettoPublic = RistrettoPublic::try_from(&report_data_bytes[32..64])?;

        let masked_report_data = ReportDataMask::new_with_mask(report_data_bytes, &[0u8; 32])?;

        let mut verifier = self.verifier.clone();
        verifier
            .sign_type(QuoteSignType::Linkable)
            .report_data(&masked_report_data);

        verifier.verify(&remote_report)?;

        Ok(report_pubkey)
    }
}

impl From<&Verifier> for IngestReportVerifier {
    fn from(src: &Verifier) -> Self {
        Self {
            verifier: src.clone(),
        }
    }
}

/// An error that can occur when validating an ingest report
#[derive(Clone, Debug, Display, PartialEq)]
pub enum Error {
    /// Encoding Error: {0}
    Encoding(EncodingError),
    /// Key Error: {0}
    Key(KeyError),
    /// Verification failed: {0}
    VerificationParse(VerifyError),
    /// Verifier error: {0}
    Verifier(VerifierError),
}

impl From<EncodingError> for Error {
    fn from(src: EncodingError) -> Self {
        Self::Encoding(src)
    }
}

impl From<VerifyError> for Error {
    fn from(src: VerifyError) -> Self {
        Self::VerificationParse(src)
    }
}

impl From<VerifierError> for Error {
    fn from(src: VerifierError) -> Self {
        Self::Verifier(src)
    }
}

impl From<KeyError> for Error {
    fn from(src: KeyError) -> Self {
        Self::Key(src)
    }
}
