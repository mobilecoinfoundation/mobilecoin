// Copyright (c) 2018-2022 The MobileCoin Foundation

use displaydoc::Display;
use mc_attest_core::{VerificationReportData, VerifyError};
use mc_crypto_keys::{CompressedRistrettoPublic, KeyError};
use mc_fog_report_types::AttestationEvidence;
use mc_util_encodings::Error as EncodingError;

/// Helper function which extracts an unvalidated ingress pubkey from fog ingest
/// attestation evidence.
///
/// This is useful for
/// (1) double checking the attestation evidence (on server side)
/// (2) diagnostic tools that checkup on fog (to simplify those tools)
///
/// This MUST NOT be used by a MobileCoin client because it skips the
/// validation. It cannot be used with the TransactionBuilder or the
/// FogPubkeyResolver infra, because this function does not produce a
/// FullyValidatedFogPubkey.
pub fn try_extract_unvalidated_ingress_pubkey_from_fog_evidence(
    attestation_evidence: &AttestationEvidence,
) -> Result<CompressedRistrettoPublic, ReportParseError> {
    let key_bytes = match attestation_evidence {
        AttestationEvidence::VerificationReport(report) => {
            let verification_report_data = VerificationReportData::try_from(report)?;
            let report_data = verification_report_data.quote.report_body()?.report_data();
            let report_data_bytes: &[u8] = report_data.as_ref();
            report_data_bytes[32..64].to_vec()
        }
        AttestationEvidence::DcapEvidence(evidence) => evidence
            .report_data
            .as_ref()
            .map(|r| r.custom_identity.clone())
            .ok_or(ReportParseError::Encoding(EncodingError::InvalidInput))?,
    };

    Ok(CompressedRistrettoPublic::try_from(key_bytes.as_slice())?)
}

/// An error which occurs when parsing an AVR
#[derive(Debug, Display)]
pub enum ReportParseError {
    /// Verification: {0}
    Verify(VerifyError),
    /// Encoding: {0}
    Encoding(EncodingError),
    /// Key: {0}
    Key(KeyError),
}

impl From<VerifyError> for ReportParseError {
    fn from(src: VerifyError) -> Self {
        Self::Verify(src)
    }
}

impl From<EncodingError> for ReportParseError {
    fn from(src: EncodingError) -> Self {
        Self::Encoding(src)
    }
}

impl From<KeyError> for ReportParseError {
    fn from(src: KeyError) -> Self {
        Self::Key(src)
    }
}
