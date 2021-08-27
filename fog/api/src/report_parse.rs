// Copyright (c) 2021 The MobileCoin Foundation

use core::convert::TryFrom;
use displaydoc::Display;
use mc_attest_core::{VerificationReport, VerificationReportData, VerifyError};
use mc_crypto_keys::{CompressedRistrettoPublic, KeyError};
use mc_util_encodings::Error as EncodingError;

/// Helper function which extracts an unvalidated ingress pubkey from fog ingest
/// report
///
/// This is useful for
/// (1) double checking the report contents (on server side)
/// (2) diagnostic tools that checkup on fog (to simplify those tools)
///
/// This MUST NOT be used by a MobileCoin client because it skips the
/// validation. It cannot be used with the TransactionBuilder or the
/// FogPubkeyResolver infra, because this function does not produce a
/// FullyValidatedFogPubkey.
pub fn try_extract_unvalidated_ingress_pubkey_from_fog_report(
    report: &VerificationReport,
) -> Result<CompressedRistrettoPublic, ReportParseError> {
    let verification_report_data = VerificationReportData::try_from(report)?;
    // This extracts the user-data attached to the report, which is a thin wrapper
    // around [u8; 64]
    let report_data = verification_report_data.quote.report_body()?.report_data();
    // The second half of this is the data we care about, per the fog-ingest-enclave
    // identity implementation. These 32 bytes should be Ristretto.
    let report_data_bytes: &[u8] = report_data.as_ref();
    Ok(CompressedRistrettoPublic::try_from(
        &report_data_bytes[32..64],
    )?)
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
