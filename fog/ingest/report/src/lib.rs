// Copyright (c) 2018-2022 The MobileCoin Foundation

#![allow(clippy::result_large_err)]

use der::DateTime;
use displaydoc::Display;
use mc_attest_core::{DcapEvidence, VerifyError};
use mc_attest_verifier::{DcapVerifier, Error as VerifierError};
use mc_attestation_verifier::{Evidence, TrustedIdentity, VerificationTreeDisplay};
use mc_crypto_keys::{KeyError, RistrettoPublic};
use mc_util_encodings::Error as EncodingError;
use std::time::SystemTime;

/// A structure that can validate ingest enclave evidence and measurements at
/// runtime.
///
/// This is expected to take the attestation evidence and produce the
/// validated and decompressed RistrettoPublic key.
#[derive(Default, Clone, Debug)]
pub struct IngestAttestationEvidenceVerifier {
    identities: Vec<TrustedIdentity>,
}

impl IngestAttestationEvidenceVerifier {
    /// Validate remote ingest attestation evidence, and extract the pubkey from
    /// the report data bytes. The details of this are tied to the layout of
    /// the "identity" object in the ingest enclave impl.
    pub fn validate_ingest_attestation_evidence(
        &self,
        attestation_evidence: DcapEvidence,
    ) -> Result<RistrettoPublic, Error> {
        let quote = attestation_evidence.quote;
        let collateral = attestation_evidence.collateral;
        let report_data = attestation_evidence.report_data;
        let custom_id = report_data
            .custom_identity()
            .ok_or(Error::Encoding(EncodingError::InvalidInput))?;

        let now = DateTime::from_system_time(SystemTime::now())
            .expect("System time now should always be able to convert to DateTime");
        let verifier = DcapVerifier::new(self.identities.clone(), now, report_data);
        let evidence = Evidence::new(quote, collateral)
            .map_err(|_| Error::Encoding(EncodingError::InvalidInput))?;
        let verification = verifier.verify(&evidence);
        if verification.is_success().into() {
            Ok(RistrettoPublic::try_from(&custom_id)?)
        } else {
            let display_tree = VerificationTreeDisplay::new(&verifier, verification);
            Err(VerifierError::Verification(display_tree.to_string()).into())
        }
    }
}

impl From<&[TrustedIdentity]> for IngestAttestationEvidenceVerifier {
    fn from(src: &[TrustedIdentity]) -> Self {
        Self {
            identities: src.to_vec(),
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
