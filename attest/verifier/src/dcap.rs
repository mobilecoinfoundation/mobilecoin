// Copyright (c) 2023 The MobileCoin Foundation

//! Verify the contents of a Quote3.

use crate::IAS_SIGNING_ROOT_CERT_PEM;
use alloc::vec::Vec;
use der::DateTime;
use mc_attestation_verifier::{
    Evidence, EvidenceValue, EvidenceVerifier, MbedTlsCertificateChainVerifier, TrustAnchor,
    TrustedIdentity, VerificationOutput, Verifier,
};

#[derive(Debug)]
pub struct DcapVerifier {
    verifier: EvidenceVerifier<MbedTlsCertificateChainVerifier>,
}
impl DcapVerifier {
    /// Create a new instance of the DcapVerifier.
    ///
    /// # Arguments
    /// * `trusted_identities` - The allowed identities that can be used in an
    ///   enclave. Verification will succeed if any of these match.
    /// * `time` - The time to use to verify the validity of the certificates
    ///   and collateral. Verification will fail if this time is before or after
    ///   any of the validity periods.
    pub fn new<I, ID>(trusted_identities: I, time: DateTime) -> Self
    where
        I: IntoIterator<Item = ID>,
        ID: Into<TrustedIdentity>,
    {
        let trust_anchor = TrustAnchor::try_from_pem(IAS_SIGNING_ROOT_CERT_PEM)
            .expect("Failed to parse root cert");
        let certificate_verifier = MbedTlsCertificateChainVerifier::new(trust_anchor);
        let verifier = EvidenceVerifier::new(certificate_verifier, trusted_identities, time);
        Self { verifier }
    }

    /// Verify the `evidence`
    pub fn verify(&self, evidence: Evidence<Vec<u8>>) -> VerificationOutput<EvidenceValue> {
        self.verifier.verify(&evidence)
    }
}
