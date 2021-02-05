// Copyright 2018-2021 The MobileCoin Foundation

//! This module provides traits and methods for the signing and verification
//! of report server responses.

mod ed25519;

use mc_attest_core::VerificationReport;
use signature::Signature;
use std::fmt::Display;

/// Retrieve the domain separator used to sign a report server response
pub fn context() -> &'static [u8] {
    b"Fog ingest reports"
}

/// A trait which private keyholders can implement to allow them to sign a
/// list of IAS verification reports with appropriate domain separators.
pub trait Signer {
    /// The signature output type
    type Sig: Signature;
    /// A printable error type
    type Error: Display;

    /// Sign a list of IAS verification report.
    fn sign_reports(&self, reports: &[VerificationReport]) -> Result<Self::Sig, Self::Error>;
}

/// A trait which public keys can implement to allow them to verify a signature
/// over a list of IAS verification reports with appropriate domain separators.
pub trait Verifier {
    /// The signature output type
    type Sig: Signature;
    /// The printable error type
    type Error: Display;

    /// Verify the provided signature is valid for the object over the reports.
    fn verify_reports(
        &self,
        reports: &[VerificationReport],
        sig: &Self::Sig,
    ) -> Result<(), Self::Error>;
}
