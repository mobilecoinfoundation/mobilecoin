// Copyright 2018-2021 The MobileCoin Foundation

//! This module provides traits and methods for the signing and verification
//! of report server responses.

use signature::Signature;
use std::fmt::Display;

const CONTEXT: &[u8] = b"Report server response";

trait ReportSigner {
    type Sig: Signature;
    type Error: Display;

    fn sign_reports(&self, reports: &[VerificationReport]) -> Result<Self::Sig, Self::Error>;
}

trait ReportVerifier {
    type Sig: Signature;
    type Error: Display;

    fn verify_reports(
        &self,
        reports: &[VerificationReport],
        sig: &Self::Sig,
    ) -> Result<Self::Sig, Self::Error>;
}
