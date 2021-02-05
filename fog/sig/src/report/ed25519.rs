// Copyright 2018-2021 The MobileCoin Foundation

//! This module provides implementations of the report signer for the Ed25519
//! signature scheme.

use crate::report::{Signer, Verifier};
use mc_attest_core::VerificationReport;
use mc_crypto_digestible_signature::{DigestibleSigner, DigestibleVerifier};
use mc_crypto_keys::{Ed25519Pair, Ed25519Public, Ed25519Signature, Ed25519SignatureError};

impl Signer for Ed25519Pair {
    type Sig = Ed25519Signature;
    type Error = Ed25519SignatureError;

    fn sign_reports(&self, reports: &[VerificationReport]) -> Result<Self::Sig, Self::Error> {
        self.try_sign_digestible(super::context(), &reports)
    }
}

impl Verifier for Ed25519Public {
    type Sig = Ed25519Signature;
    type Error = Ed25519SignatureError;

    fn verify_reports(
        &self,
        reports: &[VerificationReport],
        sig: &Self::Sig,
    ) -> Result<(), Self::Error> {
        self.verify_digestible(super::context(), &reports, sig)
    }
}
