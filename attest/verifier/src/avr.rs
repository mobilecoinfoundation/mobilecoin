// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Verifiers which operate on the contents of the
//! [`VerificationReportData`](::mc_attest_core::VerificationReportData)
//! structure.

use crate::{
    macros::{impl_kind_from_inner, impl_kind_from_verifier},
    quote::Kind as QuoteKind,
    Verify,
};
use alloc::vec::Vec;
use mc_attest_core::{IasNonce, VerificationReportData};
use serde::{Deserialize, Serialize};

/// An enumeration of AVR data verifiers
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum Kind {
    /// A verifier that checks the nonce of the IAS report
    Nonce(NonceVerifier),
    /// A verifier that chains to a list of quote verifiers.
    Quote(QuoteVerifier),
    /// A verifier that checks the PSE manifest hash and result
    Pse(PseVerifier),
}

impl Verify<VerificationReportData> for Kind {
    fn verify(&self, report_data: &VerificationReportData) -> bool {
        match self {
            Kind::Nonce(v) => v.verify(report_data),
            Kind::Quote(v) => v.verify(report_data),
            Kind::Pse(v) => v.verify(report_data),
        }
    }
}

impl_kind_from_inner! {
    NonceVerifier, Nonce, IasNonce;
    QuoteVerifier, Quote, Vec<QuoteKind>;
}

impl_kind_from_verifier! {
    PseVerifier, Pse, Vec<u8>;
}

/// A [`VerifyIasReportData`] implementation that will check report data for the
/// presence of the given IAS nonce.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct NonceVerifier(IasNonce);

impl Verify<VerificationReportData> for NonceVerifier {
    fn verify(&self, data: &VerificationReportData) -> bool {
        data.nonce.as_ref().map(|v| v.eq(&self.0)).unwrap_or(false)
    }
}

/// A [`VerifyIasReportData`] implementation which applies a list of verifiers
/// against the quote structure.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct QuoteVerifier(Vec<QuoteKind>);

impl Verify<VerificationReportData> for QuoteVerifier {
    fn verify(&self, data: &VerificationReportData) -> bool {
        for verifier in &self.0 {
            if !verifier.verify(&data.quote) {
                return false;
            }
        }

        true
    }
}

/// A [`VerifyIasReportData`] implementation which checks the PSE result is
/// acceptable and was made over a particular hash.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct PseVerifier(Vec<u8>);

impl Verify<VerificationReportData> for PseVerifier {
    fn verify(&self, data: &VerificationReportData) -> bool {
        if let Some(hash) = &data.pse_manifest_hash {
            if let Some(Ok(())) = &data.pse_manifest_status {
                self.0.eq(hash)
            } else {
                false
            }
        } else {
            false
        }
    }
}
