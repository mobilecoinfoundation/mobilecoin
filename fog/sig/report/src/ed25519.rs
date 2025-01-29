// Copyright (c) 2018-2022 The MobileCoin Foundation

//! This module provides implementations of the report signer for the Ed25519
//! signature scheme.

use crate::{Signer, Verifier};
use mc_crypto_digestible_signature::{DigestibleSigner, DigestibleVerifier};
use mc_crypto_keys::{Ed25519Pair, Ed25519Public, Ed25519Signature, SignatureError};
use mc_fog_report_types::Report;

impl Signer for Ed25519Pair {
    type Sig = Ed25519Signature;
    type Error = SignatureError;

    fn sign_reports(&self, reports: &[Report]) -> Result<Self::Sig, Self::Error> {
        self.try_sign_digestible(super::context(), &reports)
    }
}

impl Verifier for Ed25519Public {
    type Sig = Ed25519Signature;
    type Error = SignatureError;

    fn verify_reports(&self, reports: &[Report], sig: &Self::Sig) -> Result<(), Self::Error> {
        self.verify_digestible(super::context(), &reports, sig)
    }
}

/// Unit tests.
///
/// We assume signing, context changes, mutability, etc. is tested at lower
/// level, and just do a round-trip.
#[cfg(test)]
mod test {
    extern crate alloc;

    use super::*;
    use alloc::borrow::ToOwned;
    use mc_attest_verifier_types::prost;
    use mc_util_from_random::FromRandom;
    use rand_core::SeedableRng;
    use rand_hc::Hc128Rng;

    #[test]
    fn roundtrip() {
        let report_data = prost::EnclaveReportDataContents {
            nonce: b"nonce".to_vec(),
            key: b"key".to_vec(),
            custom_identity: b"custom_identity".to_vec(),
        };
        let reports = [Report {
            fog_report_id: "id".to_owned(),
            attestation_evidence: Some(
                prost::DcapEvidence {
                    quote: None,
                    collateral: None,
                    report_data: Some(report_data),
                }
                .into(),
            ),
            pubkey_expiry: 0,
        }];

        let mut csprng = Hc128Rng::seed_from_u64(0);
        let pair = Ed25519Pair::from_random(&mut csprng);
        let sig = pair
            .sign_reports(&reports)
            .expect("Could not sign verification reports");

        let public = pair.public_key();
        public
            .verify_reports(&reports, &sig)
            .expect("Could not verify signature over reports");
    }
}
