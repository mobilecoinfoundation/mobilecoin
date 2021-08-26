// Copyright 2018-2021 The MobileCoin Foundation

//! This module provides implementations of the report signer for the Ed25519
//! signature scheme.

use crate::{Signer, Verifier};
use mc_crypto_digestible_signature::{DigestibleSigner, DigestibleVerifier};
use mc_crypto_keys::{Ed25519Pair, Ed25519Public, Ed25519Signature, Ed25519SignatureError};
use mc_fog_report_types::Report;

impl Signer for Ed25519Pair {
    type Sig = Ed25519Signature;
    type Error = Ed25519SignatureError;

    fn sign_reports(&self, reports: &[Report]) -> Result<Self::Sig, Self::Error> {
        self.try_sign_digestible(super::context(), &reports)
    }
}

impl Verifier for Ed25519Public {
    type Sig = Ed25519Signature;
    type Error = Ed25519SignatureError;

    fn verify_reports(&self, reports: &[Report], sig: &Self::Sig) -> Result<(), Self::Error> {
        self.verify_digestible(super::context(), &reports, sig)
    }
}

#[cfg(test)]
mod test {
    //! Unit tests.
    //!
    //! We assume signing, context changes, mutability, etc. is tested at lower
    //! level, and just do a round-trip.

    extern crate alloc;

    use super::*;
    use alloc::{borrow::ToOwned, vec};
    use mc_attest_core::{VerificationReport, VerificationSignature};
    use mc_util_from_random::FromRandom;
    use rand_core::SeedableRng;
    use rand_hc::Hc128Rng;

    #[test]
    fn roundtrip() {
        let reports = [Report {
            fog_report_id: "id".to_owned(),
            report: VerificationReport {
                sig: VerificationSignature::default(),
                chain: vec![],
                http_body: "this should probably be a json".to_owned(),
            },
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
