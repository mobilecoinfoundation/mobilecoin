// Copyright 2018-2021 The MobileCoin Foundation

//! This module contains the implementation of the fog authority signing and
//! verification services for ristretto keys.
//
// TODO: If/when we have a ViewPublic/ViewPrivate types, this should be
//       implemented on those types, instead of all ristretto public keys.

use crate::authority::{Error, Signer, Verifier};
use mc_crypto_keys::{RistrettoPrivate, RistrettoPublic, RistrettoSignature};

impl Signer for RistrettoPrivate {
    type Sig = RistrettoSignature;
    type Error = String;

    fn sign_authority_bytes(&self, spki_bytes: &[u8]) -> Result<Self::Sig, Error<String>> {
        Ok(self.sign_schnorrkel(super::context(), spki_bytes))
    }
}

impl Verifier for RistrettoPublic {
    type Sig = RistrettoSignature;
    type Error = String;

    fn verify_authority_sig_bytes(
        &self,
        spki_bytes: &[u8],
        sig: &Self::Sig,
    ) -> Result<(), Error<String>> {
        self.verify_schnorrkel(super::context(), spki_bytes, sig)
            .map_err(|e| Error::Algorithm(format!("{:#}", e)))
    }
}

#[cfg(test)]
mod test {
    //! Unit tests.
    //!
    //! We assume signing, context changes, mutability, etc. is tested at lower
    //! level, and just do a round-trip.

    use super::*;
    use mc_util_from_random::FromRandom;
    use rand_core::SeedableRng;
    use rand_hc::Hc128Rng;

    const TEST_MSG: &[u8] = b"The era of \"electronic mail\" may soon be upon us;";

    #[test]
    fn roundtrip() {
        let mut csprng = Hc128Rng::seed_from_u64(0);
        let privkey = RistrettoPrivate::from_random(&mut csprng);

        let sig = privkey
            .sign_authority_bytes(TEST_MSG)
            .expect("Could not sign test message");
        let pubkey = RistrettoPublic::from(&privkey);
        pubkey
            .verify_authority_sig_bytes(TEST_MSG, &sig)
            .expect("Could not verify signature");
    }
}
