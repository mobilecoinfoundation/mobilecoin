// Copyright 2018-2021 The MobileCoin Foundation

//! This module contains the implementation of the fog authority signing and
//! verification services for ristretto keys.
//
// TODO: If/when we have a ViewPublic/ViewPrivate types, this should be
//       implemented on those types, instead of all ristretto public keys.

use crate::authority::{AuthorityError, Signer as AuthoritySigner, Verifier as AuthorityVerifier};
use mc_crypto_keys::{RistrettoPrivate, RistrettoPublic, RistrettoSignature};

impl AuthoritySigner for RistrettoPrivate {
    type Sig = RistrettoSignature;
    type Error = String;

    fn sign_authority_bytes(&self, spki_bytes: &[u8]) -> Result<Self::Sig, AuthorityError<String>> {
        Ok(self.sign_schnorrkel(super::context(), spki_bytes))
    }
}

impl AuthorityVerifier for RistrettoPublic {
    type Sig = RistrettoSignature;
    type Error = String;

    fn verify_authority_sig_bytes(
        &self,
        spki_bytes: &[u8],
        sig: &Self::Sig,
    ) -> Result<(), AuthorityError<String>> {
        self.verify_schnorrkel(super::context(), spki_bytes, sig)
            .map_err(|e| AuthorityError::Algorithm(format!("{:#}", e)))
    }
}
