//! This module contains the implementation of the fog authority signing and
//! verification services for the AccountKey/PublicAddress types.
//!
//! This is done because we specifically use the view_private and view_public
//! addresses.
//
// Note: This may be able to go away when we have ViewPublic/ViewPrivate.

use crate::authority::{
    Error as AuthorityError, Signer as AuthoritySigner, Verifier as AuthorityVerifier,
};
use mc_account_keys::{AccountKey, PublicAddress};
use mc_crypto_keys::RistrettoSignature;

impl AuthorityVerifier for PublicAddress {
    type Sig = RistrettoSignature;
    type Error = String;

    fn verify_authority_sig_bytes(
        &self,
        spki_bytes: &[u8],
        sig: &Self::Sig,
    ) -> Result<(), AuthorityError<String>> {
        self.view_public_key()
            .verify_authority_sig_bytes(spki_bytes, sig)
    }
}

impl AuthoritySigner for AccountKey {
    type Sig = RistrettoSignature;
    type Error = String;

    fn sign_authority_bytes(
        &self,
        spki_bytes: &[u8],
    ) -> Result<Self::Sig, AuthorityError<Self::Error>> {
        self.view_private_key().sign_authority_bytes(spki_bytes)
    }
}
