//! MobileCoin BIP-39 Key Derivation

#![no_std]
#![warn(missing_docs)]
#![deny(unsafe_code)]

extern crate alloc;

use alloc::borrow::ToOwned;
// use bip39::{Mnemonic, Seed};
use core::fmt::Display;
use curve25519_dalek::scalar::Scalar;
use hkdf::Hkdf;
use mc_account_keys::{AccountKey, Result as AccountKeyResult};
use mc_crypto_keys::RistrettoPrivate;
use sha2::Sha512;
use zeroize::Zeroize;

/// A key derived using SLIP-0010 key derivation
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct Slip10Key([u8; 32]);

impl AsRef<[u8]> for Slip10Key {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}

/// Create the view and spend private keys, and return them in reverse order,
/// e.g. `(spend, view)`, to match `AccountKey::new()`
impl Into<(RistrettoPrivate, RistrettoPrivate)> for Slip10Key {
    fn into(self) -> (RistrettoPrivate, RistrettoPrivate) {
        let kdf = Hkdf::<Sha512>::new(None, self.as_ref());
        let mut okm = [0u8; 64];

        kdf.expand(b"mobilecoin-ristretto255-view", &mut okm)
            .expect("Invalid okm length when creating private view key");
        let view_scalar = Scalar::from_bytes_mod_order_wide(&okm);
        let view_private_key = RistrettoPrivate::from(view_scalar);

        kdf.expand(b"mobilecoin-ristretto255-spend", &mut okm)
            .expect("Invalid okm length when creating private spend key");
        let spend_scalar = Scalar::from_bytes_mod_order_wide(&okm);
        let spend_private_key = RistrettoPrivate::from(spend_scalar);

        (spend_private_key, view_private_key)
    }
}

impl From<[u8; 32]> for Slip10Key {
    fn from(src: [u8; 32]) -> Self {
        Self(src)
    }
}

/// A common interface for constructing a Slip10Key at a particular path from
/// existing entropy
pub trait Slip10KeyGenerator {
    /// The type of error, if any, to be returned if it occurs
    type Error: Display;

    /// Derive a slip10 key for the given path from the current object
    fn derive_slip10_key(self, path: &[u32]) -> Result<Slip10Key, Self::Error>;
}

// TODO: Slip10KeyGenerator for Mnemonic
//
// This lets us get to
// Mnemonic::from_phrases().derive_slip10_key(path).try_into_account_key(...)

// TODO: Slip10KeyGenerator for Seed
//
// This is a tougher call, since there doesn't appear to be any way to ensure
// the password is blank for this---and From<[u8; 32]> may be all we need for HW
// wallets...

impl Slip10Key {
    /// Try to construct a new AccountKey from an existing Slip10Key.
    // In the future, AccountKey::new_with_fog will be fallible.
    pub fn try_into_account_key(
        self,
        fog_report_url: &str,
        fog_report_id: &str,
        fog_authority_spki: &[u8],
    ) -> AccountKeyResult<AccountKey> {
        let (spend_private_key, view_private_key) = self.into();
        Ok(AccountKey::new_with_fog(
            &spend_private_key,
            &view_private_key,
            fog_report_url,
            fog_report_id.to_owned(),
            fog_authority_spki,
        ))
    }
}

impl Into<AccountKey> for Slip10Key {
    fn into(self) -> AccountKey {
        let (spend_private_key, view_private_key) = self.into();
        AccountKey::new(&spend_private_key, &view_private_key)
    }
}
