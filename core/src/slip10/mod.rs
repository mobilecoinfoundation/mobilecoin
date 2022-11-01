// Copyright (c) 2018-2022 The MobileCoin Foundation

//! MobileCoin SLIP-0010 / BIP39 Based Key Derivation
//!
//! This provides utilities to handle SLIP-0010 key bytes and their relation to
//! the MobileCoin [`Account`](mc_core::Account) structure, which contains a
//! pair of Ristretto255 view/spend private scalars.
//!
//! As well as providing traits to create a Slip10Key from entropy and path,
//! along with the canonical method of converting a BIP-39
//! [`Mnemonic`](tiny_bip32::Mnemonic) with a given BIP-32 path into a
//! [`Slip10Key`](Slip10Key) usable within MobileCoin.

use curve25519_dalek::scalar::Scalar;
use hkdf::Hkdf;
use sha2::Sha512;
use zeroize::Zeroize;

use mc_crypto_keys::RistrettoPrivate;

#[cfg(feature = "bip39")]
pub use bip39::{Language, Mnemonic};

use crate::{
    account::Account,
    consts::{COINTYPE_MOBILECOIN, USAGE_BIP44},
    keys::{RootSpendPrivate, RootViewPrivate},
};

/// [Hardened derivation](https://github.com/bitcoin/bips/blob/master/bip-0043.mediawiki#Security) flag for path components
const BIP39_SECURE: u32 = 0x80000000;

/// Fetch the BIP39 path for a given account index
pub const fn wallet_path(account_index: u32) -> [u32; 3] {
    [
        BIP39_SECURE | USAGE_BIP44,
        BIP39_SECURE | COINTYPE_MOBILECOIN,
        BIP39_SECURE | (account_index & 0x7FFFFFFF),
    ]
}

/// A key derived using SLIP-0010 key derivation
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct Slip10Key([u8; 32]);

/// Access [`Slip10Key`] value as byte slice
impl AsRef<[u8]> for Slip10Key {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}

#[cfg(feature = "internals")]
impl Slip10Key {
    /// Create a SLIP-0010 key from raw Ed25519 private key value
    pub fn from_raw(raw: [u8; 32]) -> Self {
        Self(raw)
    }
}

/// Derive an [`Account`] object from slip10 derived Ed25519 private key
/// (see [`wallet_path`] for the BIP32 derivation path)
impl From<&Slip10Key> for Account {
    fn from(src: &Slip10Key) -> Self {
        Account::new(RootViewPrivate::from(src), RootSpendPrivate::from(src))
    }
}

/// Canonical derivation of a [`RootViewPrivate`] key from SLIP-0010 derived
/// Ed25519 key
impl From<&Slip10Key> for RootViewPrivate {
    fn from(src: &Slip10Key) -> Self {
        let mut okm = [0u8; 64];

        let view_kdf = Hkdf::<Sha512>::new(Some(b"mobilecoin-ristretto255-view"), src.as_ref());
        view_kdf
            .expand(b"", &mut okm)
            .expect("Invalid okm length when creating private view key");
        let view_scalar = Scalar::from_bytes_mod_order_wide(&okm);
        let view_private_key = RistrettoPrivate::from(view_scalar);

        RootViewPrivate::from(view_private_key)
    }
}

/// Canonical derivation of a [`RootSpendPrivate`] key from SLIP-0010 derived
/// Ed25519 key
impl From<&Slip10Key> for RootSpendPrivate {
    fn from(src: &Slip10Key) -> Self {
        let mut okm = [0u8; 64];

        let spend_kdf = Hkdf::<Sha512>::new(Some(b"mobilecoin-ristretto255-spend"), src.as_ref());
        spend_kdf
            .expand(b"", &mut okm)
            .expect("Invalid okm length when creating private spend key");
        let spend_scalar = Scalar::from_bytes_mod_order_wide(&okm);
        let spend_private_key = RistrettoPrivate::from(spend_scalar);

        RootSpendPrivate::from(spend_private_key)
    }
}

/// A common interface for constructing a [`Slip10Key`] for MobileCoin given an
/// account index.
pub trait Slip10KeyGenerator {
    /// Derive a MobileCoin SLIP10 key for the given account from the current
    /// object
    fn derive_slip10_key(self, account_index: u32) -> Slip10Key;
}

// This lets us get to
// let account: AccountKey =
// Mnemonic::from_phrases().derive_slip10_key(account_index).into()
#[cfg(feature = "bip39")]
impl Slip10KeyGenerator for Mnemonic {
    /// Derive a SLIP-0010 key for the specified account
    fn derive_slip10_key(self, account_index: u32) -> Slip10Key {
        // We explicitly do not support passphrases for BIP-39 mnemonics, please
        // see the MobileCoin Key Derivation design specification, v1.0.0, for
        // design rationale.
        let seed = bip39::Seed::new(&self, "");

        // This is constructing an `m/44/866/<idx>` BIP32 path for use by SLIP-0010.
        let path = wallet_path(account_index);

        // We're taking what the SLIP-0010 spec calls the "Ed25519 private key"
        // here as our `Slip10Key`. That said, we're not actually using this as
        // an Ed25519 key, just IKM for a pair of HKDF-SHA512 instances whose
        // output will be correctly transformed into the Ristretto255 keypair we
        // need.
        //
        // This will also transform any "unhardened" path components into their
        // "hardened" version.
        let key = slip10_ed25519::derive_ed25519_private_key(seed.as_bytes(), &path);

        Slip10Key(key)
    }
}

#[cfg(test)]
mod test {
    extern crate alloc;

    use alloc::{string::String, vec::Vec};
    use serde::{Deserialize, Serialize};

    use curve25519_dalek::scalar::Scalar;

    use mc_crypto_keys::{RistrettoPrivate, RistrettoPublic};

    use super::*;

    // Include test vectors as JSON strings
    const KEY_TO_RISTRETTO_STR: &str = include_str!("../../tests/slip10_key.json");
    const MNEMONIC_TO_RISTRETTO_STR: &str = include_str!("../../tests/slip10_mnemonic.json");

    // Deserialize test vectors on first access
    lazy_static::lazy_static! {
        pub static ref SLIPKEY_TO_RISTRETTO_TESTS: Vec<KeyToRistretto> = serde_json::from_str(KEY_TO_RISTRETTO_STR).unwrap();
        pub static ref MNEMONIC_TO_RISTRETTO_TESTS: Vec<MnemonicToRistretto> = serde_json::from_str(MNEMONIC_TO_RISTRETTO_STR).unwrap();
    }

    /// Slip10 key to ristretto test definitions
    #[derive(Clone, PartialEq, Serialize, Deserialize)]
    pub struct KeyToRistretto {
        slip10_hex: String,
        view_hex: String,
        spend_hex: String,
    }

    /// Slip10 mnemonic to ristretto test definitions
    #[derive(Clone, PartialEq, Serialize, Deserialize)]
    pub struct MnemonicToRistretto {
        phrase: String,
        account_index: u32,
        view_hex: String,
        spend_hex: String,
    }

    /// Test conversion of a SLIP10 seed into mobilecoin account keys
    #[test]
    fn slip10key_into_account_key() {
        for data in SLIPKEY_TO_RISTRETTO_TESTS.iter() {
            // TODO: maybe Slip10Key could implement hex::FromHex?
            let mut key_bytes = [0u8; 32];
            hex::decode_to_slice(&data.slip10_hex, &mut key_bytes[..])
                .expect("Could not decode SLIP10 test vector output");

            let slip10_key = Slip10Key(key_bytes);

            let mut expected_view_bytes = [0u8; 64];
            hex::decode_to_slice(&data.view_hex, &mut expected_view_bytes)
                .expect("Could not decode view-key bytes");
            let expected_view_scalar = Scalar::from_bytes_mod_order_wide(&expected_view_bytes);
            let expected_view_key = RistrettoPrivate::from(expected_view_scalar);

            let mut expected_spend_bytes = [0u8; 64];
            hex::decode_to_slice(&data.spend_hex, &mut expected_spend_bytes)
                .expect("Could not decode spend-key bytes");
            let expected_spend_scalar = Scalar::from_bytes_mod_order_wide(&expected_spend_bytes);
            let expected_spend_key = RistrettoPrivate::from(expected_spend_scalar);

            let account_key = Account::from(&slip10_key);

            assert_ne!(
                RistrettoPublic::from(&expected_view_key),
                RistrettoPublic::from(&expected_spend_key),
            );
            assert_eq!(account_key.view_private_key(), &expected_view_key,);
            assert_eq!(account_key.spend_private_key(), &expected_spend_key,);
        }
    }

    /// Test conversion of a BIP39 mnemonic into mobilecoin account keys
    #[test]
    #[cfg(feature = "bip39")]
    fn mnemonic_into_account_key() {
        for data in MNEMONIC_TO_RISTRETTO_TESTS.iter() {
            let mnemonic = Mnemonic::from_phrase(&data.phrase, Language::English)
                .expect("Could not read test phrase into mnemonic");
            let key = mnemonic.derive_slip10_key(data.account_index);
            let account_key = Account::from(&key);

            let mut expected_view_bytes = [0u8; 64];
            hex::decode_to_slice(&data.view_hex, &mut expected_view_bytes)
                .expect("Could not decode view-key bytes");
            let expected_view_scalar = Scalar::from_bytes_mod_order_wide(&expected_view_bytes);
            let expected_view_key = RistrettoPrivate::from(expected_view_scalar);

            let mut expected_spend_bytes = [0u8; 64];
            hex::decode_to_slice(&data.spend_hex, &mut expected_spend_bytes)
                .expect("Could not decode spend-key bytes");
            let expected_spend_scalar = Scalar::from_bytes_mod_order_wide(&expected_spend_bytes);
            let expected_spend_key = RistrettoPrivate::from(expected_spend_scalar);

            assert_ne!(
                RistrettoPublic::from(&expected_view_key),
                RistrettoPublic::from(&expected_spend_key),
            );
            assert_eq!(account_key.view_private_key(), &expected_view_key,);
            assert_eq!(account_key.spend_private_key(), &expected_spend_key,);
        }
    }
}
