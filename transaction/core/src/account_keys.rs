// Copyright (c) 2018-2020 MobileCoin Inc.

//! MobileCoin account keys.
//!
//! MobileCoin accounts give users fine-grained controls for sharing their
//! address with senders and third-party services. Each account is defined
//! by a pair of private keys (a,b) that are used for identifying owned
//! outputs and spending them, respectively. Instead of sharing the public
//! keys (A,B) directly with senders, users generate and share "subaddresses"
//! (C_i, D_i) that are derived from the private keys (a,b) and an index i.
//! We refer to (C_0, D_0)* as the "default subaddress" for account (a,b).

#![allow(non_snake_case)]

use crate::{domain_separators::SUBADDRESS_DOMAIN_TAG, view_key::ViewKey};

use core::{
    cmp::Ordering,
    fmt,
    hash::{Hash, Hasher},
};

use alloc::{
    string::{String, ToString},
    vec::Vec,
};

use mc_crypto_digestible::Digestible;
use mc_crypto_keys::{RistrettoPrivate, RistrettoPublic};
use mc_util_from_random::FromRandom;

use blake2::{Blake2b, Digest};
use curve25519_dalek::scalar::Scalar;
use prost::Message;
use rand_core::{CryptoRng, RngCore};

/// An account's "default address" is its zero^th subaddress.
pub const DEFAULT_SUBADDRESS_INDEX: u64 = 0;

/// A MobileCoin user's public subaddress.
#[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Message, Clone, Digestible)]
pub struct PublicAddress {
    /// The user's public subaddress view key 'C'.
    #[prost(message, required, tag = "1")]
    view_public_key: RistrettoPublic,

    /// The user's public subaddress spend key `D`.
    #[prost(message, required, tag = "2")]
    spend_public_key: RistrettoPublic,

    /// This is the URL to talk to the fog report server, if the user has a fog service
    /// Empty if no fog for this public address
    /// Should be parseable as mc_util_uri::FogUri.
    #[prost(string, tag = "3")]
    fog_report_url: String,

    /// The fog report server potentially returns multiple reports when queried.
    /// This value is the key that indicates which of the reports to use.
    /// Empty if no fog for this public address.
    #[prost(string, tag = "4")]
    fog_report_key: String,

    /// A signature with the user's spend_private_key over the fog authority key fingerprint.
    /// Empty if no fog for this public address
    #[prost(bytes, tag = "5")]
    fog_authority_sig: Vec<u8>,
}

impl fmt::Display for PublicAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "MOB")?;
        for byte in self
            .spend_public_key
            .to_bytes()
            .iter()
            .chain(self.view_public_key().to_bytes().iter())
        {
            write!(f, "{:02X}", byte)?;
        }
        if !self.fog_report_url.is_empty() {
            write!(f, ":'{}'", self.fog_report_url)?;
        }
        if !self.fog_report_key.is_empty() {
            write!(f, ":{}", self.fog_report_key)?;
        }
        Ok(())
    }
}

impl PublicAddress {
    /// Create a new public address from CryptoNote key pair (with no account service)
    ///
    /// # Arguments
    /// `spend_public_key` - The user's public subaddress spend key `D`,
    /// `view_public_key` - The user's public subaddress view key  `C`,
    #[inline]
    pub fn new(spend_public_key: &RistrettoPublic, view_public_key: &RistrettoPublic) -> Self {
        Self {
            view_public_key: *view_public_key,
            spend_public_key: *spend_public_key,
            fog_report_url: Default::default(),
            fog_authority_sig: Default::default(),
            fog_report_key: Default::default(),
        }
    }

    /// Create a new public address with specific public keys and account service name and authority sig.
    ///
    /// # Arguments
    /// `spend_public_key` - The user's public subaddress spend key `D`,
    /// `view_public_key` - The user's public subaddress view key `C`,
    /// `fog_report_url` - User's fog report server url
    /// `fog_report_key` - The key labelling the report to use, from among the several reports which might be served by the fog report server.
    /// `fog_authority_sig` - A signature over the fog authority fingerprint using the subaddress_spend_private_key
    #[inline]
    pub fn new_with_fog(
        spend_public_key: &RistrettoPublic,
        view_public_key: &RistrettoPublic,
        fog_report_url: impl ToString,
        fog_report_key: String,
        fog_authority_sig: Vec<u8>,
    ) -> Self {
        Self {
            view_public_key: *view_public_key,
            spend_public_key: *spend_public_key,
            fog_report_url: fog_report_url.to_string(),
            fog_report_key,
            fog_authority_sig,
        }
    }

    /// Get the public subaddress view key.
    pub fn view_public_key(&self) -> &RistrettoPublic {
        &self.view_public_key
    }

    /// Get the public subaddress spend key.
    pub fn spend_public_key(&self) -> &RistrettoPublic {
        &self.spend_public_key
    }

    /// Get the optional fog report url (if it exists / is not empty).
    pub fn fog_report_url(&self) -> Option<&str> {
        if self.fog_report_url.is_empty() {
            None
        } else {
            Some(&self.fog_report_url)
        }
    }

    /// Get the optional fog authority sig (if it exists / is not empty).
    pub fn fog_authority_sig(&self) -> Option<&[u8]> {
        if self.fog_authority_sig.is_empty() {
            None
        } else {
            Some(&self.fog_authority_sig)
        }
    }

    /// Get the optional fog report key (if it exists / is not empty).
    pub fn fog_report_key(&self) -> Option<&str> {
        if self.fog_report_key.is_empty() {
            None
        } else {
            Some(&self.fog_report_key)
        }
    }
}

/// Complete AccountKey, containing the pair of secret keys, which can be used
/// for spending, and optionally some fog-related info,
/// can be used for spending. This should only ever be present in client code.
#[derive(Clone, Message)]
pub struct AccountKey {
    /// Private key 'a' used for view-key matching.
    #[prost(message, required, tag = "1")]
    view_private_key: RistrettoPrivate,

    /// Private key `b` used for spending.
    #[prost(message, required, tag = "2")]
    spend_private_key: RistrettoPrivate,

    /// Fog Report server url (if user has Fog service), empty string otherwise
    #[prost(string, tag = "3")]
    fog_report_url: String,

    /// Fog Report Key (if user has Fog service), empty otherwise
    /// The key labelling the report to use, from among the several reports
    /// which might be served by the fog report server.
    #[prost(string, tag = "4")]
    fog_report_key: String,

    /// Fog Authority Key Fingerprint (if user has Fog service), empty otherwise
    #[prost(bytes, tag = "5")]
    fog_authority_key_fingerprint: Vec<u8>,
}

// Note: Hash, Ord is implemented in terms of default_subaddress() because
// we don't want comparisons to leak private key details over side-channels.
impl Hash for AccountKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.default_subaddress().hash(state)
    }
}

impl Eq for AccountKey {}

impl PartialEq for AccountKey {
    fn eq(&self, other: &Self) -> bool {
        self.default_subaddress().eq(&other.default_subaddress())
    }
}

impl PartialOrd for AccountKey {
    fn partial_cmp(&self, other: &AccountKey) -> Option<Ordering> {
        self.default_subaddress()
            .partial_cmp(&other.default_subaddress())
    }
}

impl Ord for AccountKey {
    fn cmp(&self, other: &AccountKey) -> Ordering {
        self.default_subaddress().cmp(&other.default_subaddress())
    }
}

impl AccountKey {
    /// A user's AccountKey, without a fog service.
    ///
    /// # Arguments
    /// * `spend_private_key` - The user's private spend key `b`.
    /// * `view_private_key` - The user's private view key `a`.
    #[inline]
    pub fn new(spend_private_key: &RistrettoPrivate, view_private_key: &RistrettoPrivate) -> Self {
        Self {
            spend_private_key: *spend_private_key,
            view_private_key: *view_private_key,
            fog_report_url: Default::default(),
            fog_report_key: Default::default(),
            fog_authority_key_fingerprint: Default::default(),
        }
    }

    /// A user's AccountKey, with an fog service.
    ///
    /// # Arguments
    /// * `spend_private_key` - The user's private spend key `b`.
    /// * `view_private_key` - The user's private view key `a`.
    /// * `fog_report_url` - Url of fog report service
    /// * `fog_report_key` - The key labelling the report to use, from among the
    ///                     several reports which might be served by the fog report server.
    /// * `fog_authority` - The fingerprint of the public key of the fog authority,
    ///                     which is signed by the user for the public address.
    pub fn new_with_fog(
        spend_private_key: &RistrettoPrivate,
        view_private_key: &RistrettoPrivate,
        fog_report_url: impl ToString,
        fog_report_key: String,
        fog_authority: impl AsRef<[u8]>,
    ) -> Self {
        Self {
            spend_private_key: *spend_private_key,
            view_private_key: *view_private_key,
            fog_report_url: fog_report_url.to_string(),
            fog_report_key,
            fog_authority_key_fingerprint: fog_authority.as_ref().to_vec(),
        }
    }

    /// Get the view private key.
    pub fn view_private_key(&self) -> &RistrettoPrivate {
        &self.view_private_key
    }

    /// Get the spend private key.
    pub fn spend_private_key(&self) -> &RistrettoPrivate {
        &self.spend_private_key
    }

    /// Access the fog url (if it exists).
    pub fn fog_report_url(&self) -> Option<&str> {
        if self.fog_report_url.is_empty() {
            None
        } else {
            Some(&self.fog_report_url)
        }
    }

    /// Access the fog authority key fingerprint (if it exists).
    pub fn fog_authority_key_fingerprint(&self) -> Option<&[u8]> {
        if self.fog_authority_key_fingerprint.is_empty() {
            None
        } else {
            Some(&self.fog_authority_key_fingerprint)
        }
    }

    /// Access the fog report key (if it exists).
    pub fn fog_report_key(&self) -> Option<&str> {
        if self.fog_report_key.is_empty() {
            None
        } else {
            Some(&self.fog_report_key)
        }
    }

    /// Returns the default subaddress view key (a, D).
    pub fn view_key(&self) -> ViewKey {
        ViewKey {
            spend_public_key: self.default_subaddress().spend_public_key,
            view_private_key: self.view_private_key,
        }
    }

    /// Create an account key with random secret keys, and no fog service
    /// (intended for tests).
    pub fn random<T: RngCore + CryptoRng>(rng: &mut T) -> Self {
        Self::new(
            &RistrettoPrivate::from_random(rng),
            &RistrettoPrivate::from_random(rng),
        )
    }

    /// Create an account key with random secret keys, and the fog service
    /// url "fog://example.com"
    /// (intended for tests).
    pub fn random_with_fog<T: RngCore + CryptoRng>(rng: &mut T) -> Self {
        Self::new_with_fog(
            &RistrettoPrivate::from_random(rng),
            &RistrettoPrivate::from_random(rng),
            "fog://example.com".to_string(),
            Default::default(),
            <Vec<u8>>::default(),
        )
    }

    /// Get the account's default subaddress.
    #[inline]
    pub fn default_subaddress(&self) -> PublicAddress {
        self.subaddress(DEFAULT_SUBADDRESS_INDEX)
    }

    /// Get the account's i^th subaddress.
    pub fn subaddress(&self, index: u64) -> PublicAddress {
        let subaddress_view_public = {
            let subaddress_view_private = self.subaddress_view_private(index);
            RistrettoPublic::from(&subaddress_view_private)
        };

        let subaddress_spend_public = {
            let subaddress_spend_private = self.subaddress_spend_private(index);
            RistrettoPublic::from(&subaddress_spend_private)
        };

        let mut result = PublicAddress {
            view_public_key: subaddress_view_public,
            spend_public_key: subaddress_spend_public,
            fog_report_url: self.fog_report_url.clone(),
            fog_report_key: self.fog_report_key.clone(),
            fog_authority_sig: Default::default(),
        };

        // Compute fog_authority_sig as a signature over self.fog_authority_key_fingerprint
        if !self.fog_report_url.is_empty() {
            // FIXME: FOG-106 fog_authority_sig should be a Schnorrkel sig using subaddress_view_private
            result.fog_authority_sig.extend(&[9u8, 9u8, 9u8, 9u8]);
        }

        result
    }

    /// The private spend key for the default subaddress.
    pub fn default_subaddress_spend_private(&self) -> RistrettoPrivate {
        self.subaddress_spend_private(DEFAULT_SUBADDRESS_INDEX)
    }

    /// The private spend key for the i^th subaddress.
    pub fn subaddress_spend_private(&self, index: u64) -> RistrettoPrivate {
        let a: &Scalar = self.view_private_key.as_ref();

        // `Hs(a || n)`
        let Hs: Scalar = {
            let n = Scalar::from(index);
            let mut digest = Blake2b::new();
            digest.input(SUBADDRESS_DOMAIN_TAG);
            digest.input(a.as_bytes());
            digest.input(n.as_bytes());
            Scalar::from_hash::<Blake2b>(digest)
        };

        let b: &Scalar = self.spend_private_key.as_ref();
        RistrettoPrivate::from(Hs + b)
    }

    /// The private view key for the default subaddress.
    pub fn default_subaddress_view_private(&self) -> RistrettoPrivate {
        self.subaddress_view_private(DEFAULT_SUBADDRESS_INDEX)
    }

    /// The private view key for the i^th subaddress.
    pub fn subaddress_view_private(&self, index: u64) -> RistrettoPrivate {
        let a: &Scalar = self.view_private_key.as_ref();

        // `Hs(a || n)`
        let Hs: Scalar = {
            let n = Scalar::from(index);
            let mut digest = Blake2b::new();
            digest.input(SUBADDRESS_DOMAIN_TAG);
            digest.input(a.as_bytes());
            digest.input(n.as_bytes());
            Scalar::from_hash::<Blake2b>(digest)
        };

        let b: &Scalar = self.spend_private_key.as_ref();
        let c = a * (Hs + b);
        RistrettoPrivate::from(c)
    }
}

#[cfg(test)]
mod account_key_tests {
    use super::*;
    use rand::prelude::StdRng;
    use rand_core::SeedableRng;

    #[test]
    // Deserializing should recover a serialized a PublicAddress.
    fn mc_util_serial_prost_roundtrip_public_address() {
        mc_util_test_helper::run_with_several_seeds(|mut rng| {
            {
                let acct = AccountKey::random(&mut rng);
                let ser = mc_util_serial::encode(&acct.default_subaddress());
                let result: PublicAddress = mc_util_serial::decode(&ser).unwrap();
                assert_eq!(acct.default_subaddress(), result);
            }
            {
                let acct = AccountKey::random_with_fog(&mut rng);
                let ser = mc_util_serial::encode(&acct.default_subaddress());
                let result: PublicAddress = mc_util_serial::decode(&ser).unwrap();
                assert_eq!(acct.default_subaddress(), result);
            }
        });
    }

    #[test]
    // Subaddress private keys should agree with subaddress public keys.
    fn test_subadress_private_keys_agree_with_subaddress_public_keys() {
        let mut rng: StdRng = SeedableRng::from_seed([91u8; 32]);
        let view_private = RistrettoPrivate::from_random(&mut rng);
        let spend_private = RistrettoPrivate::from_random(&mut rng);

        let account_key = AccountKey::new(&spend_private, &view_private);

        let index = rng.next_u64();
        let subaddress = account_key.subaddress(index);

        let subaddress_view_private = account_key.subaddress_view_private(index);
        let subaddress_spend_private = account_key.subaddress_spend_private(index);

        let expected_subaddress_view_public = RistrettoPublic::from(&subaddress_view_private);
        let expected_subaddress_spend_public = RistrettoPublic::from(&subaddress_spend_private);

        assert_eq!(expected_subaddress_view_public, subaddress.view_public_key);
        assert_eq!(
            expected_subaddress_spend_public,
            subaddress.spend_public_key
        );
    }
}
