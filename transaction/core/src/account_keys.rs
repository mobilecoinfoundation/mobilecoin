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

use crate::view_key::ViewKey;
use alloc::string::{String, ToString};
use blake2::{Blake2b, Digest};
use core::{
    cmp::Ordering,
    fmt,
    hash::{Hash, Hasher},
};
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT, ristretto::RistrettoPoint, scalar::Scalar,
};
use digestible::Digestible;
use keys::{RistrettoPrivate, RistrettoPublic};
use mc_util_from_random::FromRandom;
use mcserial::{Message, ReprBytes32};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

const G: RistrettoPoint = RISTRETTO_BASEPOINT_POINT;

/// An account's "default address" is its zero^th subaddress.
pub const DEFAULT_SUBADDRESS_INDEX: u64 = 0;

/// A MobileCoin user's public address.
#[derive(
    PartialEq, Eq, PartialOrd, Ord, Hash, Default, Debug, Serialize, Deserialize, Clone, Digestible,
)]
pub struct PublicAddress {
    /// The user's public key `A`.
    view_public_key: RistrettoPublic,

    /// The user's public key `B`.
    spend_public_key: RistrettoPublic,

    /// Fog Url, if the user has a fog service
    fog_url: Option<String>,
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
        if let Some(ref name) = self.fog_url {
            write!(f, ":'{}'", name)?;
        }
        Ok(())
    }
}

impl PublicAddress {
    /// Create a new public address from CryptoNote key pair (with no account service)
    ///
    /// # Arguments
    /// `spend_public_key` - The user's public key `B`,
    /// `view_public_key` - The user's public key `A`,
    #[inline]
    pub fn new(spend_public_key: &RistrettoPublic, view_public_key: &RistrettoPublic) -> Self {
        Self {
            view_public_key: *view_public_key,
            spend_public_key: *spend_public_key,
            fog_url: None,
        }
    }

    /// Create a new public address from specific secret keys and account service name.
    ///
    /// # Arguments
    /// `spend_public_key` - The user's public key `B`,
    /// `view_public_key` - The user's public key `A`,
    /// `fog_url` - User's fog url
    #[inline]
    pub fn new_with_fog(
        spend_public_key: &RistrettoPublic,
        view_public_key: &RistrettoPublic,
        fog_url: impl ToString,
    ) -> Self {
        Self {
            view_public_key: *view_public_key,
            spend_public_key: *spend_public_key,
            fog_url: Some(fog_url.to_string()),
        }
    }

    /// Get the view public key.
    pub fn view_public_key(&self) -> &RistrettoPublic {
        &self.view_public_key
    }

    /// Get the spend public key
    pub fn spend_public_key(&self) -> &RistrettoPublic {
        &self.spend_public_key
    }

    /// Get the optional fog url.
    pub fn fog_url(&self) -> Option<&str> {
        self.fog_url.as_deref()
    }
}

/// Complete AccountKey, containing the pair of secret keys, which can be used
/// for spending, and optionally some fog-related info,
/// can be used for spending. This should only ever be present in client code.
#[derive(Clone, Serialize, Deserialize, Message)]
pub struct AccountKey {
    /// Private key 'a' used for view-key matching.
    #[prost(message, required, tag = "1")]
    view_private_key: RistrettoPrivate,

    /// Private key `b` used for spending.
    #[prost(message, required, tag = "2")]
    spend_private_key: RistrettoPrivate,

    /// Fog URL (if user has Fog service)
    #[prost(string, tag = "3")]
    fog_url: String,
}

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
    /// * `spend_private_key` - The user's private key `b`.
    /// * `view_private_key` - The user's private key `a`.
    #[inline]
    pub fn new(spend_private_key: &RistrettoPrivate, view_private_key: &RistrettoPrivate) -> Self {
        Self {
            spend_private_key: *spend_private_key,
            view_private_key: *view_private_key,
            fog_url: "".to_string(),
        }
    }

    /// A user's AccountKey, with an fog service.
    ///
    /// # Arguments
    /// * `spend_private_key` - The user's private key `b`.
    /// * `view_private_key` - The user's private key `a`.
    /// * `fog_url` - Url of fog service
    pub fn new_with_fog(
        spend_private_key: &RistrettoPrivate,
        view_private_key: &RistrettoPrivate,
        fog_url: impl ToString,
    ) -> Self {
        Self {
            spend_private_key: *spend_private_key,
            view_private_key: *view_private_key,
            fog_url: fog_url.to_string(),
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

    /// Access the acct server name (if it exists)
    #[inline]
    pub fn fog_url(&self) -> Option<&str> {
        if self.fog_url.is_empty() {
            None
        } else {
            Some(&self.fog_url)
        }
    }

    /// Obtain ViewKey struct (a, D) from AccountKey
    #[inline]
    pub fn view_key(&self) -> ViewKey {
        ViewKey {
            spend_public_key: self.default_subaddress().spend_public_key,
            view_private_key: self.view_private_key,
        }
    }

    /// Create an account key with random secret keys, and no fog service
    /// (intended for tests)
    #[inline]
    pub fn random<T: RngCore + CryptoRng>(rng: &mut T) -> Self {
        Self::new(
            &RistrettoPrivate::from_random(rng),
            &RistrettoPrivate::from_random(rng),
        )
    }

    /// Create an account key with random secret keys, and the fog service
    /// FQDN "example.com"
    /// (intended for tests)
    #[inline]
    pub fn random_with_fog<T: RngCore + CryptoRng>(rng: &mut T) -> Self {
        Self::new_with_fog(
            &RistrettoPrivate::from_random(rng),
            &RistrettoPrivate::from_random(rng),
            "example.com".to_string(),
        )
    }

    /// Compute the default subaddress from private AccountKey data
    #[inline]
    pub fn default_subaddress(&self) -> PublicAddress {
        self.subaddress(DEFAULT_SUBADDRESS_INDEX)
    }

    /// Compute a subaddress from private AccountKey data
    pub fn subaddress(&self, index: u64) -> PublicAddress {
        let a: &Scalar = self.view_private_key.as_ref();

        // `Hs(a || n)`
        let Hs: Scalar = {
            let n = Scalar::from(index);
            let mut digest = Blake2b::new();
            digest.input(a.as_bytes());
            digest.input(n.as_bytes());
            Scalar::from_hash::<Blake2b>(digest)
        };

        let M = Hs * G;
        let B = RistrettoPublic::from(&self.spend_private_key);
        let D = M + B.as_ref();
        let C = a * D;

        match self.fog_url() {
            None => PublicAddress::new(&RistrettoPublic::from(D), &RistrettoPublic::from(C)),
            Some(acct_data) => PublicAddress::new_with_fog(
                &RistrettoPublic::from(D),
                &RistrettoPublic::from(C),
                acct_data,
            ),
        }
    }

    /// Compute a subaddress spend key `d` from private AccountKey data
    pub fn default_subaddress_spend_key(&self) -> RistrettoPrivate {
        self.subaddress_spend_key(DEFAULT_SUBADDRESS_INDEX)
    }

    /// Compute a subaddress spend key `d` from private AccountKey data
    pub fn subaddress_spend_key(&self, index: u64) -> RistrettoPrivate {
        let a: &Scalar = self.view_private_key.as_ref();

        // `Hs(a || n)`
        let Hs: Scalar = {
            let n = Scalar::from(index);
            let mut digest = Blake2b::new();
            digest.input(a.as_bytes());
            digest.input(n.as_bytes());
            Scalar::from_hash::<Blake2b>(digest)
        };

        let b: &Scalar = self.spend_private_key.as_ref();
        RistrettoPrivate::from(Hs + b)
    }

    /// Compute a subaddress view key `c` from private AccountKey data
    pub fn default_subaddress_view_key(&self) -> RistrettoPrivate {
        self.subaddress_view_key(DEFAULT_SUBADDRESS_INDEX)
    }

    /// Compute a subaddress view key `c` from private AccountKey data
    pub fn subaddress_view_key(&self, index: u64) -> RistrettoPrivate {
        let a: &Scalar = self.view_private_key.as_ref();

        // `Hs(a || n)`
        let Hs: Scalar = {
            let n = Scalar::from(index);
            let mut digest = Blake2b::new();
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
mod testing {
    use super::*;

    #[test]
    //Deserializing should recover a serialized a PublicAddress.
    fn mcserial_roundtrip_public_address() {
        test_helper::run_with_several_seeds(|mut rng| {
            {
                let acct = AccountKey::random(&mut rng);
                let ser = mcserial::serialize(&acct.default_subaddress()).unwrap();
                let result: PublicAddress = mcserial::deserialize(&ser).unwrap();
                assert_eq!(acct.default_subaddress(), result);
            }
            {
                let acct = AccountKey::random_with_fog(&mut rng);
                let ser = mcserial::serialize(&acct.default_subaddress()).unwrap();
                let result: PublicAddress = mcserial::deserialize(&ser).unwrap();
                assert_eq!(acct.default_subaddress(), result);
            }
        });
    }
}
