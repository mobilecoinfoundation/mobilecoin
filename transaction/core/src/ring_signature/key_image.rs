// Copyright (c) 2018-2020 MobileCoin Inc.

use super::Error;
use crate::{onetime_keys::hash_to_point, ring_signature::Scalar};
use core::{convert::TryFrom, fmt};
use curve25519_dalek::ristretto::CompressedRistretto;
use mc_crypto_digestible::Digestible;
use mc_crypto_keys::{RistrettoPrivate, RistrettoPublic};
use mc_util_serial::{
    deduce_core_traits_from_public_bytes, prost_message_helper32, try_from_helper32, ReprBytes32,
};
use serde::{Deserialize, Serialize};

#[derive(Copy, Clone, Default, Eq, Serialize, Deserialize, Digestible)]
/// The "image" of a private key `x`: I = x * Hp(x * G) = x * Hp(P).
pub struct KeyImage {
    pub point: CompressedRistretto,
}

impl KeyImage {
    /// View the underlying `CompressedRistretto` as an array of bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.point.as_bytes()
    }

    /// Copies `self` into a new Vec.
    pub fn to_vec(&self) -> alloc::vec::Vec<u8> {
        self.point.as_bytes().to_vec()
    }
}

impl fmt::Debug for KeyImage {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "KeyImage({})", hex_fmt::HexFmt(self.as_bytes()))
    }
}

impl From<&RistrettoPrivate> for KeyImage {
    fn from(x: &RistrettoPrivate) -> Self {
        let P = RistrettoPublic::from(x);
        let Hp = hash_to_point(&P);
        let point = x.as_ref() * Hp;
        KeyImage {
            point: point.compress(),
        }
    }
}

// Many tests use this
impl From<u64> for KeyImage {
    fn from(n: u64) -> Self {
        let private_key = RistrettoPrivate::from(Scalar::from(n));
        Self::from(&private_key)
    }
}

impl From<[u8; 32]> for KeyImage {
    fn from(src: [u8; 32]) -> Self {
        Self {
            point: CompressedRistretto::from_slice(&src),
        }
    }
}

impl AsRef<CompressedRistretto> for KeyImage {
    fn as_ref(&self) -> &CompressedRistretto {
        &self.point
    }
}

impl AsRef<[u8; 32]> for KeyImage {
    fn as_ref(&self) -> &[u8; 32] {
        self.point.as_bytes()
    }
}

impl AsRef<[u8]> for KeyImage {
    fn as_ref(&self) -> &[u8] {
        &self.point.as_bytes()[..]
    }
}

impl ReprBytes32 for KeyImage {
    type Error = Error;
    fn to_bytes(&self) -> [u8; 32] {
        self.point.to_bytes()
    }
    fn from_bytes(src: &[u8; 32]) -> Result<Self, Error> {
        Ok(Self {
            point: CompressedRistretto::from_slice(src),
        })
    }
}

// Implements prost::Message. Requires Debug and ReprBytes32.
prost_message_helper32! { KeyImage }

// Implements try_from<&[u8;32]> and try_from<&[u8]>. Requires ReprBytes32.
try_from_helper32! { KeyImage }

// Implements Ord, PartialOrd, PartialEq, Hash. Requires AsRef<[u8;32]>.
deduce_core_traits_from_public_bytes! { KeyImage }
