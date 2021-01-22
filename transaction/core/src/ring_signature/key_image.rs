// Copyright (c) 2018-2021 The MobileCoin Foundation

use super::Error;
use crate::ring_signature::{hash_to_point, Scalar};
use core::{convert::TryFrom, fmt};
use curve25519_dalek::ristretto::CompressedRistretto;
use mc_crypto_digestible::Digestible;
use mc_crypto_keys::{RistrettoPrivate, RistrettoPublic};
use mc_util_repr_bytes::{
    derive_core_cmp_from_as_ref, derive_prost_message_from_repr_bytes,
    derive_repr_bytes_from_as_ref_and_try_from, typenum::U32, LengthMismatch,
};
use serde::{Deserialize, Serialize};

#[derive(Copy, Clone, Default, Eq, Serialize, Deserialize, Digestible)]
#[digestible(transparent)]
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

impl TryFrom<&[u8]> for KeyImage {
    type Error = Error;
    fn try_from(src: &[u8]) -> Result<Self, Error> {
        if src.len() != 32 {
            return Err(Error::from(LengthMismatch {
                expected: 32,
                found: src.len(),
            }));
        }
        Ok(Self {
            point: CompressedRistretto::from_slice(src),
        })
    }
}

derive_repr_bytes_from_as_ref_and_try_from!(KeyImage, U32);
derive_prost_message_from_repr_bytes!(KeyImage);
derive_core_cmp_from_as_ref!(KeyImage, [u8; 32]);
