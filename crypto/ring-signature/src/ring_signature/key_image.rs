// Copyright (c) 2018-2022 The MobileCoin Foundation

use super::{hash_to_point, Error, Scalar};
use mc_crypto_dalek::curve25519::ristretto::CompressedRistretto;
use mc_crypto_digestible::Digestible;
use mc_crypto_keys::{RistrettoPrivate, RistrettoPublic};
use mc_util_repr_bytes::{
    derive_core_cmp_from_as_ref, derive_debug_and_display_hex_from_as_ref,
    derive_repr_bytes_from_as_ref_and_try_from, typenum::U32, LengthMismatch,
};

#[cfg(feature = "prost")]
use mc_util_repr_bytes::derive_prost_message_from_repr_bytes;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

#[derive(Clone, Copy, Default, Digestible, Zeroize)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[digestible(transparent)]
/// The "image" of a private key `x`: I = x * Hp(x * G) = x * Hp(P).
pub struct KeyImage {
    /// The curve point corresponding to the key image
    pub point: CompressedRistretto,
}

impl KeyImage {
    /// View the underlying `CompressedRistretto` as an array of bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.point.as_bytes()
    }

    /// Copies `self` into a new Vec.
    #[cfg(feature = "alloc")]
    pub fn to_vec(&self) -> alloc::vec::Vec<u8> {
        self.point.as_bytes().to_vec()
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

impl TryFrom<[u8; 32]> for KeyImage {
    type Error = Error;
    fn try_from(src: [u8; 32]) -> Result<Self, Self::Error> {
        let point = CompressedRistretto::from_slice(&src).map_err(|_e| Error::InvalidCurvePoint)?;
        Ok(Self { point })
    }
}

impl AsRef<CompressedRistretto> for KeyImage {
    fn as_ref(&self) -> &CompressedRistretto {
        &self.point
    }
}

impl AsRef<[u8; 32]> for KeyImage {
    fn as_ref(&self) -> &[u8; 32] {
        self.as_bytes()
    }
}

impl AsRef<[u8]> for KeyImage {
    fn as_ref(&self) -> &[u8] {
        &self.as_bytes()[..]
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
        let point = CompressedRistretto::from_slice(src).map_err(|_e| Error::InvalidCurvePoint)?;
        Ok(Self { point })
    }
}

derive_repr_bytes_from_as_ref_and_try_from!(KeyImage, U32);
derive_core_cmp_from_as_ref!(KeyImage, [u8; 32]);
derive_debug_and_display_hex_from_as_ref!(KeyImage);

#[cfg(feature = "prost")]
derive_prost_message_from_repr_bytes!(KeyImage);
