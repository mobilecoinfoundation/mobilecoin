// Copyright (c) 2018-2021 The MobileCoin Foundation

//! A wrapper around dalek's Scalar.
//!
//! The `Scalar` struct holds an integer \\(s < 2\^{255} \\) which
//! represents an element of \\(\mathbb Z / \ell\\).

use super::Error;
use core::fmt;
use curve25519_dalek::scalar::Scalar;
use mc_crypto_digestible::Digestible;
use mc_util_from_random::FromRandom;
use mc_util_repr_bytes::{
    derive_core_cmp_from_as_ref, derive_prost_message_from_repr_bytes,
    derive_try_from_slice_from_repr_bytes, typenum::U32, GenericArray, ReprBytes,
};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

#[derive(Copy, Clone, Default, Eq, Serialize, Deserialize, Digestible, Zeroize)]
#[digestible(transparent)]
pub struct CurveScalar {
    pub scalar: Scalar,
}

impl CurveScalar {
    /// Construct a `CurveScalar` by reducing a 256-bit little-endian integer
    /// modulo the group order \\( \ell \\).
    pub fn from_bytes_mod_order(bytes: [u8; 32]) -> Self {
        Self {
            scalar: Scalar::from_bytes_mod_order(bytes),
        }
    }

    /// The little-endian byte encoding of the integer representing this Scalar.
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.scalar.as_bytes()
    }
}

impl FromRandom for CurveScalar {
    fn from_random<R: CryptoRng + RngCore>(csprng: &mut R) -> Self {
        Self {
            scalar: Scalar::random(csprng),
        }
    }
}

impl From<Scalar> for CurveScalar {
    #[inline]
    fn from(scalar: Scalar) -> Self {
        Self { scalar }
    }
}

impl From<u64> for CurveScalar {
    #[inline]
    fn from(val: u64) -> Self {
        Self {
            scalar: Scalar::from(val),
        }
    }
}

impl AsRef<[u8; 32]> for CurveScalar {
    #[inline]
    fn as_ref(&self) -> &[u8; 32] {
        self.scalar.as_bytes()
    }
}

impl From<&[u8; 32]> for CurveScalar {
    #[inline]
    fn from(src: &[u8; 32]) -> Self {
        Self {
            scalar: Scalar::from_bytes_mod_order(*src),
        }
    }
}

// Implements Ord, PartialOrd, PartialEq, Hash.
derive_core_cmp_from_as_ref!(CurveScalar, [u8; 32]);

impl AsRef<[u8]> for CurveScalar {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.scalar.as_bytes()
    }
}

impl AsRef<Scalar> for CurveScalar {
    #[inline]
    fn as_ref(&self) -> &Scalar {
        &self.scalar
    }
}

impl From<CurveScalar> for Scalar {
    fn from(src: CurveScalar) -> Scalar {
        src.scalar
    }
}

impl ReprBytes for CurveScalar {
    type Error = Error;
    type Size = U32;
    fn to_bytes(&self) -> GenericArray<u8, U32> {
        self.scalar.to_bytes().into()
    }
    fn from_bytes(src: &GenericArray<u8, U32>) -> Result<Self, Error> {
        Ok(Self::from(&(*src).into()))
    }
}

impl fmt::Debug for CurveScalar {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "CurveScalar({})", hex_fmt::HexFmt(self.as_bytes()))
    }
}

// Implements prost::Message. Requires Debug and ReprBytes32.
derive_prost_message_from_repr_bytes!(CurveScalar);
derive_try_from_slice_from_repr_bytes!(CurveScalar);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_to_from_bytes() {
        let one = Scalar::one();
        let curve_scalar = CurveScalar::from_bytes_mod_order(*one.as_bytes());
        assert_eq!(curve_scalar.scalar, one);
        assert_eq!(curve_scalar.as_bytes(), one.as_bytes());
    }

    #[test]
    fn test_from_bytes_mod_order() {
        // All arithmetic on `Scalars` is done modulo \\( \ell \\). This number is
        // larger.
        let l_plus_two_bytes: [u8; 32] = [
            0xef, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
            0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x10,
        ];

        let curve_scalar = CurveScalar::from_bytes_mod_order(l_plus_two_bytes);
        let two: Scalar = Scalar::one() + Scalar::one();

        assert_eq!(curve_scalar.scalar, two);
    }

    #[test]
    /// CurveScalar should serialize and deserialize.
    fn test_curve_scalar_roundtrip() {
        let five = CurveScalar::from(5u64);
        let bytes = mc_util_serial::encode(&five);
        let result: CurveScalar = mc_util_serial::decode(&bytes).unwrap();
        assert_eq!(five, result);
    }
}
