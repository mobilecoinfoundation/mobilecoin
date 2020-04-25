// Copyright (c) 2018-2020 MobileCoin Inc.

//! A wrapper around dalek's Scalar.
//!
//! The `Scalar` struct holds an integer \\(s < 2\^{255} \\) which
//! represents an element of \\(\mathbb Z / \ell\\).

use super::Error;
use core::{convert::TryFrom, fmt};
use curve25519_dalek::scalar::Scalar;
use mc_crypto_digestible::Digestible;
use mc_util_from_random::FromRandom;
use mc_util_serial::{
    deduce_core_traits_from_public_bytes, prost_message_helper32, try_from_helper32, ReprBytes32,
};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

#[derive(Copy, Clone, Default, Eq, Serialize, Deserialize, Digestible)]
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

// Implements Ord, PartialOrd, PartialEq, Hash. Requires AsRef<[u8;32]>.
deduce_core_traits_from_public_bytes! { CurveScalar }

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

impl Into<Scalar> for CurveScalar {
    fn into(self) -> Scalar {
        self.scalar
    }
}

impl ReprBytes32 for CurveScalar {
    type Error = Error;
    fn to_bytes(&self) -> [u8; 32] {
        self.scalar.to_bytes()
    }
    fn from_bytes(src: &[u8; 32]) -> Result<Self, Error> {
        Ok(Self {
            scalar: Scalar::from_bytes_mod_order(*src),
        })
    }
}

impl fmt::Debug for CurveScalar {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "CurveScalar({})", hex_fmt::HexFmt(self.as_bytes()))
    }
}

// Implements prost::Message. Requires Debug and ReprBytes32.
prost_message_helper32! { CurveScalar }

// Implements try_from<&[u8;32]> and try_from<&[u8]>. Requires ReprBytes32.
try_from_helper32! { CurveScalar }

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
        // All arithmetic on `Scalars` is done modulo \\( \ell \\). This number is larger.
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
