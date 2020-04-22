// Copyright (c) 2018-2020 MobileCoin Inc.

use core::{convert::TryFrom, fmt};
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use digestible::Digestible;
use mcserial::{
    deduce_core_traits_from_public_bytes, prost_message_helper32, try_from_helper32, ReprBytes32,
};
use serde::{Deserialize, Serialize};

use super::Error;
use crate::ring_signature::Scalar;
use core::convert::TryInto;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;

#[derive(Copy, Clone, Default, Eq, Serialize, Deserialize, Digestible)]
/// The "image" of a private key `x`: I = x * H(x * G) = x * H(P).
pub struct KeyImage(pub(crate) CompressedRistretto);

impl KeyImage {
    /// View the underlying `CompressedRistretto` as an array of bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    /// Copies `self` into a new Vec.
    pub fn to_vec(&self) -> alloc::vec::Vec<u8> {
        self.0.as_bytes().to_vec()
    }
}

impl AsRef<[u8; 32]> for KeyImage {
    fn as_ref(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }
}

impl AsRef<[u8]> for KeyImage {
    fn as_ref(&self) -> &[u8] {
        &self.0.as_bytes()[..]
    }
}

impl ReprBytes32 for KeyImage {
    type Error = Error;
    fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
    fn from_bytes(src: &[u8; 32]) -> Result<Self, Error> {
        Ok(Self(CompressedRistretto::from_slice(src)))
    }
}

prost_message_helper32! { KeyImage }
try_from_helper32! { KeyImage }
deduce_core_traits_from_public_bytes! { KeyImage }

impl From<[u8; 32]> for KeyImage {
    fn from(src: [u8; 32]) -> Self {
        Self(CompressedRistretto::from_slice(&src))
    }
}

impl fmt::Debug for KeyImage {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "KeyImage({})", hex_fmt::HexFmt(self.as_bytes()))
    }
}

impl From<RistrettoPoint> for KeyImage {
    fn from(src: RistrettoPoint) -> Self {
        Self(src.compress())
    }
}

// Many tests use this
impl From<u64> for KeyImage {
    fn from(n: u64) -> Self {
        let point = Scalar::from(n) * RISTRETTO_BASEPOINT_POINT;
        Self::from(point)
    }
}

impl AsRef<CompressedRistretto> for KeyImage {
    fn as_ref(&self) -> &CompressedRistretto {
        &self.0
    }
}

impl TryInto<RistrettoPoint> for KeyImage {
    type Error = ();

    fn try_into(self) -> Result<RistrettoPoint, Self::Error> {
        self.0.decompress().ok_or(())
    }
}
