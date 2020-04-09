// Copyright (c) 2018-2020 MobileCoin Inc.

//! A wrapper around dalek's RistrettoPoint.

use super::Error;

use core::{
    convert::TryFrom,
    fmt,
    hash::{Hash, Hasher},
};
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use digestible::Digestible;
use mcserial::{prost_message_helper32, try_from_helper32, ReprBytes32};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

#[derive(Copy, Clone, Default, PartialEq, Eq, Serialize, Deserialize, Digestible)]
pub struct CurvePoint(pub(crate) RistrettoPoint);

impl CurvePoint {
    /// The bytes of a RistrettoPoint in compressed wire format.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.compress().to_bytes()
    }
}

impl keys::FromRandom for CurvePoint {
    fn from_random(csprng: &mut (impl CryptoRng + RngCore)) -> Self {
        Self(RistrettoPoint::random(csprng))
    }
}

#[allow(clippy::derive_hash_xor_eq)]
impl Hash for CurvePoint {
    fn hash<H: Hasher>(&self, hasher: &mut H) {
        self.to_bytes().hash(hasher);
    }
}

impl fmt::Debug for CurvePoint {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "CurvePoint({})", hex_fmt::HexFmt(self.to_bytes()))
    }
}

impl AsRef<RistrettoPoint> for CurvePoint {
    #[inline]
    fn as_ref(&self) -> &RistrettoPoint {
        &self.0
    }
}

impl From<RistrettoPoint> for CurvePoint {
    #[inline]
    fn from(point: RistrettoPoint) -> Self {
        Self(point)
    }
}

impl From<u64> for CurvePoint {
    #[inline]
    fn from(k: u64) -> Self {
        let point = Scalar::from(k) * RISTRETTO_BASEPOINT_POINT;
        Self(point)
    }
}

impl ReprBytes32 for CurvePoint {
    type Error = Error;
    fn to_bytes(&self) -> [u8; 32] {
        self.to_bytes()
    }
    fn from_bytes(src: &[u8; 32]) -> Result<Self, Error> {
        Ok(Self(
            CompressedRistretto::from_slice(src)
                .decompress()
                .ok_or(Error::InvalidCurvePoint)?,
        ))
    }
}

prost_message_helper32! { CurvePoint }
try_from_helper32! { CurvePoint }
