// Copyright (c) 2018-2020 MobileCoin Inc.

#![allow(non_snake_case)]

use crate::traits::*;
use alloc::vec::Vec;
use core::{
    cmp::Ordering,
    convert::{AsRef, TryFrom, TryInto},
    fmt::{Debug, Display, Formatter, Result as FmtResult},
    hash::{Hash, Hasher},
};
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use digest::generic_array::typenum::U32;
use hex_fmt::HexFmt;
use mc_crypto_digestible::Digestible;
use mc_util_from_random::FromRandom;
use mc_util_repr_bytes::{
    derive_core_cmp_from_as_ref, derive_into_vec_from_repr_bytes,
    derive_prost_message_from_repr_bytes, derive_repr_bytes_from_as_ref_and_try_from,
    derive_serde_from_repr_bytes, derive_try_from_slice_from_repr_bytes, ReprBytes,
};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// A Ristretto-format private scalar
#[derive(Clone, Copy, Default, Zeroize)]
pub struct RistrettoPrivate(pub(crate) Scalar);

impl AsRef<[u8; 32]> for RistrettoPrivate {
    fn as_ref(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }
}

impl TryFrom<&[u8; 32]> for RistrettoPrivate {
    type Error = KeyError;

    fn try_from(src: &[u8; 32]) -> Result<Self, KeyError> {
        Ok(Self(
            Scalar::from_canonical_bytes(*src).ok_or(KeyError::InvalidPrivateKey)?,
        ))
    }
}

impl AsRef<[u8]> for RistrettoPrivate {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl TryFrom<&[u8]> for RistrettoPrivate {
    type Error = KeyError;
    fn try_from(src: &[u8]) -> Result<Self, KeyError> {
        let bytes: &[u8; 32] = src
            .try_into()
            .map_err(|_| KeyError::LengthMismatch(src.len(), 32))?;
        Self::try_from(bytes)
    }
}

derive_repr_bytes_from_as_ref_and_try_from!(RistrettoPrivate, U32);
derive_into_vec_from_repr_bytes!(RistrettoPrivate);
derive_serde_from_repr_bytes!(RistrettoPrivate);
derive_prost_message_from_repr_bytes!(RistrettoPrivate);

impl RistrettoPrivate {
    /// This is used by some code that used to use ReprBytes32 API
    /// This is okay in code that is not generic over the key type.
    pub fn to_bytes(&self) -> [u8; 32] {
        *self.0.as_bytes()
    }
}

impl AsRef<Scalar> for RistrettoPrivate {
    fn as_ref(&self) -> &Scalar {
        &self.0
    }
}

impl From<Scalar> for RistrettoPrivate {
    fn from(scalar: Scalar) -> Self {
        Self(scalar)
    }
}

impl Debug for RistrettoPrivate {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(
            f,
            "RistrettoPrivate for pubkey: {:?}",
            RistrettoPublic::from(self)
        )
    }
}

impl PrivateKey for RistrettoPrivate {
    type Public = RistrettoPublic;
}

impl FromRandom for RistrettoPrivate {
    fn from_random<R: CryptoRng + RngCore>(csprng: &mut R) -> RistrettoPrivate {
        Self(Scalar::random(csprng))
    }
}

impl KexEphemeralPrivate for RistrettoPrivate {
    fn key_exchange(
        self,
        their_public: &<Self as PrivateKey>::Public,
    ) -> <Self as KexPrivate>::Secret {
        RistrettoSecret((self.0 * their_public.0).compress().to_bytes())
    }
}

impl KexReusablePrivate for RistrettoPrivate {
    fn key_exchange(
        &self,
        their_public: &<Self as PrivateKey>::Public,
    ) -> <Self as KexPrivate>::Secret {
        RistrettoSecret((self.0 * their_public.0).compress().to_bytes())
    }
}

impl KexPrivate for RistrettoPrivate {
    type Secret = RistrettoSecret;
}

/// A private ristretto key which is ephemeral, should never be copied,
/// and should be zeroized
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct RistrettoEphemeralPrivate(Scalar);

impl PrivateKey for RistrettoEphemeralPrivate {
    type Public = RistrettoPublic;
}

impl KexPrivate for RistrettoEphemeralPrivate {
    type Secret = RistrettoSecret;
}

impl KexEphemeralPrivate for RistrettoEphemeralPrivate {
    fn key_exchange(
        self,
        their_public: &<Self as PrivateKey>::Public,
    ) -> <Self as KexPrivate>::Secret {
        RistrettoSecret((self.0 * their_public.0).compress().to_bytes())
    }
}

impl FromRandom for RistrettoEphemeralPrivate {
    fn from_random<R: CryptoRng + RngCore>(csprng: &mut R) -> Self {
        Self(Scalar::random(csprng))
    }
}

impl Debug for RistrettoEphemeralPrivate {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(
            f,
            "RistrettoEphemeralPrivate for {:?}",
            RistrettoPublic::from(self)
        )
    }
}

/// A Ristretto-format curve point for use as a public key
#[derive(Clone, Copy, Default, Digestible)]
pub struct RistrettoPublic(pub(crate) RistrettoPoint);

impl AsRef<RistrettoPoint> for RistrettoPublic {
    fn as_ref(&self) -> &RistrettoPoint {
        &self.0
    }
}

impl FromRandom for RistrettoPublic {
    fn from_random<R: CryptoRng + RngCore>(csprng: &mut R) -> RistrettoPublic {
        Self(RistrettoPoint::random(csprng))
    }
}

impl From<RistrettoPoint> for RistrettoPublic {
    fn from(point: RistrettoPoint) -> Self {
        Self(point)
    }
}

impl ReprBytes for RistrettoPublic {
    type Size = U32;
    type Error = KeyError;

    fn to_bytes(&self) -> GenericArray<u8, U32> {
        self.0.compress().to_bytes().into()
    }

    fn from_bytes(src: &GenericArray<u8, U32>) -> Result<Self, KeyError> {
        Ok(Self(
            CompressedRistretto::from_slice(src.as_slice())
                .decompress()
                .ok_or(KeyError::InvalidPublicKey)?,
        ))
    }
}

derive_serde_from_repr_bytes!(RistrettoPublic);
derive_prost_message_from_repr_bytes!(RistrettoPublic);
derive_into_vec_from_repr_bytes!(RistrettoPublic);
derive_try_from_slice_from_repr_bytes!(RistrettoPublic);

// Many historical APIs assumed TryFrom<&[u8;32]> existed for RistrettoPublic
// This will work fine in code that is not generic over the size of the key
impl TryFrom<&[u8; 32]> for RistrettoPublic {
    type Error = KeyError;
    fn try_from(src: &[u8; 32]) -> Result<Self, KeyError> {
        Self::try_from(&src[..])
    }
}

impl RistrettoPublic {
    // Many historical APIs based on ReprBytes32 in mobilecoin use to_bytes() -> [u8;32].
    // This is okay in non-generic code
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.compress().to_bytes()
    }
}

impl PartialOrd for RistrettoPublic {
    fn partial_cmp(&self, other: &RistrettoPublic) -> Option<Ordering> {
        self.to_bytes().partial_cmp(&other.to_bytes())
    }
}

impl Ord for RistrettoPublic {
    fn cmp(&self, other: &RistrettoPublic) -> Ordering {
        self.to_bytes().cmp(&other.to_bytes())
    }
}

impl Hash for RistrettoPublic {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.to_bytes().hash(state)
    }
}

impl Eq for RistrettoPublic {}

impl PartialEq for RistrettoPublic {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl PublicKey for RistrettoPublic {}

impl From<&RistrettoPrivate> for RistrettoPublic {
    fn from(private: &RistrettoPrivate) -> Self {
        let x = private.0;
        let G = RISTRETTO_BASEPOINT_POINT;
        let Y = x * G;

        Self(Y)
    }
}

impl From<&RistrettoEphemeralPrivate> for RistrettoPublic {
    fn from(private: &RistrettoEphemeralPrivate) -> Self {
        let x = private.0;
        let G = RISTRETTO_BASEPOINT_POINT;
        let Y = x * G;

        Self(Y)
    }
}

impl Debug for RistrettoPublic {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "RistrettoPublic({})", HexFmt(self.to_bytes()))
    }
}

impl Display for RistrettoPublic {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "{}", HexFmt(self.to_bytes()))
    }
}

impl From<&RistrettoPublic> for Vec<u8> {
    fn from(src: &RistrettoPublic) -> Vec<u8> {
        let compressed = src.as_ref().compress();
        Vec::from(&compressed.as_bytes()[..])
    }
}

impl KexPublic for RistrettoPublic {
    type KexEphemeralPrivate = RistrettoEphemeralPrivate;
}

impl TryFrom<&CompressedRistrettoPublic> for RistrettoPublic {
    type Error = KeyError;
    fn try_from(src: &CompressedRistrettoPublic) -> Result<Self, KeyError> {
        Ok(Self(src.0.decompress().ok_or(KeyError::InvalidPublicKey)?))
    }
}

/// Shared Secret resulting from Key Exchange
///
/// This is a (compressed) curve point on the ristretto curve, but we make it a
/// different type from RistrettoPublic in order to avoid bugs where the secret
/// is publicized.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct RistrettoSecret([u8; 32]);

impl Drop for RistrettoSecret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl AsRef<[u8]> for RistrettoSecret {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}

impl AsRef<[u8; 32]> for RistrettoSecret {
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}

impl KexSecret for RistrettoSecret {}

/// This is a newtype wrapper around CompressedRistretto, which implements
/// From<RistrettoPublic>, and serialization / digest implementations.
///
/// This structure does not perform any validation that the bytes contained
/// within it represent a valid point, because compression/decompression of
/// ristretto-flavored points is a very expensive operation.
///
/// As a result, this does not implement the `PublicKey` interface, nor is it
/// usable in a key-exchange.
#[derive(Clone, Copy, Default, Eq, Digestible)]
pub struct CompressedRistrettoPublic(pub(crate) CompressedRistretto);

impl CompressedRistrettoPublic {
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }
}

impl AsRef<[u8]> for CompressedRistrettoPublic {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl TryFrom<&[u8]> for CompressedRistrettoPublic {
    type Error = KeyError;
    fn try_from(src: &[u8]) -> Result<Self, KeyError> {
        if src.len() != 32 {
            return Err(KeyError::LengthMismatch(src.len(), 32));
        }
        Ok(Self(CompressedRistretto::from_slice(src)))
    }
}

derive_repr_bytes_from_as_ref_and_try_from!(CompressedRistrettoPublic, U32);
derive_into_vec_from_repr_bytes!(CompressedRistrettoPublic);
derive_serde_from_repr_bytes!(CompressedRistrettoPublic);
derive_prost_message_from_repr_bytes!(CompressedRistrettoPublic);

impl From<&[u8; 32]> for CompressedRistrettoPublic {
    fn from(src: &[u8; 32]) -> Self {
        Self(CompressedRistretto::from_slice(&src[..]))
    }
}

impl AsRef<[u8; 32]> for CompressedRistrettoPublic {
    fn as_ref(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }
}

derive_core_cmp_from_as_ref!(CompressedRistrettoPublic, [u8; 32]);

impl Debug for CompressedRistrettoPublic {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        let bytes: &[u8] = self.as_ref();
        write!(f, "CompressedRistrettoPublic({})", HexFmt(bytes))
    }
}

impl Display for CompressedRistrettoPublic {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        let bytes: &[u8] = self.as_ref();
        write!(f, "{}", HexFmt(bytes))
    }
}

impl AsRef<CompressedRistretto> for CompressedRistrettoPublic {
    fn as_ref(&self) -> &CompressedRistretto {
        &self.0
    }
}

impl From<RistrettoPoint> for CompressedRistrettoPublic {
    fn from(src: RistrettoPoint) -> Self {
        Self(src.compress())
    }
}

impl From<&RistrettoPublic> for CompressedRistrettoPublic {
    fn from(src: &RistrettoPublic) -> Self {
        Self(src.0.compress())
    }
}

impl From<RistrettoPublic> for CompressedRistrettoPublic {
    fn from(src: RistrettoPublic) -> Self {
        Self(src.0.compress())
    }
}

impl From<CompressedRistretto> for CompressedRistrettoPublic {
    fn from(src: CompressedRistretto) -> Self {
        Self(src)
    }
}

impl PublicKey for CompressedRistrettoPublic {}

/// A zero-width type used to identify the Ristretto key exchange system.
pub struct Ristretto {}

/// The implementation of the Ristretto key exchange system.
impl Kex for Ristretto {
    type Public = RistrettoPublic;
    type Private = RistrettoPrivate;
    type EphemeralPrivate = RistrettoEphemeralPrivate;
    type Secret = RistrettoSecret;
}

#[cfg(test)]
mod test {
    extern crate mc_util_test_helper;

    use super::*;

    // Test that mc-util-serial can serialize a pubkey
    #[test]
    fn test_pubkey_serialize() {
        mc_util_test_helper::run_with_several_seeds(|mut rng| {
            let pubkey = RistrettoPublic::from_random(&mut rng);
            let serialized =
                mc_util_serial::serialize(&pubkey).expect("Could not serialize pubkey");
            let deserialized: RistrettoPublic =
                mc_util_serial::deserialize(&serialized).expect("Could not deserialize pubkey");
            assert_eq!(deserialized, pubkey);
        });
    }

    // Test that mc-util-serial can serialize a private key
    #[test]
    fn test_privkey_serialize() {
        mc_util_test_helper::run_with_several_seeds(|mut rng| {
            let privkey = RistrettoPrivate::from_random(&mut rng);
            let serialized =
                mc_util_serial::serialize(&privkey).expect("Could not serialize privkey.");
            let deserialized: RistrettoPrivate =
                mc_util_serial::deserialize(&serialized).expect("Could not deserialize privkey");
            let pubkey = RistrettoPublic::from(&privkey);
            let deserialized_pubkey = RistrettoPublic::from(&deserialized);
            assert_eq!(deserialized_pubkey, pubkey);
        });
    }

    // Note: serde_json currently fails on RistrettoPublic and RistrettoPrivate
}
