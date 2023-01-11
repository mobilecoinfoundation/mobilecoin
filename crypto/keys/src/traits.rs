// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Abstract traits used by Structs which implement key management

use crate::{Digest, LengthMismatch, ReprBytes};

use core::{fmt::Debug, hash::Hash};
use displaydoc::Display;
//use hex_fmt::HexFmt;
use mc_crypto_digestible::Digestible;
use mc_util_from_random::FromRandom;
use rand_core::{CryptoRng, RngCore};

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

#[cfg(feature = "serde")]
use serde::{de::DeserializeOwned, Deserialize, Serialize};

/// Marker trait for serialization when `serde` feature is enabled
#[cfg(feature = "serde")]
pub trait MaybeSerde: DeserializeOwned + Serialize {}

#[cfg(feature = "serde")]
impl<T: DeserializeOwned + Serialize> MaybeSerde for T {}

/// Marker trait for serialization when `serde` feature is disabled
#[cfg(not(feature = "serde"))]
pub trait MaybeSerde {}

#[cfg(not(feature = "serde"))]
impl<T> MaybeSerde for T {}

/// Marker trait for `Into<Vec<u8>>` when `alloc` feature is enabled
#[cfg(feature = "alloc")]
pub trait MaybeAlloc: Into<Vec<u8>> {}

#[cfg(feature = "alloc")]
impl<T: Into<Vec<u8>>> MaybeAlloc for T {}

/// Marker trait for `Into<Vec<u8>>` when `alloc` feature is disabled
#[cfg(not(feature = "alloc"))]
pub trait MaybeAlloc {}

#[cfg(not(feature = "alloc"))]
impl<T> MaybeAlloc for T {}

/// A collection of common errors for use by implementers
#[derive(Clone, Copy, Debug, Eq, Hash, Display, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum KeyError {
    /**
     * The length of the given data does not match the algorithm's expected
     * length, provided {0}, required {1}
     */
    LengthMismatch(usize, usize),
    /// The specified algorithm does not match what was expected
    AlgorithmMismatch,
    /// The provided public key is invalid
    InvalidPublicKey,
    /// The provided private key is invalid
    InvalidPrivateKey,
    /// The signature was not able to be validated
    SignatureMismatch,
    /// There was an opaque error returned by another crate or library
    InternalError,
}

impl From<LengthMismatch> for KeyError {
    fn from(src: LengthMismatch) -> Self {
        KeyError::LengthMismatch(src.found, src.expected)
    }
}

/// A trait indicating that a key can be read/written as ASN.1 using the
/// Distinguished Encoding Rules (DER).
pub trait DistinguishedEncoding: Sized {
    /// Retrieve the size of the key, in bytes.
    fn der_size() -> usize;

    /// Create a new object from the given DER-encoded SubjectPublicKeyInfo.
    fn try_from_der(src: &[u8]) -> Result<Self, KeyError>;

    /// Create the standardized DER-encoded representation of this object and
    /// write to the provided buffer.
    ///
    /// Note that this will panic if `buff.len()` is less than
    /// [`DistinguishedEncoding::der_size()`]
    fn to_der_slice<'a>(&self, buff: &'a mut [u8]) -> &'a [u8];

    /// Create the standardized DER-encoded representation of this object.
    #[cfg(feature = "alloc")]
    fn to_der(&self) -> Vec<u8> {
        let mut buff = alloc::vec![0; <Self as DistinguishedEncoding>::der_size()];
        self.to_der_slice(&mut buff);
        buff
    }
}

/// Maximum length of the DER buffer required for
/// [`DistinguishedEncoding::to_der()`]
pub const DER_MAX_LEN: usize = 128;

/// A trait indicating that a fingerprint can be generated for an object.
pub trait Fingerprintable {
    /// Generate fingerprint
    fn fingerprint<D: Digest>(&self) -> Fingerprint<D>;
}

/// A fingerprint object, generic over digest output size
pub struct Fingerprint<D: digest::OutputSizeUser>(
    digest::generic_array::GenericArray<u8, D::OutputSize>,
);

/// Debug impl for fingerprint objects
impl<D: digest::OutputSizeUser> core::fmt::Debug for Fingerprint<D> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Fingerprint({self})")
    }
}

/// Display impl for fingerprint objects
impl<D: digest::OutputSizeUser> core::fmt::Display for Fingerprint<D> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for i in 0..self.0.len() {
            match i < (self.0.len() - 1) {
                true => write!(f, "{:02x}:", self.0[i])?,
                false => write!(f, "{:02x}", self.0[i])?,
            }
        }

        Ok(())
    }
}

/// Blanket implementation of fingerprinting for any public key which also
/// implements the DistinguishedEncoding trait.
impl<T: PublicKey + DistinguishedEncoding> Fingerprintable for T {
    fn fingerprint<D: Digest>(&self) -> Fingerprint<D> {
        // Convert to DER
        let mut buff = [0u8; DER_MAX_LEN];
        let der = self.to_der_slice(&mut buff);

        // Get the hash of the DER bytes
        let hash = D::digest(der);

        // Return fingerprint
        Fingerprint(hash)
    }
}

/// A trait which all public key structures should implement.
pub trait PublicKey:
    Clone
    + Debug
    + Digestible
    + Eq
    + Hash
    + PartialEq
    + PartialOrd
    + Ord
    + ReprBytes<Error = KeyError>
    + MaybeSerde
    + Sized
    + for<'bytes> TryFrom<&'bytes [u8], Error = KeyError>
{
}

/// A trait for all public key types to implement.
pub trait PrivateKey: Debug + Sized + FromRandom {
    type Public: PublicKey + for<'privkey> From<&'privkey Self>;
}

/// A dependency trait for shared secret implementations
///
/// Objects which implement this can be read as bytes, but not copied or
/// serialized.
pub trait KexSecret: AsRef<[u8]> + Debug + Sized {}

/// A marker trait for public keys to be used in key exchange
pub trait KexPublic: PublicKey
where
    for<'privkey> Self: From<&'privkey <Self as KexPublic>::KexEphemeralPrivate>,
{
    type KexEphemeralPrivate: KexEphemeralPrivate + PrivateKey<Public = Self>;

    /// Create a new single-use shared secret for the destination.
    ///
    /// The public key and derived secret will be returned on success.
    fn new_secret(
        &self,
        csprng: &mut (impl RngCore + CryptoRng),
    ) -> (Self, <Self::KexEphemeralPrivate as KexPrivate>::Secret) {
        let our_privkey = <Self::KexEphemeralPrivate as FromRandom>::from_random(csprng);
        let our_pubkey: Self = (&our_privkey).into();
        let shared_secret = our_privkey.key_exchange(self);
        (our_pubkey, shared_secret)
    }
}

/// A trait which private key types used in key exchange should implement
pub trait KexPrivate: PrivateKey
where
    for<'privkey> <Self as PrivateKey>::Public: From<&'privkey Self>,
{
    type Secret: KexSecret;
}

/// A trait which private keys used in a single key exchange should implement.
///
/// Note that ephemeral key-exchange pairs are dropped after the key exchange
/// is performed.
pub trait KexEphemeralPrivate: KexPrivate
where
    for<'privkey> <Self as PrivateKey>::Public: From<&'privkey Self>,
{
    /// Perform a key exchange to get a shared secret, consuming self
    fn key_exchange(
        self,
        their_public: &<Self as PrivateKey>::Public,
    ) -> <Self as KexPrivate>::Secret;
}

/// A trait which private keys used in multiple key exchanges should implement.
///
/// These types of key-exchange pairs can be saved and restored, and will
/// persist after a key-exchange has been performed.
pub trait KexReusablePrivate:
    Clone + KexPrivate + MaybeAlloc + MaybeSerde + for<'bytes> TryFrom<&'bytes [u8]>
where
    for<'privkey> <Self as PrivateKey>::Public: From<&'privkey Self>,
{
    /// Perform a key exchange to get a shared secret, without consuming
    /// self
    fn key_exchange(
        &self,
        their_public: &<Self as PrivateKey>::Public,
    ) -> <Self as KexPrivate>::Secret;
}

/// A trait describing a diffie-helman key exchange system.
///
/// This should be implemented by a zero-width type, and used to select all
/// the various types associated with a given algorithm.
pub trait Kex {
    type Public: KexPublic<KexEphemeralPrivate = Self::EphemeralPrivate>
        + for<'reusable> From<&'reusable Self::Private>;
    type Private: KexReusablePrivate
        + PrivateKey<Public = Self::Public>
        + KexPrivate<Secret = Self::Secret>;
    type EphemeralPrivate: KexEphemeralPrivate
        + PrivateKey<Public = Self::Public>
        + KexPrivate<Secret = Self::Secret>;
    type Secret: KexSecret;
}

#[cfg(test)]
mod test {
    use alloc::string::ToString;
    use sha2::Sha256;

    use super::Fingerprint;

    #[test]
    fn fingerprint_display() {
        let mut h = [0u8; 32];
        h.iter_mut().enumerate().for_each(|(i, v)| *v = i as u8);

        let fp = Fingerprint::<Sha256>(h.into());

        assert_eq!(fp.to_string(), "00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f");
    }
}
