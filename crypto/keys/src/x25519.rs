// Copyright (c) 2018-2021 The MobileCoin Foundation

//! dalek-cryptography based keys implementations

// Badly-named Macros
use alloc::vec;

// Dependencies
use crate::traits::*;
use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use binascii::b64encode;
use core::{
    convert::{AsRef, TryFrom},
    fmt::{Debug, Error as FmtError, Formatter, Result as FmtResult},
    str::from_utf8,
};
use digest::generic_array::typenum::U32;
use mc_crypto_digestible::Digestible;
use mc_util_from_random::FromRandom;
use mc_util_repr_bytes::{
    derive_core_cmp_from_as_ref, derive_into_vec_from_repr_bytes,
    derive_repr_bytes_from_as_ref_and_try_from,
};
use rand_core::{CryptoRng, RngCore};
use serde::{
    de::{Deserialize, Deserializer, Error as DeserializeError, Visitor},
    ser::{Serialize, Serializer},
};
use sha2::{self, Sha256};
use x25519_dalek::{EphemeralSecret, PublicKey as DalekPublicKey, SharedSecret, StaticSecret};
use zeroize::Zeroize;

/// The length in bytes of canonical representation of x25519 (public and
/// private keys)
pub const X25519_LEN: usize = 32;

/// A structure for keeping an X25519 shared secret
pub struct X25519Secret(SharedSecret);

impl KexSecret for X25519Secret {}

/// A shared secret can be used as a byte slice
impl AsRef<[u8]> for X25519Secret {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

/// The debug implementation will output the SHA-256 sum of the secret, but not
/// the secret itself
impl Debug for X25519Secret {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        let mut hasher = Sha256::new();
        hasher.update(self.as_ref());
        let hash_results = hasher.finalize();
        let mut hash_strbuf: Vec<u8> = Vec::with_capacity(hash_results.len() * 2);
        let hash_len = {
            let hash_strslice =
                binascii::bin2hex(&hash_results, &mut hash_strbuf).map_err(|_e| FmtError)?;
            hash_strslice.len()
        };
        hash_strbuf.truncate(hash_len);
        write!(
            f,
            "X25519Secret SHA-256: {}",
            from_utf8(&hash_strbuf).map_err(|_e| FmtError)?
        )
    }
}

impl Serialize for X25519Secret {
    /// Secret keys are serialized as bytes, as there is no ASN.1 representation
    /// of a symmetric key
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(self.as_ref())
    }
}

/// A structure encapsulating an X25519 public key
#[derive(Digestible)]
pub struct X25519Public(DalekPublicKey);

// ASN.1 DER SubjectPublicKeyInfo Bytes -- this is a set of nested TLVs
// describing a pubkey -- use https://lapo.it/asn1js/
//
//   SEQUENCE(30), Length = 2a               -- T,L
//     SEQUENCE(30), Length = 05             -- T,L
//        OBJECT IDENTIFIER(06), Length = 03  -- T,L,V
//           curveX25519(1.3.101.110 = 2B 65 6E)
//     BIT STRING(03), Length = 21            -- T,L
//        paddingBits = 00 (0x21 == 33, first byte is the number of padding bits
// to fill an octet)        actualKeyBitsGoesHere
const X25519_SPKI_DER_PREFIX: [u8; 12] = [
    0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x6E, 0x03, 0x21, 0x00,
];

// In ASN.1 + DER's TLV, L is just the length of V, so we need to add 2 for
// the length of T and L themselves.
const X25519_SPKI_DER_LEN: usize = 0x02 + 0x2A;

impl PublicKey for X25519Public {}

impl DistinguishedEncoding for X25519Public {
    fn der_size() -> usize {
        X25519_SPKI_DER_LEN
    }

    /// Constructs a new X25519Public from a DER-encoded SubjectPublicKeyInfo
    /// structure
    ///
    /// # Examples
    ///
    /// ```
    /// use pem::parse;
    /// use mc_crypto_keys::*;
    ///
    /// const PUBKEY: &'static str = "-----BEGIN PUBLIC KEY-----
    /// MCowBQYDK2VuAyEAQcOfK2+MHlDJoQUkjboENfdfpFf2Uhv+ESWue1ErPTM=
    /// -----END PUBLIC KEY-----
    /// ";
    ///
    /// let parsed = parse(PUBKEY).expect("Could not parse public key PEM");
    /// let pubkey = X25519Public::try_from_der(&parsed.contents).expect("Could not parse DER into X25519Public");
    /// let der = pubkey.to_der();
    /// let pubkey2 = X25519Public::try_from_der(der.as_slice()).expect("Could not parse generated DER into X25519Public");
    /// assert_eq!(pubkey, pubkey2);
    /// assert_eq!(&parsed.contents, &der);
    /// ```
    fn try_from_der(src: &[u8]) -> Result<Self, KeyError> {
        if src.len() != X25519_SPKI_DER_LEN {
            return Err(KeyError::LengthMismatch(src.len(), X25519_SPKI_DER_LEN));
        }
        if src[6..9] != X25519_SPKI_DER_PREFIX[6..9] {
            return Err(KeyError::AlgorithmMismatch);
        }
        if src[..12] != X25519_SPKI_DER_PREFIX {
            return Err(KeyError::InvalidPublicKey);
        }
        Self::try_from(&src[12..])
    }

    /// Serializes this object into a DER-encoded SubjectPublicKeyInfo structure
    fn to_der(&self) -> Vec<u8> {
        let data = self.as_ref();
        let mut retval = vec![0u8; X25519_SPKI_DER_LEN];
        let prefix_len = X25519_SPKI_DER_PREFIX.len();
        retval[..prefix_len].copy_from_slice(&X25519_SPKI_DER_PREFIX);
        retval[prefix_len..].copy_from_slice(data);
        retval
    }
}

impl KexPublic for X25519Public {
    type KexEphemeralPrivate = X25519EphemeralPrivate;
}

impl AsRef<[u8]> for X25519Public {
    /// Public keys can be referenced as bytes.
    ///
    /// ```
    /// use mc_crypto_keys::*;
    /// use std::convert::TryFrom;
    ///
    /// let key = [0x55u8; 32];
    /// let pubkey = X25519Public::try_from(&key as &[u8]).expect("Could not create key.");
    /// let pubkey_bytes : &[u8] = pubkey.as_ref();
    /// assert_eq!(&key as &[u8], pubkey_bytes);
    /// ```
    ///
    /// Digesting a X25519 key's raw bytes
    ///
    /// ```
    /// use mc_crypto_keys::*;
    /// use mc_crypto_digestible::Digestible;
    /// use sha2::{Digest, Sha256};
    /// use std::convert::TryFrom;
    ///
    /// let key = [0x55u8; 32];
    /// let pubkey = X25519Public::try_from(&key as &[u8]).expect("Could not create key.");
    /// let mut hasher = Sha256::new();
    /// hasher.update(pubkey);
    /// let hash = hasher.finalize();
    /// let expected : [u8; 32] = [
    ///     132, 18, 109, 13, 216, 80, 25, 155, 226, 144, 33, 170, 219, 174, 230, 140,
    ///     185, 25, 144, 71, 177, 203, 126, 201, 137, 77, 219, 30, 53, 98, 120, 60
    /// ];
    /// assert_eq!(hash.as_slice(), &expected);
    /// ```
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl TryFrom<&[u8]> for X25519Public {
    type Error = KeyError;

    /// Try to load the given byte slice as a public key.
    fn try_from(src: &[u8]) -> Result<Self, <Self as TryFrom<&[u8]>>::Error> {
        if src.len() != X25519_LEN {
            return Err(KeyError::LengthMismatch(src.len(), X25519_LEN));
        }
        let mut src_copy = [0u8; X25519_LEN];
        src_copy.copy_from_slice(src);
        Ok(Self(DalekPublicKey::from(src_copy)))
    }
}

derive_repr_bytes_from_as_ref_and_try_from!(X25519Public, U32);
derive_into_vec_from_repr_bytes!(X25519Public);

impl Clone for X25519Public {
    /// Public keys can be cloned.
    ///
    /// # Examples
    ///
    /// ```
    /// use mc_crypto_keys::X25519Public;
    /// use std::convert::TryFrom;
    ///
    /// let key = [0x55u8; 32];
    /// let pubkey1 = X25519Public::try_from(&key as &[u8]).expect("Could not create key.");
    /// let pubkey2 = pubkey1.clone();
    /// assert_eq!(pubkey1, pubkey2);
    /// ```
    fn clone(&self) -> Self {
        X25519Public(DalekPublicKey::from(*self.0.as_bytes()))
    }
}

impl Debug for X25519Public {
    /// Public keys are debug-printed as PEM-formatted data.
    ///
    /// # Examples
    ///
    /// ```
    /// use pem::parse;
    /// use mc_crypto_keys::*;
    ///
    /// const PUBKEY: &'static str = "-----BEGIN PUBLIC KEY-----
    /// MCowBQYDK2VuAyEAQcOfK2+MHlDJoQUkjboENfdfpFf2Uhv+ESWue1ErPTM=
    /// -----END PUBLIC KEY-----
    /// ";
    ///
    /// let parsed = parse(PUBKEY).expect("Could not parse public key PEM");
    /// let pubkey = X25519Public::try_from_der(&parsed.contents).expect("Could not parse DER into X25519Public");
    /// assert_eq!(format!("{:?}", pubkey), PUBKEY);
    /// ```
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        let der = self.to_der();
        let mut b64_output = vec![0u8; der.len() * 4 / 3 + 4];
        let final_len = loop {
            match b64encode(&der, &mut b64_output) {
                Ok(val) => break val.len(),
                Err(e) => match e {
                    binascii::ConvertError::InvalidOutputLength => {
                        let target_len = b64_output.len() * 2;
                        b64_output.resize(target_len, 0u8);
                    }
                    binascii::ConvertError::InvalidInputLength => {
                        return Err(FmtError);
                    }
                    binascii::ConvertError::InvalidInput => {
                        return Err(FmtError);
                    }
                },
            }
        };
        b64_output.truncate(final_len);
        write!(
            f,
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
            String::from_utf8(b64_output).map_err(|_e| FmtError)?
        )
    }
}

impl<'de> Deserialize<'de> for X25519Public {
    /// Public keys are deserialized from DER-encoded SubjectPublicKeyInfo
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<X25519Public, D::Error> {
        struct KeyVisitor;

        impl<'de> Visitor<'de> for KeyVisitor {
            type Value = X25519Public;

            fn expecting(&self, formatter: &mut Formatter) -> FmtResult {
                write!(formatter, "A public key structure as DER bytes")
            }

            fn visit_bytes<E: DeserializeError>(self, value: &[u8]) -> Result<Self::Value, E> {
                X25519Public::try_from_der(value).map_err(|err| E::custom(err.to_string()))
            }
        }

        deserializer.deserialize_bytes(KeyVisitor)
    }
}

impl AsRef<[u8; X25519_LEN]> for X25519Public {
    fn as_ref(&self) -> &[u8; X25519_LEN] {
        self.0.as_bytes()
    }
}

derive_core_cmp_from_as_ref!(X25519Public, [u8; X25519_LEN]);
impl Eq for X25519Public {}

impl Serialize for X25519Public {
    /// Public keys are serialized as simple DER-encoded byte streams
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(self.to_der().as_slice())
    }
}

impl From<&X25519Private> for X25519Public {
    /// Public keys can be extracted from a reusable private key reference
    ///
    /// # Examples
    /// ```
    /// use mc_crypto_keys::*;
    /// use mc_util_from_random::FromRandom;
    /// use rand_core::SeedableRng;
    /// use rand_hc::Hc128Rng;
    /// use sha2::*;
    ///
    /// let mut rng = Hc128Rng::seed_from_u64(0);
    /// let privkey = X25519Private::from_random(&mut rng);
    /// let pubkey = X25519Public::from(&privkey);
    /// assert_eq!("0b:5e:58:80:55:b2:3b:f4:d6:df:71:c5:ae:be:3c:30:23:37:41:06:64:b5:55:69:4d:04:a2:35:21:36:2d:c3",
    ///            pubkey.fingerprint::<Sha256>().expect("Could not take fingerprint of pubkey."));
    /// ```
    fn from(pair: &X25519Private) -> Self {
        Self(DalekPublicKey::from(&pair.0))
    }
}

impl From<&X25519EphemeralPrivate> for X25519Public {
    /// Public keys can be extracted from an ephemeral private key reference
    ///
    /// # Examples
    /// ```
    /// use mc_crypto_keys::*;
    /// use mc_util_from_random::FromRandom;
    /// use rand_core::SeedableRng;
    /// use rand_hc::Hc128Rng;
    /// use sha2::*;
    ///
    /// let mut rng = Hc128Rng::seed_from_u64(0);
    /// let privkey = X25519EphemeralPrivate::from_random(&mut rng);
    /// let pubkey = X25519Public::from(&privkey);
    /// assert_eq!("0b:5e:58:80:55:b2:3b:f4:d6:df:71:c5:ae:be:3c:30:23:37:41:06:64:b5:55:69:4d:04:a2:35:21:36:2d:c3",
    ///            pubkey.fingerprint::<Sha256>().expect("Could not take fingerprint of pubkey."));
    /// ```
    fn from(pair: &X25519EphemeralPrivate) -> Self {
        Self(DalekPublicKey::from(&pair.0))
    }
}

impl From<&X25519Public> for Vec<u8> {
    fn from(src: &X25519Public) -> Vec<u8> {
        let bytes = src.0.as_bytes();
        Vec::from(&bytes[..])
    }
}

/// A KeyPair for use with an X25519 key exchange
pub struct X25519EphemeralPrivate(EphemeralSecret);

impl PrivateKey for X25519EphemeralPrivate {
    type Public = X25519Public;
}

impl KexPrivate for X25519EphemeralPrivate {
    type Secret = X25519Secret;
}

impl KexEphemeralPrivate for X25519EphemeralPrivate {
    fn key_exchange(self, their_public: &X25519Public) -> X25519Secret {
        X25519Secret(self.0.diffie_hellman(&their_public.0))
    }
}

impl FromRandom for X25519EphemeralPrivate {
    fn from_random<R: CryptoRng + RngCore>(csprng: &mut R) -> X25519EphemeralPrivate {
        X25519EphemeralPrivate(EphemeralSecret::new(csprng))
    }
}

impl Debug for X25519EphemeralPrivate {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(
            f,
            "X25519EphemeralPrivate for {:?}",
            X25519Public::from(self)
        )
    }
}

/// An X25519 private key which can be saved and restored
pub struct X25519Private(StaticSecret);

impl PrivateKey for X25519Private {
    type Public = X25519Public;
}

impl FromRandom for X25519Private {
    fn from_random<R: CryptoRng + RngCore>(csprng: &mut R) -> X25519Private {
        X25519Private(StaticSecret::new(csprng))
    }
}

impl KexPrivate for X25519Private {
    type Secret = X25519Secret;
}

// ASN.1 DER PrivateKeyInfo Bytes -- this is a set of nested TLVs
// describing a private key -- use https://lapo.it/asn1js/
//
//   SEQUENCE(30), Length = 0x2a                  -- T,L
//     INTEGER(0)
//     SEQUENCE(30), Length = 0x05                -- T,L
//        OBJECT IDENTIFIER(06), Length = 0x03    -- T,L,V
//           curveX25519(1.3.101.110 = 2B 65 70)
//     OCTET STRING(04), Length = 0x22            -- T,L
//        OCTET STRING(04), Length = 0x20         -- T,L,V
//           actualKeyBytesGoHere
const X25519_PKI_DER_PREFIX: [u8; 16] = [
    0x30, 0x2E, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x6E, 0x04, 0x22, 0x04, 0x20,
];

const X25519_PKI_DER_LEN: usize = 0x02 + 0x2E;

impl DistinguishedEncoding for X25519Private {
    fn der_size() -> usize {
        X25519_PKI_DER_LEN
    }

    fn try_from_der(src: &[u8]) -> Result<Self, KeyError> {
        if src.len() != X25519_PKI_DER_LEN {
            return Err(KeyError::LengthMismatch(src.len(), X25519_PKI_DER_LEN));
        }
        if src[9..12] != X25519_PKI_DER_PREFIX[9..12] {
            return Err(KeyError::AlgorithmMismatch);
        }
        let prefix_len = X25519_PKI_DER_PREFIX.len();
        if src[..prefix_len] != X25519_PKI_DER_PREFIX {
            return Err(KeyError::InvalidPrivateKey);
        }
        Self::try_from(&src[prefix_len..])
    }

    fn to_der(&self) -> Vec<u8> {
        let mut retval = vec![0u8; X25519_PKI_DER_LEN];
        let key = self.0.to_bytes();
        let prefix_len = X25519_PKI_DER_PREFIX.len();
        retval[..prefix_len].copy_from_slice(&X25519_PKI_DER_PREFIX);
        retval[prefix_len..].copy_from_slice(&key);
        retval
    }
}

impl KexReusablePrivate for X25519Private {
    fn key_exchange(&self, their_public: &X25519Public) -> X25519Secret {
        X25519Secret(self.0.diffie_hellman(&their_public.0))
    }
}

impl Clone for X25519Private {
    /// Create a one-to-one copy of this private key.
    ///
    /// # Examples
    ///
    /// ```
    /// use core::convert::TryFrom;
    /// use mc_crypto_keys::*;
    ///
    /// let key = [0x55u8; 32];
    /// let privkey1 = X25519Private::try_from(&key as &[u8]).expect("Could not load key.");
    /// let privkey2 = privkey1.clone();
    ///
    /// let pubkey1 = X25519Public::from(&privkey1);
    /// let pubkey2 = X25519Public::from(&privkey2);
    /// assert_eq!(pubkey1, pubkey2);
    /// ```
    fn clone(&self) -> Self {
        X25519Private(StaticSecret::from(self.0.to_bytes()))
    }
}

impl Debug for X25519Private {
    /// Output the public key corresponding to this private key as a debug
    /// string
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(
            f,
            "X25519Private with public SHA2-256 fingerprint {}",
            X25519Public::from(self)
                .fingerprint::<Sha256>()
                .map_err(|_e| FmtError)?
        )
    }
}

impl<'de> Deserialize<'de> for X25519Private {
    /// Public keys are deserialized from DER-encoded PrivateKeyInfo
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<X25519Private, D::Error> {
        struct KeyVisitor;

        impl<'de> Visitor<'de> for KeyVisitor {
            type Value = X25519Private;

            fn expecting(&self, formatter: &mut Formatter) -> FmtResult {
                write!(formatter, "An public key structure as DER bytes")
            }

            fn visit_bytes<E: DeserializeError>(self, value: &[u8]) -> Result<Self::Value, E> {
                X25519Private::try_from_der(value).map_err(|err| E::custom(err.to_string()))
            }
        }

        deserializer.deserialize_bytes(KeyVisitor)
    }
}

/// Convert the scalar contents of a static keypair into a vector of bytes.
///
/// # Examples
///
/// ```
/// use mc_crypto_keys::*;
/// use std::convert::TryFrom;
///
/// let mut key = [0x55u8; 32];
/// key[0] = 0x50u8; // scalar values are clamped by dalek
/// let privkey = X25519Private::try_from(&key as &[u8]).expect("Could not create key.");
/// let keyout: Vec<u8> = privkey.into();
/// assert_eq!(&key as &[u8], keyout.as_slice());
/// ```
impl From<X25519Private> for Vec<u8> {
    fn from(src: X25519Private) -> Vec<u8> {
        src.0.to_bytes().to_vec()
    }
}

impl Serialize for X25519Private {
    /// Private keys are serialized as simple DER-encoded byte streams
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut der_bytes = self.to_der();
        let retval = serializer.serialize_bytes(der_bytes.as_slice());
        der_bytes.zeroize();
        retval
    }
}

impl<'bytes> TryFrom<&'bytes [u8]> for X25519Private {
    type Error = KeyError;

    /// Convert the scalar contents of a static keypair into a vector of bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// use mc_crypto_keys::X25519Private;
    /// use std::convert::TryFrom;
    ///
    /// let mut key = [0x55u8; 32];
    /// key[0] = 0x50u8; // scalar values are clamped by dalek
    /// let privkey = X25519Private::try_from(&key as &[u8]).expect("Could not create key.");
    /// let keyout: Vec<u8> = privkey.into();
    /// assert_eq!(&key as &[u8], keyout.as_slice());
    /// ```
    fn try_from(src: &[u8]) -> Result<Self, <Self as TryFrom<&'bytes [u8]>>::Error> {
        if src.len() != X25519_LEN {
            return Err(KeyError::LengthMismatch(src.len(), X25519_LEN));
        }
        let mut bytes = [0u8; X25519_LEN];
        bytes.copy_from_slice(src);
        Ok(X25519Private(StaticSecret::from(bytes)))
    }
}

/// A zero-width type used to identify the X25519 key exchange system.
pub struct X25519;

/// The implementation of the X25519 key exchange system.
impl Kex for X25519 {
    type Public = X25519Public;
    type Private = X25519Private;
    type EphemeralPrivate = X25519EphemeralPrivate;
    type Secret = X25519Secret;
}

#[cfg(test)]
mod test {
    use super::*;
    use mc_util_serial::{deserialize, serialize};

    #[test]
    fn test_repr_bytes_size_vs_constant() {
        assert_eq!(<X25519Public as ReprBytes>::Size::USIZE, X25519_LEN);
    }

    #[test]
    fn test_pubkey_serialize() {
        let pubkey = X25519Public::try_from(&[0x55u8; 32] as &[u8]).expect("Could not load pubkey");
        let serialized = serialize(&pubkey).expect("Could not serialize pubkey");
        let deserialized: X25519Public =
            deserialize(&serialized).expect("Could not deserialize pubkey");
        assert_eq!(deserialized, pubkey);
    }

    #[test]
    fn test_privkey_serialize() {
        let privkey: X25519Private =
            X25519Private::try_from(&[0x55u8; 32] as &[u8]).expect("Could not load privkey.");
        let serialized = serialize(&privkey).expect("Could not serialize privkey.");
        let deserialized: X25519Private =
            deserialize(&serialized).expect("Could not deserialize privkey");

        let pubkey: X25519Public = X25519Public::from(&privkey);
        let deserialize_pubkey: X25519Public = X25519Public::from(&deserialized);
        assert_eq!(pubkey, deserialize_pubkey);
    }
}
