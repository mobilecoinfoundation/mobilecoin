// Copyright (c) 2018-2022 The MobileCoin Foundation

//! This module implements the common keys traits for the Ed25519 digital
//! signature scheme.

use crate::{
    DigestSigner, DigestVerifier, DistinguishedEncoding, KeyError, PrivateKey, PublicKey,
    SignatureEncoding, SignatureError, Signer, Verifier,
};
use digest::{
    generic_array::typenum::{U32, U64},
    Digest,
};
use ed25519::{Signature, SignatureBytes};
use ed25519_dalek::{
    SecretKey, Signature as DalekSignature, SigningKey, VerifyingKey as DalekPublicKey,
    PUBLIC_KEY_LENGTH,
};
use mc_crypto_digestible::{DigestTranscript, Digestible};
use mc_util_from_random::FromRandom;
use mc_util_repr_bytes::{
    derive_core_cmp_from_as_ref, derive_debug_and_display_hex_from_as_ref,
    derive_repr_bytes_from_as_ref_and_try_from,
};
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroize;

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

#[cfg(feature = "alloc")]
use mc_util_repr_bytes::derive_into_vec_from_repr_bytes;

#[cfg(feature = "prost")]
use mc_util_repr_bytes::derive_prost_message_from_repr_bytes;

#[cfg(feature = "serde")]
use serde::{self as serde, Deserialize, Serialize};

#[cfg(feature = "serde")]
use mc_util_serial::BigArray;

// ASN.1 DER Signature Bytes -- this is a set of nested TLVs describing
// a detached signature -- use https://lapo.it/asn1js/
//
// I'm not really sure if this is the correct way to do this, but I'm using
// https://tools.ietf.org/html/rfc5912 as a reference. Unfortunately, digital
// signatures are representing by a structure that is nearly identical to
// a SubjectPublicKeyInfo structure (this is 64 bytes, to accommodate the
// concatenation of the "S" signature and "R" nonce).
//
// Signature       ::=     SEQUENCE {
//     signatureAlgorithm   AlgorithmIdentifier
//                              { SIGNATURE-ALGORITHM, {...}},
//     signature            BIT STRING,
//     certs            [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL }
//
// AlgorithmIdentifier{ALGORITHM-TYPE, ALGORITHM-TYPE:AlgorithmSet} ::=
//         SEQUENCE {
//             algorithm   ALGORITHM-TYPE.&id({AlgorithmSet}),
//             parameters  ALGORITHM-TYPE.
//                    &Params({AlgorithmSet}{@algorithm}) OPTIONAL
//         }
//
//   SEQUENCE(30), Length = 4A               -- T,L - Signature
//     SEQUENCE(30), Length = 05             -- T,L -
//        OBJECT IDENTIFIER(06), Length = 03  -- T,L,V
//           curveEd25519(1.3.101.112 = 2B 65 70)
//     BIT STRING(03), Length = 41            -- T,L
//        paddingBits = 00 (0x21 == 33, first byte is the number of padding bits
// to fill an octet)        actualKeyBitsGoesHere
const ED25519_SIG_DER_PREFIX: [u8; 12] = [
    0x30, 0x4A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x41, 0x00,
];

// In ASN.1 + DER's TLV, L is just the length of V, so we need to add 2 for
// the length of T and L themselves.
const ED25519_SIG_DER_LEN: usize = 0x02 + 0x4A;

static_assertions::const_assert!(ED25519_SIG_DER_LEN <= super::DER_MAX_LEN);

impl DistinguishedEncoding for Ed25519Signature {
    fn der_size() -> usize {
        ED25519_SIG_DER_LEN
    }

    fn try_from_der(src: &[u8]) -> Result<Self, KeyError> {
        if src.len() != ED25519_SIG_DER_LEN {
            return Err(KeyError::LengthMismatch(src.len(), ED25519_SIG_DER_LEN));
        }
        if src[6..9] != ED25519_SIG_DER_PREFIX[6..9] {
            return Err(KeyError::AlgorithmMismatch);
        }
        if src[..12] != ED25519_SIG_DER_PREFIX {
            return Err(KeyError::InvalidPublicKey);
        }
        Ok(Self(
            SignatureBytes::try_from(&src[12..]).map_err(|_e| KeyError::InternalError)?,
        ))
    }

    /// Serializes this object into a DER-encoded SubjectPublicKeyInfo structure
    fn to_der_slice<'a>(&self, buff: &'a mut [u8]) -> &'a [u8] {
        let data = self.to_bytes();
        buff[..ED25519_SIG_DER_LEN].iter_mut().for_each(|b| *b = 0);

        let prefix_len = ED25519_SIG_DER_PREFIX.len();
        buff[..prefix_len].copy_from_slice(&ED25519_SIG_DER_PREFIX);
        buff[prefix_len..ED25519_SIG_DER_LEN].copy_from_slice(&data[..]);
        &buff[..ED25519_SIG_DER_LEN]
    }
}

/// An Ed25519 public key.
#[derive(Copy, Clone, Default, Digestible)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Ed25519Public(DalekPublicKey);

impl AsRef<[u8]> for Ed25519Public {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl AsRef<[u8; PUBLIC_KEY_LENGTH]> for Ed25519Public {
    fn as_ref(&self) -> &[u8; PUBLIC_KEY_LENGTH] {
        self.0.as_bytes()
    }
}

impl TryFrom<&[u8]> for Ed25519Public {
    type Error = KeyError;

    fn try_from(src: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self(
            DalekPublicKey::try_from(src).map_err(|_e| KeyError::InvalidPublicKey)?,
        ))
    }
}

#[cfg(feature = "alloc")]
impl TryFrom<alloc::vec::Vec<u8>> for Ed25519Public {
    type Error = KeyError;

    fn try_from(src: alloc::vec::Vec<u8>) -> Result<Self, Self::Error> {
        src.as_slice().try_into()
    }
}

derive_core_cmp_from_as_ref!(Ed25519Public, [u8; PUBLIC_KEY_LENGTH]);
derive_debug_and_display_hex_from_as_ref!(Ed25519Public);
derive_repr_bytes_from_as_ref_and_try_from!(Ed25519Public, U32);

#[cfg(feature = "alloc")]
derive_into_vec_from_repr_bytes!(Ed25519Public);

#[cfg(feature = "prost")]
derive_prost_message_from_repr_bytes!(Ed25519Public);

// ASN.1 DER SubjectPublicKeyInfo Bytes -- this is a set of nested TLVs
// describing a pubkey -- use https://lapo.it/asn1js/
//
//   SEQUENCE(30), Length = 2a               -- T,L
//     SEQUENCE(30), Length = 05             -- T,L
//        OBJECT IDENTIFIER(06), Length = 03  -- T,L,V
//           curveEd25519(1.3.101.112 = 2B 65 70)
//     BIT STRING(03), Length = 21            -- T,L
//        paddingBits = 00 (0x21 == 33, first byte is the number of padding bits
// to fill an octet)        actualKeyBitsGoesHere
const ED25519_SPKI_DER_PREFIX: [u8; 12] = [
    0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x21, 0x00,
];

// In ASN.1 + DER's TLV, L is just the length of V, so we need to add 2 for
// the length of T and L themselves.
const ED25519_SPKI_DER_LEN: usize = 0x02 + 0x2A;

static_assertions::const_assert!(ED25519_SPKI_DER_LEN <= super::DER_MAX_LEN);

impl DistinguishedEncoding for Ed25519Public {
    fn der_size() -> usize {
        ED25519_SPKI_DER_LEN
    }

    fn try_from_der(src: &[u8]) -> Result<Self, KeyError> {
        if src.len() != ED25519_SPKI_DER_LEN {
            return Err(KeyError::LengthMismatch(src.len(), ED25519_SPKI_DER_LEN));
        }
        if src[6..9] != ED25519_SPKI_DER_PREFIX[6..9] {
            return Err(KeyError::AlgorithmMismatch);
        }
        if src[..12] != ED25519_SPKI_DER_PREFIX {
            return Err(KeyError::InvalidPublicKey);
        }
        Self::try_from(&src[12..]).map_err(|_e| KeyError::InternalError)
    }

    /// Serializes this object into a DER-encoded SubjectPublicKeyInfo structure
    fn to_der_slice<'a>(&self, buff: &'a mut [u8]) -> &'a [u8] {
        let data = self.as_ref();
        buff[..ED25519_SPKI_DER_LEN].iter_mut().for_each(|b| *b = 0);

        let prefix_len = ED25519_SPKI_DER_PREFIX.len();
        buff[..prefix_len].copy_from_slice(&ED25519_SPKI_DER_PREFIX);
        buff[prefix_len..ED25519_SPKI_DER_LEN].copy_from_slice(data);
        &buff[..ED25519_SPKI_DER_LEN]
    }
}

impl<D: Digest<OutputSize = U64>> DigestVerifier<D, Ed25519Signature> for Ed25519Public {
    fn verify_digest(&self, digest: D, signature: &Ed25519Signature) -> Result<(), SignatureError> {
        let sig =
            DalekSignature::try_from(&signature.to_bytes()).map_err(|_e| SignatureError::new())?;
        self.0
            .verify_prehashed(digest, None, &sig)
            .map_err(|_e| SignatureError::new())
    }
}

impl From<&Ed25519Private> for Ed25519Public {
    fn from(src: &Ed25519Private) -> Self {
        let signing_key = SigningKey::from(&src.0);
        Self(DalekPublicKey::from(&signing_key))
    }
}

impl PublicKey for Ed25519Public {}

impl Verifier<Ed25519Signature> for Ed25519Public {
    fn verify(&self, message: &[u8], signature: &Ed25519Signature) -> Result<(), SignatureError> {
        let sig =
            DalekSignature::try_from(&signature.to_bytes()).map_err(|_e| SignatureError::new())?;
        self.0
            .verify_strict(message, &sig)
            .map_err(|_e| SignatureError::new())
    }
}

/// An Ed25519 private key
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Ed25519Private(SecretKey);

impl AsRef<[u8]> for Ed25519Private {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl core::fmt::Debug for Ed25519Private {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(
            f,
            "Ed25519Private for pubkey: {:?}",
            Ed25519Public::from(self)
        )
    }
}

// ASN.1 DER PrivateKeyInfo Bytes -- this is a set of nested TLVs
// describing a private key -- use https://lapo.it/asn1js/
//
//   SEQUENCE(30), Length = 0x2a                  -- T,L
//     INTEGER(0)
//     SEQUENCE(30), Length = 0x05                -- T,L
//        OBJECT IDENTIFIER(06), Length = 0x03    -- T,L,V
//           curveEd25519(1.3.101.112 = 2B 65 70)
//     OCTET STRING(04), Length = 0x22            -- T,L
//        OCTET STRING(04), Length = 0x20         -- T,L,V
//           actualKeyBytesGoHere
const ED25519_PKI_DER_PREFIX: [u8; 16] = [
    0x30, 0x2E, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];

const ED25519_PKI_DER_LEN: usize = 0x02 + 0x2E;

static_assertions::const_assert!(ED25519_PKI_DER_LEN <= super::DER_MAX_LEN);

impl DistinguishedEncoding for Ed25519Private {
    fn der_size() -> usize {
        ED25519_PKI_DER_LEN
    }

    fn try_from_der(src: &[u8]) -> Result<Self, KeyError> {
        if src.len() != ED25519_PKI_DER_LEN {
            return Err(KeyError::LengthMismatch(src.len(), ED25519_PKI_DER_LEN));
        }
        if src[9..12] != ED25519_PKI_DER_PREFIX[9..12] {
            return Err(KeyError::AlgorithmMismatch);
        }
        let prefix_len = ED25519_PKI_DER_PREFIX.len();
        if src[..prefix_len] != ED25519_PKI_DER_PREFIX {
            return Err(KeyError::InvalidPrivateKey);
        }
        Self::try_from(&src[prefix_len..]).map_err(|_err| KeyError::InternalError)
    }

    fn to_der_slice<'a>(&self, buff: &'a mut [u8]) -> &'a [u8] {
        let mut key = self.0;
        buff[..ED25519_PKI_DER_LEN].iter_mut().for_each(|b| *b = 0);

        let prefix_len = ED25519_PKI_DER_PREFIX.len();
        buff[..prefix_len].copy_from_slice(&ED25519_PKI_DER_PREFIX);
        buff[prefix_len..ED25519_PKI_DER_LEN].copy_from_slice(&key);
        key.zeroize();
        &buff[..ED25519_PKI_DER_LEN]
    }
}

impl PrivateKey for Ed25519Private {
    type Public = Ed25519Public;
}

impl FromRandom for Ed25519Private {
    fn from_random<R: CryptoRng + RngCore>(csprng: &mut R) -> Self {
        let signing_key = SigningKey::generate(csprng);
        Self(signing_key.to_bytes())
    }
}

impl<'bytes> TryFrom<&'bytes [u8]> for Ed25519Private {
    type Error = SignatureError;

    fn try_from(src: &[u8]) -> Result<Ed25519Private, Self::Error> {
        let secret_key = SecretKey::try_from(src).map_err(|_e| SignatureError::new())?;
        Ok(Self(secret_key))
    }
}

#[cfg(feature = "alloc")]
impl TryFrom<alloc::vec::Vec<u8>> for Ed25519Private {
    type Error = SignatureError;

    fn try_from(src: alloc::vec::Vec<u8>) -> Result<Self, Self::Error> {
        src.as_slice().try_into()
    }
}

#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Ed25519Pair(SigningKey);

impl Ed25519Pair {
    pub fn private_key(&self) -> Ed25519Private {
        let secret_key = self.0.to_bytes();
        Ed25519Private::try_from(secret_key.as_slice()).expect("Invalid private key in keypair")
    }

    pub fn public_key(&self) -> Ed25519Public {
        Ed25519Public(self.0.verifying_key())
    }
}

impl<D: Digest<OutputSize = U64>> DigestSigner<D, Ed25519Signature> for Ed25519Pair {
    fn try_sign_digest(&self, digest: D) -> Result<Ed25519Signature, SignatureError> {
        let sig = self
            .0
            .sign_prehashed(digest, None)?;
        Ok(Ed25519Signature::new(sig.to_bytes()))
    }
}

impl<D: Digest<OutputSize = U64>> DigestVerifier<D, Ed25519Signature> for Ed25519Pair {
    fn verify_digest(&self, digest: D, signature: &Ed25519Signature) -> Result<(), SignatureError> {
        let sig =
            DalekSignature::try_from(&signature.to_bytes()).map_err(|_e| SignatureError::new())?;
        self.0
            .verify_prehashed(digest, None, &sig)
            .map_err(|_e| SignatureError::new())
    }
}

impl From<Ed25519Private> for Ed25519Pair {
    fn from(src: Ed25519Private) -> Ed25519Pair {
        let signing_key = SigningKey::from_bytes(&src.0);
        Ed25519Pair(signing_key)
    }
}

impl FromRandom for Ed25519Pair {
    fn from_random<R: CryptoRng + RngCore>(csprng: &mut R) -> Self {
        Self(SigningKey::generate(csprng))
    }
}

impl Signer<Ed25519Signature> for Ed25519Pair {
    fn try_sign(&self, msg: &[u8]) -> Result<Ed25519Signature, SignatureError> {
        let sig = self.0.sign(msg);
        let signature = Signature::try_from(&sig.to_bytes()[..])?;
        let signature_bytes = signature.to_bytes();

        Ok(Ed25519Signature(signature_bytes))
    }
}

impl<'bytes> TryFrom<&'bytes [u8]> for Ed25519Pair {
    type Error = SignatureError;

    fn try_from(src: &[u8]) -> Result<Self, SignatureError> {
        Ok(Self(
            SigningKey::try_from(src).map_err(|_e| SignatureError::new())?,
        ))
    }
}

#[cfg(feature = "alloc")]
impl TryFrom<Vec<u8>> for Ed25519Pair {
    type Error = SignatureError;

    fn try_from(src: Vec<u8>) -> Result<Self, Self::Error> {
        src.as_slice().try_into()
    }
}

impl Verifier<Ed25519Signature> for Ed25519Pair {
    fn verify(&self, message: &[u8], signature: &Ed25519Signature) -> Result<(), SignatureError> {
        let sig =
            DalekSignature::try_from(&signature.to_bytes()).map_err(|_e| SignatureError::new())?;
        self.0
            .verifying_key()
            .verify_strict(message, &sig)
            .map_err(|_e| SignatureError::new())
    }
}

/// An Ed25519 signature.
#[derive(Copy, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Ed25519Signature(
    #[cfg_attr(feature = "serde", serde(with = "BigArray"))] SignatureBytes,
);

impl Ed25519Signature {
    /// Signature length in bytes.
    pub const BYTE_SIZE: usize = Signature::BYTE_SIZE;

    /// Create a new signature from a byte array
    pub fn new(bytes: [u8; Self::BYTE_SIZE]) -> Self {
        Self(bytes)
    }

    /// Return the inner byte array
    pub fn to_bytes(&self) -> [u8; Self::BYTE_SIZE] {
        self.0
    }
}

impl AsRef<[u8]> for Ed25519Signature {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl Digestible for Ed25519Signature {
    fn append_to_transcript<DT: DigestTranscript>(
        &self,
        context: &'static [u8],
        transcript: &mut DT,
    ) {
        transcript.append_primitive(context, b"ed25519-sig", self);
    }
}

// This is needed to implement prost::Message
impl Default for Ed25519Signature {
    fn default() -> Self {
        Self::new([0; Self::BYTE_SIZE])
    }
}

impl SignatureEncoding for Ed25519Signature {
    type Repr = [u8; Self::BYTE_SIZE];
}

impl From<Ed25519Signature> for [u8; 64] {
    fn from(src: Ed25519Signature) -> Self {
        src.0
    }
}

impl<'a> TryFrom<&'a [u8]> for Ed25519Signature {
    type Error = SignatureError;

    fn try_from(bytes: &'a [u8]) -> Result<Self, SignatureError> {
        Ok(Self(
            SignatureBytes::try_from(bytes).map_err(|_e| SignatureError::new())?,
        ))
    }
}

#[cfg(feature = "alloc")]
impl TryFrom<alloc::vec::Vec<u8>> for Ed25519Signature {
    type Error = SignatureError;

    fn try_from(src: alloc::vec::Vec<u8>) -> Result<Self, Self::Error> {
        src.as_slice().try_into()
    }
}

derive_repr_bytes_from_as_ref_and_try_from!(Ed25519Signature, U64);
derive_core_cmp_from_as_ref!(Ed25519Signature);
derive_debug_and_display_hex_from_as_ref!(Ed25519Signature);

#[cfg(feature = "prost")]
derive_prost_message_from_repr_bytes!(Ed25519Signature);

#[cfg(test)]
mod ed25519_tests {
    extern crate std;

    use super::*;
    use crate::{ReprBytes, Unsigned};
    use mc_crypto_digestible::Digestible;
    use mc_crypto_hashes::PseudoMerlin;
    use rand_core::SeedableRng;
    use rand_hc::Hc128Rng;
    use semver::{Version, VersionReq};
    use sha2::Sha512;
    use std::{
        eprintln,
        process::Command,
        string::{String, ToString},
    };
    use tempfile::TempDir;

    #[derive(Digestible)]
    struct YoloStruct {
        a: u64,
        b: Vec<u8>,
        c: u32,
    }

    // FIXME: use test vectors from the RFC.

    #[test]
    /// Test conversion to and from DER for Ed25519 signatures.
    fn test_der() {
        let mut rng = Hc128Rng::from_seed([4u8; 32]);
        let pair = Ed25519Pair::from_random(&mut rng);
        let test_data = [123u8, 100];

        let sig = pair.sign(&test_data);
        let der = sig.to_der();

        let sig2 = Ed25519Signature::try_from_der(&der).expect("failed parsing DER");
        assert_eq!(sig, sig2);
    }

    #[test]
    fn test_prehashed() {
        let mut rng = Hc128Rng::seed_from_u64(0);
        let pair = Ed25519Pair::from_random(&mut rng);
        let data = YoloStruct {
            a: 12345,
            b: alloc::vec![0x31, 0x33, 0x70],
            c: 54321,
        };

        let mut hasher = PseudoMerlin(Sha512::default());
        data.append_to_transcript(b"test", &mut hasher);
        let sig = pair
            .try_sign_digest(hasher.inner)
            .expect("Failed to sign digest");

        let mut hasher = PseudoMerlin(Sha512::default());
        data.append_to_transcript(b"test", &mut hasher);
        pair.verify_digest(hasher.inner, &sig)
            .expect("Failed to validate digest signature");
    }

    // Test that our (typenum) constant for the size of Ed25519 matches the
    // published constant in the dalek interface.
    #[test]
    fn test_key_len() {
        assert_eq!(
            ed25519_dalek::PUBLIC_KEY_LENGTH,
            <Ed25519Public as ReprBytes>::Size::USIZE
        );
        assert_eq!(
            ed25519_dalek::Signature::BYTE_SIZE,
            <Ed25519Signature as ReprBytes>::Size::USIZE
        );
    }

    ////
    // Validate ED25519_*_PREFIX against openssl implementation
    ////
    //
    // In review, Isis suggested that the 12 byte pattern ED25519_SIG_DER_PREFIX
    // should be validated by
    //
    // openssl genpkey -algorithm ed25519 -outform DER -out
    // /tmp/openssl-ed25519-keypair.der openssl ec -in
    // /tmp/openssl-ed25519-keypair.der -pubout -outform DER -out
    // /tmp/openssl-ed25519-pubkey.der
    //
    // and then inspection of final pubkey.der file
    //
    // I couldn't get this to work with openssl version OpenSSL 1.1.1b  26 Feb 2019,
    //
    // I tried some variations of this but in the end James and I determined that
    // this isn't expected to work exactly because openssl produces der
    // representations of public and private keys but not a detached signature.
    //
    // So we're skipping validation of ED25519_SIG_DER_PREFIX, but we're validating
    // the others

    // Run and log a command, panic if it fails
    // It is sad that std::process::Command doesn't have a flag like `bash -x`
    fn run_and_log(cmd: &str, args: &[&str]) {
        eprintln!("{} {}", cmd, args.join(" "));
        let result = Command::new(cmd)
            .args(args)
            .status()
            .expect("Could not start command");
        assert!(result.success())
    }

    // Print and check openssl version
    fn openssl_version() {
        run_and_log("openssl", &["version"]);

        let output = Command::new("openssl").args(["version"]).output().unwrap();
        let output_string = String::from_utf8(output.stdout).unwrap();
        let mut iter = output_string.split(' ');
        iter.next();
        let ver_string = iter.next().unwrap();
        eprintln!("version: {ver_string}");
        let ver = Version::parse(ver_string).unwrap();
        let ver_req = VersionReq::parse(">= 1.1").unwrap();
        assert!(ver_req.matches(&ver), "Version of openssl should be {ver_req}, install a better one and put it in path (or run in docker)");
    }

    // This test is only run in nightly, because it has a dependency on host version
    // of openssl
    #[test]
    #[ignore]
    fn validate_ed25519_priv_der_prefix() {
        let tempdir = TempDir::new().unwrap();
        let privder = tempdir
            .path()
            .join("openssl-ed25519-private.der")
            .to_str()
            .unwrap()
            .to_string();

        openssl_version();
        run_and_log(
            "openssl",
            &[
                "genpkey",
                "-algorithm",
                "ed25519",
                "-outform",
                "DER",
                "-out",
                &privder,
            ],
        );

        let bytes = std::fs::read(privder).expect("Unable to read openssl der file");

        assert_eq!(
            bytes[0..16],
            ED25519_PKI_DER_PREFIX,
            "Our prefix doesn't match openssl prefix:\n{:X?}\n{:X?}",
            &bytes[0..16],
            &ED25519_PKI_DER_PREFIX
        );
    }

    // This test is only run in nightly, because it has a dependency on host version
    // of openssl
    #[test]
    #[ignore]
    fn validate_ed25519_pub_der_prefix() {
        let tempdir = TempDir::new().unwrap();
        let privkey = tempdir
            .path()
            .join("openssl-ed25519-private.pem")
            .to_str()
            .unwrap()
            .to_string();
        let pubder = tempdir
            .path()
            .join("openssl-ed25519-pubkey.der")
            .to_str()
            .unwrap()
            .to_string();

        openssl_version();
        run_and_log(
            "openssl",
            &[
                "genpkey",
                "-algorithm",
                "ed25519",
                "-outform",
                "PEM",
                "-out",
                &privkey,
            ],
        );
        run_and_log(
            "openssl",
            &[
                "pkey", "-in", &privkey, "-inform", "PEM", "-pubout", "-outform", "DER", "-out",
                &pubder,
            ],
        );

        let bytes = std::fs::read(pubder).expect("Unable to read openssl der file");

        assert_eq!(
            bytes[0..12],
            ED25519_SPKI_DER_PREFIX,
            "Our prefix doesn't match openssl prefix:\n{:X?}\n{:X?}",
            &bytes[0..12],
            &ED25519_SPKI_DER_PREFIX
        );
    }
}
