// Copyright (c) 2018-2021 The MobileCoin Foundation

//! A set of static ZWTs designed to aid the handling of noise protocol strings.

use crate::patterns::{HandshakeIX, HandshakeNX, HandshakePattern};
use aead::AeadMut;
use aes_gcm::Aes256Gcm;
use core::marker::PhantomData;
use digest::{FixedOutput, Update};
use displaydoc::Display;
use mc_crypto_keys::{Kex, X25519};
use serde::{Deserialize, Serialize};
use sha2::Sha512;
use subtle::ConstantTimeEq;

/// An enumeration of errors which can be generated while parsing a protocol
/// name string.
#[derive(
    Clone, Copy, Debug, Deserialize, Display, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
)]
pub enum ProtocolNameError {
    /// The string given does not match the type in question
    Unknown,
}

/// A parsed noise protocol name.
///
/// This is a template, meant to provide a static-compilation friendly
/// implementation of the protocol names described in
/// [section 8](http://noiseprotocol.org/noise.html#protocol-names-and-modifiers)
/// of the specification.
#[derive(Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ProtocolName<Handshake, KexAlgo, Cipher, DigestType>
where
    Handshake: HandshakePattern,
    KexAlgo: Kex,
    Cipher: AeadMut,
    DigestType: Default + Update + FixedOutput,
{
    _pattern: PhantomData<fn() -> Handshake>,
    _kex: PhantomData<fn() -> KexAlgo>,
    _cipher: PhantomData<fn() -> Cipher>,
    _digest: PhantomData<fn() -> DigestType>,
}

impl<Handshake, KexAlgo, Cipher, DigestType> Clone
    for ProtocolName<Handshake, KexAlgo, Cipher, DigestType>
where
    Handshake: HandshakePattern,
    KexAlgo: Kex,
    Cipher: AeadMut,
    DigestType: Default + Update + FixedOutput,
{
    fn clone(&self) -> Self {
        Self {
            _pattern: PhantomData::default(),
            _kex: PhantomData::default(),
            _cipher: PhantomData::default(),
            _digest: PhantomData::default(),
        }
    }
}

impl<Handshake, KexAlgo, Cipher, DigestType> Default
    for ProtocolName<Handshake, KexAlgo, Cipher, DigestType>
where
    Handshake: HandshakePattern,
    KexAlgo: Kex,
    Cipher: AeadMut,
    DigestType: Default + Update + FixedOutput,
{
    fn default() -> Self {
        Self {
            _pattern: PhantomData::default(),
            _kex: PhantomData::default(),
            _cipher: PhantomData::default(),
            _digest: PhantomData::default(),
        }
    }
}

macro_rules! impl_protocol_names {
    ($($name:literal, $handshake:ty, $kex:ty, $cipher:ty, $hash:ty;)*) => {$(
        /// A specialized implementation of FromStr to support created the
        /// proper static type from the given protocol string.
        impl core::str::FromStr for ProtocolName<$handshake, $kex, $cipher, $hash> {
            type Err = ProtocolNameError;

            fn from_str(s: &str) -> Result<Self, ProtocolNameError> {
                #[allow(clippy::string_lit_as_bytes)]
                let name_bytes = $name.as_bytes();

                if name_bytes.ct_eq(s.as_bytes()).unwrap_u8() != 0 {
                    Ok(Self::default())
                } else {
                    Err(ProtocolNameError::Unknown)
                }
            }
        }

        /// Retrieve the string value of the given ProtocolName.
        impl AsRef<str> for ProtocolName<$handshake, $kex, $cipher, $hash> {
            fn as_ref(&self) -> &'static str {
                $name
            }
        }

        /// Retrieve the bytes which represent the protocol name.
        impl AsRef<[u8]> for ProtocolName<$handshake, $kex, $cipher, $hash> {
            fn as_ref(&self) -> &[u8] {
                #[allow(clippy::string_lit_as_bytes)]
                $name.as_bytes()
            }
        }
    )*}
}

// We prefix our own extension protocols with "McNoise" to distinguish them
// from those in the framework specification.
impl_protocol_names! {
    "Noise_IX_25519_AESGCM_SHA512", HandshakeIX, X25519, Aes256Gcm, Sha512;
    "Noise_NX_25519_AESGCM_SHA512", HandshakeNX, X25519, Aes256Gcm, Sha512;
}

#[cfg(test)]
mod test {
    use super::*;

    use aes_gcm::Aes256Gcm;
    use core::str::FromStr;

    #[test]
    fn mobilecoin_ix_25519_aesgcm_sha512_from_str() {
        let name = "Noise_IX_25519_AESGCM_SHA512";
        let parsed_name = ProtocolName::<
            HandshakeIX,
            X25519,    // Kex
            Aes256Gcm, // AEAD
            Sha512,    // Digest
        >::from_str(name)
        .unwrap_or_else(|_| panic!("Could not parse '{}'", name));
        let new_name: &str = parsed_name.as_ref();
        assert_eq!(name, new_name);
    }

    #[test]
    fn mobilecoin_nx_25519_aesgcm_sha512_from_str() {
        let name = "Noise_NX_25519_AESGCM_SHA512";
        let parsed_name = ProtocolName::<
            HandshakeNX,
            X25519,    // Kex
            Aes256Gcm, // AEAD
            Sha512,    // Digest
        >::from_str(name)
        .unwrap_or_else(|_| panic!("Could not parse '{}'", name));
        let new_name: &str = parsed_name.as_ref();
        assert_eq!(name, new_name);
    }

    #[test]
    #[should_panic(
        expected = "Could not parse 'McNoise_XX_25519_CHACHA_SHA256': The string given does not match the type in question"
    )]
    fn bogus_str() {
        let name = "McNoise_XX_25519_CHACHA_SHA256";
        let parsed_name = ProtocolName::<
            HandshakeNX,
            X25519,    // Kex
            Aes256Gcm, // AEAD
            Sha512,    // Digest
        >::from_str(name)
        .unwrap_or_else(|e| panic!("Could not parse '{}': {}", name, e));
        let new_name: &str = parsed_name.as_ref();
        assert_eq!(name, new_name);
    }
}
