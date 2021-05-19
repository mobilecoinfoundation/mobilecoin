// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Helper structure for handling AKE message transcripts (hashes)

use crate::{patterns::HandshakePattern, protocol_name::ProtocolName};
use aead::AeadMut;
use alloc::vec::Vec;
use core::{
    marker::PhantomData,
    ops::{Add, AddAssign},
};
use digest::{FixedOutput, Update};
use generic_array::{typenum::Unsigned, GenericArray};
use mc_crypto_keys::Kex;
use secrecy::{ExposeSecret, SecretVec};
use zeroize::Zeroize;

/// This helper type is designed to encapsulate the hash/session ID, built
/// from AKE messages.
///
/// This type is not specifically defined by the noise framework, but the
/// `h = HASH(h || data)` construction happens in a lot of places. This type,
/// therefore, is the `h`.
pub struct HandshakeHash<DigestType: Default + FixedOutput + Update> {
    hash: SecretVec<u8>,
    _digest: PhantomData<fn() -> DigestType>,
}

/// Handshake hashes can be exposed as a byte slice to facilitate chaining
/// key initialization.
///
/// Specifically this exists for the `ck = h` step of
/// `SymmetricState::InitializedSymmetric`, defined at
/// [section 5.2](http://noiseprotocol.org/noise.html#the-symmetricstate-object)
/// of the specification.
impl<DigestType: Default + FixedOutput + Update> AsRef<[u8]> for HandshakeHash<DigestType> {
    fn as_ref(&self) -> &[u8] {
        self.hash.expose_secret().as_slice()
    }
}

/// New data can be mixed with the handshake hash via addition.
impl<'data, DigestType: Default + FixedOutput + Update> Add<&'data [u8]>
    for HandshakeHash<DigestType>
{
    type Output = Self;

    fn add(self, data: &[u8]) -> Self {
        let mut hasher = DigestType::default();
        hasher.update(self.hash.expose_secret().as_slice());
        hasher.update(data);
        let mut result = hasher.finalize_fixed();
        let mut target = self;
        target.hash = SecretVec::new(result.to_vec());
        result.zeroize();
        target
    }
}

/// New data can be mixed with the handshake hash via add-assignment.
impl<'data, DigestType: Default + FixedOutput + Update> AddAssign<&'data [u8]>
    for HandshakeHash<DigestType>
{
    fn add_assign(&mut self, data: &[u8]) {
        let mut hasher = DigestType::default();
        hasher.update(self.hash.expose_secret().as_slice());
        hasher.update(data);
        let mut result = hasher.finalize_fixed();
        self.hash = SecretVec::new(result.to_vec());
        result.zeroize();
    }
}

/// A HandshakeHash can be initialized from a protocol name.
///
/// This initialization is the procedure to initialize `h`, defined in
/// `SymmetricState::InitializeSymmetric()` at
/// [section 5.2](http://noiseprotocol.org/noise.html#the-symmetricstate-object),
/// of the spec.
impl<Handshake, KexAlgo, Cipher, DigestType>
    From<ProtocolName<Handshake, KexAlgo, Cipher, DigestType>> for HandshakeHash<DigestType>
where
    Handshake: HandshakePattern,
    KexAlgo: Kex,
    Cipher: AeadMut,
    DigestType: Default + FixedOutput + Update,
    ProtocolName<Handshake, KexAlgo, Cipher, DigestType>: AsRef<str>,
{
    fn from(
        src: ProtocolName<Handshake, KexAlgo, Cipher, DigestType>,
    ) -> HandshakeHash<DigestType> {
        let proto = src.as_ref().as_bytes();
        let proto_len = proto.len();
        let mut result = if proto_len <= DigestType::OutputSize::to_usize() {
            let mut result = GenericArray::default();
            result[..proto_len].copy_from_slice(proto);
            result
        } else {
            let mut hasher = DigestType::default();
            hasher.update(proto);
            hasher.finalize_fixed()
        };
        let hash = SecretVec::new(result.to_vec());
        result.zeroize();

        Self {
            hash,
            _digest: PhantomData::default(),
        }
    }
}

/// A HandshakeHash may be consumed to reveal the result.
impl<DigestType: Default + FixedOutput + Update> From<HandshakeHash<DigestType>> for Vec<u8> {
    fn from(src: HandshakeHash<DigestType>) -> Vec<u8> {
        src.hash.expose_secret().clone()
    }
}

#[cfg(test)]
mod test {
    extern crate std;

    use super::*;
    use crate::{patterns::HandshakeIX, protocol_name::ProtocolName};
    use aes_gcm::Aes256Gcm;
    use mc_crypto_keys::X25519;
    use sha2::Sha512;

    //  (echo -en
    // "Noise_IX_25519_AESGCM_SHA512\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
    // 0\0\0\0\0\0\0\0\0\0\0\0\0"; \   echo -n "data to be mixed") | sha512sum
    // -b
    const OUTPUT: [u8; 64] = [
        0x29, 0x1b, 0x30, 0x52, 0x18, 0xe3, 0xc1, 0x0f, 0x1c, 0xf5, 0x34, 0x05, 0xc6, 0x67, 0x8c,
        0x81, 0xc0, 0xf6, 0x7a, 0x94, 0xd9, 0xdf, 0x84, 0x06, 0x14, 0x25, 0x33, 0x63, 0x9e, 0x21,
        0xb6, 0x8e, 0xe7, 0x81, 0x51, 0xee, 0x78, 0x47, 0x83, 0xed, 0xc6, 0x9f, 0x11, 0xb7, 0xc4,
        0x50, 0x2a, 0xd9, 0x3d, 0x40, 0xbb, 0x5f, 0x52, 0x23, 0x3c, 0x7e, 0x52, 0x35, 0x3a, 0x92,
        0xeb, 0x1a, 0x28, 0xb1,
    ];

    #[test]
    fn add() {
        let protocol_name = ProtocolName::<HandshakeIX, X25519, Aes256Gcm, Sha512>::default();
        let hash = HandshakeHash::from(protocol_name);
        let hash2 = hash + b"data to be mixed";
        let output: Vec<u8> = hash2.into();
        assert_eq!(&output[..], &OUTPUT[..]);
    }

    #[test]
    fn add_assign() {
        let protocol_name = ProtocolName::<HandshakeIX, X25519, Aes256Gcm, Sha512>::default();
        let mut hash = HandshakeHash::from(protocol_name);
        hash += b"data to be mixed";
        let output: Vec<u8> = hash.into();
        assert_eq!(&output[..], &OUTPUT[..]);
    }
}
