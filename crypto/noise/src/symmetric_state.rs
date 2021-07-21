// Copyright (c) 2018-2021 The MobileCoin Foundation

//! The Noise Framework's SymmetricState object.

use alloc::vec;

use crate::{
    cipher_state::{CipherError, CipherState, NoiseCipher},
    handshake_hash::HandshakeHash,
    patterns::HandshakePattern,
    protocol_name::ProtocolName,
};
use aead::{AeadMut, NewAead};
use alloc::vec::Vec;
use core::{convert::TryInto, marker::PhantomData};
use digest::{BlockInput, FixedOutput, Reset, Update};
use displaydoc::Display;
use generic_array::typenum::Unsigned;
use hkdf::{Hkdf, InvalidLength};
use mc_crypto_keys::{Kex, KexPublic, ReprBytes};
use secrecy::{ExposeSecret, SecretVec};
use serde::{Deserialize, Serialize};

#[derive(
    Copy, Clone, Debug, Deserialize, Display, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
)]
pub enum SymmetricError {
    /// Cipher state error: {0}
    Cipher(CipherError),
    /// Tried to expand too many keys
    KdfExpansion,
}

impl From<CipherError> for SymmetricError {
    fn from(src: CipherError) -> Self {
        SymmetricError::Cipher(src)
    }
}

impl From<InvalidLength> for SymmetricError {
    fn from(_src: InvalidLength) -> Self {
        SymmetricError::KdfExpansion
    }
}

/// The SymmetricState object, defined in
/// [section 5.2](http://noiseprotocol.org/noise.html#the-symmetricstate-object)
/// of the specification.
pub struct SymmetricState<KexAlgo, Cipher, DigestType>
where
    KexAlgo: Kex,
    Cipher: AeadMut + NewAead + NoiseCipher + Sized,
    DigestType: BlockInput + Clone + Default + FixedOutput + Update + Reset,
{
    hash: HandshakeHash<DigestType>,
    chaining_key: SecretVec<u8>,
    cipher_state: CipherState<Cipher>,
    _kex: PhantomData<fn() -> KexAlgo>,
}

impl<Handshake, KexAlgo, Cipher, DigestType>
    From<ProtocolName<Handshake, KexAlgo, Cipher, DigestType>>
    for SymmetricState<KexAlgo, Cipher, DigestType>
where
    Handshake: HandshakePattern,
    KexAlgo: Kex,
    Cipher: AeadMut + NewAead + NoiseCipher + Sized,
    DigestType: BlockInput + Clone + Default + FixedOutput + Update + Reset,
    ProtocolName<Handshake, KexAlgo, Cipher, DigestType>: AsRef<str>,
{
    /// The noise protocol `InitializeSymmetric()` operation.
    ///
    /// Using the ProtocolName ZWT, construct a handshake hash, chaining key,
    /// and "unkeyed" cipher state.
    fn from(protocol_name: ProtocolName<Handshake, KexAlgo, Cipher, DigestType>) -> Self {
        let hash = HandshakeHash::from(protocol_name);
        let chaining_key = SecretVec::new(Vec::from(hash.as_ref()));
        let cipher_state = CipherState::default();

        Self {
            hash,
            chaining_key,
            cipher_state,
            _kex: PhantomData::default(),
        }
    }
}

impl<KexAlgo, Cipher, DigestType> SymmetricState<KexAlgo, Cipher, DigestType>
where
    KexAlgo: Kex,
    Cipher: AeadMut + NewAead + NoiseCipher + Sized,
    DigestType: BlockInput + Clone + Default + FixedOutput + Update + Reset,
{
    /// Retrieve the expected size (in bytes) of a public key to read.
    ///
    /// This is an extension to the Noise protocol to support key exchange
    /// systems with key lengths other than 32 bytes.
    pub fn key_len(&self) -> usize {
        if self.cipher_state.has_key() {
            Cipher::ciphertext_len(KexAlgo::Public::size())
        } else {
            KexAlgo::Public::size()
        }
    }

    /// The noise protocol `MixKey()` operation.
    ///
    /// Runs a round of HKDF using the existing chaining key as the salt, and
    /// the given Kex secret as the IKM, resulting in "two" keys: a new
    /// chaining key, for future invocations, and a new cipher key, which is
    /// applied to our internal cipher state.
    pub fn mix_key(&mut self, input_key_material: KexAlgo::Secret) -> Result<(), SymmetricError> {
        let kdf = Hkdf::<DigestType>::new(
            Some(self.chaining_key.expose_secret().as_slice()),
            input_key_material.as_ref(),
        );

        // expand chaining_key_len + key_len bytes of secret material
        let chaining_key_len = DigestType::OutputSize::to_usize();
        let key_len = Cipher::KeySize::to_usize();
        let mut output = vec![0u8; chaining_key_len * 2];
        kdf.expand(&[], &mut output)?;

        // wrap material material into a secretvec so it's zeroed.
        let output = SecretVec::new(output);
        let output_slice = output.expose_secret().as_slice();

        // update cipher state
        self.cipher_state.initialize_key(Some(Vec::from(
            &output_slice[chaining_key_len..chaining_key_len + key_len],
        )))?;

        // save chaining key
        self.chaining_key = SecretVec::new(Vec::from(&output_slice[..chaining_key_len]));
        Ok(())
    }

    /// The noise protocol `MixHash()` operation.
    ///
    /// Updates our hash to reflect a new hash of itself and the provided
    /// data.
    pub fn mix_hash(&mut self, data: &[u8]) {
        self.hash += data;
    }

    /// The noise framework `MixKeyAndHash()` operation.
    ///
    /// Runs a round of HKDF using the existing chaining key as the salt, and
    /// the given Kex secret as the IKM, resulting in "three" keys: a new
    /// chaining key, for future invocations, new hash data, which is mixed
    /// into our existing handshake hash, and a new cipher key, which is
    /// applied to our internal cipher state.
    ///
    /// MobileCoin does not currently utilize pre-shared keys anywhere, so
    /// this is unused,
    #[allow(unused)]
    pub fn mix_key_and_hash(
        &mut self,
        input_key_material: KexAlgo::Secret,
    ) -> Result<(), SymmetricError> {
        let chaining_key_len = DigestType::OutputSize::to_usize();
        let hash_len = DigestType::OutputSize::to_usize();
        let key_len = Cipher::KeySize::to_usize();
        let mut output = vec![0u8; chaining_key_len + hash_len + key_len];

        let kdf = Hkdf::<DigestType>::new(
            Some(self.chaining_key.expose_secret().as_slice()),
            input_key_material.as_ref(),
        );
        kdf.expand(&[], &mut output)?;

        // wrap it into a secretvec so it'z zeroed.
        let output = SecretVec::new(output);
        let output_slice = output.expose_secret().as_slice();

        // update hash
        self.mix_hash(&output_slice[chaining_key_len..(chaining_key_len + hash_len)]);

        // update cipher state
        self.cipher_state.initialize_key(Some(Vec::from(
            &output_slice[(chaining_key_len + hash_len)..(chaining_key_len + hash_len + key_len)],
        )))?;

        // save chaining key
        self.chaining_key = SecretVec::new(Vec::from(&output_slice[..chaining_key_len]));
        Ok(())
    }

    /// The noise framework's `EncryptAndHash` operation.
    ///
    /// Using the handshake hash as associated data, maybe encrypt the given
    /// plaintext (if a key has been set on our inner cipher state), then
    /// update the handshake hash using the ciphertext output.
    pub fn encrypt_and_hash(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, SymmetricError> {
        match self
            .cipher_state
            .encrypt_with_ad(self.hash.as_ref(), plaintext)
        {
            Ok(ciphertext) => {
                self.hash += &ciphertext;
                Ok(ciphertext)
            }
            Err(CipherError::NoKey) => {
                self.hash += plaintext;
                Ok(Vec::from(plaintext))
            }
            Err(e) => Err(e.into()),
        }
    }

    /// The noise framework's `EncryptAndHash` operation.
    ///
    /// Using the current handshake hash as associated data, maybe decrypt the
    /// given "ciphertext" (assuming a key has been set on our innner cipher
    /// state), then update the handshake hash with the original ciphertext.
    pub fn decrypt_and_hash(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, SymmetricError> {
        match self
            .cipher_state
            .decrypt_with_ad(self.hash.as_ref(), ciphertext)
        {
            Ok(plaintext) => {
                self.hash += ciphertext;
                Ok(plaintext)
            }
            Err(CipherError::NoKey) => {
                self.hash += ciphertext;
                Ok(Vec::from(ciphertext))
            }
            Err(e) => Err(e.into()),
        }
    }
}

/// The results of a successful handshake.
///
/// This is the combined results of both `SymmetricState::Split()`
/// and `SymmetricState::GetHandshakeHash()` from the specification. They
/// are combined to ensure the user cannot contravene the specification's
/// warning to call `GetHandshakeHash()` only after calling `Split()`.
pub struct SymmetricOutput<Cipher, PubKey>
where
    Cipher: AeadMut + NewAead + NoiseCipher + Sized,
    PubKey: KexPublic,
{
    pub initiator_cipher: CipherState<Cipher>,
    pub responder_cipher: CipherState<Cipher>,
    pub channel_binding: Vec<u8>,
    pub remote_identity: Option<PubKey>,
}

impl<Cipher, PubKey> SymmetricOutput<Cipher, PubKey>
where
    Cipher: AeadMut + NewAead + NoiseCipher + Sized,
    PubKey: KexPublic,
{
    /// Bundle the given data into a handshake output structure.
    pub fn new(
        initiator_cipher: CipherState<Cipher>,
        responder_cipher: CipherState<Cipher>,
        channel_binding: Vec<u8>,
        remote_identity: Option<PubKey>,
    ) -> Self {
        Self {
            initiator_cipher,
            responder_cipher,
            channel_binding,
            remote_identity,
        }
    }
}

/// The noise framework's `Split()` and `GetHandshakeHash()` implementation.
///
/// Consumes the symmetric state, runs a round of KDF to derive keys for use
/// in new cipherstate objects, one used to handle messages from the initiator,
/// the other to handle messages from the responder, and the final handshake
/// hash, used by application-layer channel binding (i.e. as a "session ID").
impl<KexAlgo, Cipher, DigestType> TryInto<SymmetricOutput<Cipher, KexAlgo::Public>>
    for SymmetricState<KexAlgo, Cipher, DigestType>
where
    KexAlgo: Kex,
    Cipher: AeadMut + NewAead + NoiseCipher + Sized,
    DigestType: BlockInput + Clone + Default + FixedOutput + Update + Reset,
{
    type Error = SymmetricError;

    fn try_into(self) -> Result<SymmetricOutput<Cipher, KexAlgo::Public>, SymmetricError> {
        let kdf = Hkdf::<DigestType>::new(Some(self.chaining_key.expose_secret().as_slice()), &[]);

        let key_len = Cipher::KeySize::to_usize();
        let digest_len = DigestType::OutputSize::to_usize();
        assert!(digest_len >= key_len);

        let mut output = vec![0u8; digest_len * 2];
        kdf.expand(&[], &mut output)?;

        // wrap key material in a secretvec to ensure it's zeroed
        let output = SecretVec::new(output);
        let output_slice = output.expose_secret().as_slice();

        // initiator-to-responder
        let mut initiator_cipher = CipherState::default();
        initiator_cipher.initialize_key(Some(Vec::from(&output_slice[..key_len])))?;

        // responder-to-initiator
        let mut responder_cipher = CipherState::default();
        let responder_start = digest_len;
        let responder_end = responder_start + key_len;
        responder_cipher.initialize_key(Some(Vec::from(
            &output_slice[responder_start..responder_end],
        )))?;

        Ok(SymmetricOutput::new(
            initiator_cipher,
            responder_cipher,
            self.hash.into(),
            None,
        ))
    }
}
