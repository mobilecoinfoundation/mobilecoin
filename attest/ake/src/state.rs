// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Transducer states used by initiators and/or responders.

use crate::mealy::State;
use alloc::{string::String, vec::Vec};
use mc_crypto_keys::Kex;
use mc_crypto_noise::{CipherError, CipherState, HandshakeState, NoiseCipher, NoiseDigest};

/// The state of a node (initiator or responder) before anything has happened
/// yet.
pub struct Start {
    /// For responder's unique ID (hostname)
    pub(crate) responder_id: String,
}

impl Start {
    /// The Mealy machines all begin here, which contains (potentially unused)
    /// details about how to authenticate a participant.
    pub fn new(responder_id: String) -> Self {
        Self { responder_id }
    }
}

impl State for Start {}

/// The state after an NodeInit or ClientInit event has been added to
/// the Start state.
pub struct AuthPending<KexAlgo, Cipher, DigestAlgo>
where
    KexAlgo: Kex,
    Cipher: NoiseCipher,
    DigestAlgo: NoiseDigest,
{
    /// The handshake state
    pub(crate) state: HandshakeState<KexAlgo, Cipher, DigestAlgo>,
}

impl<KexAlgo, Cipher, DigestAlgo> State for AuthPending<KexAlgo, Cipher, DigestAlgo>
where
    KexAlgo: Kex,
    Cipher: NoiseCipher,
    DigestAlgo: NoiseDigest,
{
}

impl<KexAlgo, Cipher, DigestAlgo> AuthPending<KexAlgo, Cipher, DigestAlgo>
where
    KexAlgo: Kex,
    Cipher: NoiseCipher,
    DigestAlgo: NoiseDigest,
{
    pub(crate) fn new(state: HandshakeState<KexAlgo, Cipher, DigestAlgo>) -> Self {
        Self { state }
    }
}

/// The state after an auth response has been sent by a responder/received by
/// an initiator.
pub struct Ready<Cipher>
where
    Cipher: NoiseCipher,
{
    pub(crate) writer: CipherState<Cipher>,
    pub(crate) reader: CipherState<Cipher>,
    pub(crate) binding: Vec<u8>,
}

impl<Cipher> Ready<Cipher>
where
    Cipher: NoiseCipher,
{
    /// Retrieve the channel binding as a byte slice
    pub fn binding(&self) -> &[u8] {
        self.binding.as_ref()
    }

    /// Using the writer cipher, encrypt the given plaintext.
    pub fn encrypt(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CipherError> {
        self.writer.encrypt_with_ad(aad, plaintext)
    }

    /// Using the reader cipher, decrypt the provided ciphertext.
    pub fn decrypt(&mut self, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CipherError> {
        self.reader.decrypt_with_ad(aad, ciphertext)
    }

    /// Using the writer cipher, encrypt the given plaintext for the nonce.
    pub fn encrypt_with_nonce(&mut self, aad: &[u8], plaintext: &[u8], nonce: u64) -> Result<Vec<u8>, CipherError> {
        self.writer.set_nonce(nonce);
        self.encrypt(aad, plaintext)
    }

    /// Using the reader cipher, decrypt the provided ciphertext for the nonce.
    pub fn decrypt_with_nonce(&mut self, aad: &[u8], ciphertext: &[u8], nonce: u64) -> Result<Vec<u8>, CipherError> {
        self.reader.set_nonce(nonce);
        self.decrypt(aad, ciphertext)
    }
}

impl<Cipher> State for Ready<Cipher> where Cipher: NoiseCipher {}
