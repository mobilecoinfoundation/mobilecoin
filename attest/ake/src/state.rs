// Copyright (c) 2018-2020 MobileCoin Inc.

//! Transducer states used by initiators and/or responders.

use crate::mealy::State;
use aead::{AeadMut, NewAead};
use alloc::{string::String, vec::Vec};
use digest::{BlockInput, FixedOutput, Input, Reset};
use mc_attest_core::Measurement;
use mc_crypto_keys::Kex;
use mc_crypto_noise::{CipherError, CipherState, HandshakeState, NoiseCipher};

/// The state of a node (initiator or responder) before anything has happened
/// yet.
pub struct Start {
    /// For responder's unique ID (hostname)
    pub(crate) responder_id: String,

    /// The measurement we expect from authenticated counterparties
    pub(crate) expected_measurements: Vec<Measurement>,

    /// The product ID remote enclaves must be running
    pub(crate) expected_product_id: u16,

    /// The minimum security version remote enclaves must be running
    pub(crate) expected_minimum_svn: u16,

    /// Whether or not to allow remote enclaves to run in debug
    pub(crate) allow_debug: bool,

    /// An optional value used to inject specific trust anchors during validation (used for testing)
    pub(crate) trust_anchors: Option<Vec<String>>,
}

impl Start {
    /// The Mealy machines all begin here, which contains (potentially unused)
    /// details about how to authenticate a participant.
    pub fn new(
        responder_id: String,
        expected_measurements: Vec<Measurement>,
        expected_product_id: u16,
        expected_minimum_svn: u16,
        allow_debug: bool,
    ) -> Self {
        Self {
            responder_id,
            expected_measurements,
            expected_product_id,
            expected_minimum_svn,
            allow_debug,
            trust_anchors: None,
        }
    }
}

impl State for Start {}

/// The state after an NodeInit or ClientInit event has been added to
/// the Start state.
pub struct AuthPending<KexAlgo, Cipher, DigestType>
where
    KexAlgo: Kex,
    Cipher: AeadMut + NewAead + NoiseCipher + Sized,
    DigestType: BlockInput + Clone + Default + FixedOutput + Input + Reset,
{
    /// The handshake state
    pub(crate) state: HandshakeState<KexAlgo, Cipher, DigestType>,
    /// The enclave measurement we expect in the AuthResponse
    pub(crate) expected_measurements: Vec<Measurement>,
    /// The product ID remote enclaves must be running
    pub(crate) expected_product_id: u16,
    /// The minimum security version remote enclaves must be running
    pub(crate) expected_minimum_svn: u16,
    /// Whether or not to allow remote enclaves to run in debug
    pub(crate) allow_debug: bool,

    /// An optional value used to inject specific trust anchors during validation (used for testing)
    pub(crate) trust_anchors: Option<Vec<String>>,
}

impl<KexAlgo, Cipher, DigestType> State for AuthPending<KexAlgo, Cipher, DigestType>
where
    KexAlgo: Kex,
    Cipher: AeadMut + NewAead + NoiseCipher + Sized,
    DigestType: BlockInput + Clone + Default + FixedOutput + Input + Reset,
{
}

impl<KexAlgo, Cipher, DigestType> AuthPending<KexAlgo, Cipher, DigestType>
where
    KexAlgo: Kex,
    Cipher: AeadMut + NewAead + NoiseCipher + Sized,
    DigestType: BlockInput + Clone + Default + FixedOutput + Input + Reset,
{
    pub(crate) fn new(
        state: HandshakeState<KexAlgo, Cipher, DigestType>,
        expected_measurements: Vec<Measurement>,
        expected_product_id: u16,
        expected_minimum_svn: u16,
        allow_debug: bool,
        trust_anchors: Option<Vec<String>>,
    ) -> Self {
        Self {
            state,
            expected_measurements,
            expected_product_id,
            expected_minimum_svn,
            allow_debug,
            trust_anchors,
        }
    }
}

/// The state after an auth response has been sent by a responder/received by
/// an initiator.
pub struct Ready<Cipher>
where
    Cipher: AeadMut + NewAead + NoiseCipher + Sized,
{
    pub(crate) writer: CipherState<Cipher>,
    pub(crate) reader: CipherState<Cipher>,
    pub(crate) binding: Vec<u8>,
}

impl<Cipher> Ready<Cipher>
where
    Cipher: AeadMut + NewAead + NoiseCipher + Sized,
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
}

impl<Cipher> State for Ready<Cipher> where Cipher: AeadMut + NewAead + NoiseCipher + Sized {}
