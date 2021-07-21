// Copyright (c) 2018-2021 The MobileCoin Foundation

//! The HandshakeState object as described in the noise framework.

use crate::{
    cipher_state::NoiseCipher,
    patterns::{HandshakePattern, MessagePattern, PreMessageToken, Token},
    protocol_name::ProtocolName,
    symmetric_state::{SymmetricError, SymmetricOutput, SymmetricState},
};
use aead::{AeadMut, NewAead};
use alloc::vec::Vec;
use core::convert::{TryFrom, TryInto};
use digest::{BlockInput, Digest, FixedOutput, Reset, Update};
use displaydoc::Display;
use generic_array::typenum::Unsigned;
use mc_crypto_keys::{Kex, KexReusablePrivate, ReprBytes};
use mc_util_from_random::FromRandom;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

/// The public error messages which can be included in this construction
#[derive(
    Copy, Clone, Debug, Deserialize, Display, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
)]
pub enum HandshakeError {
    /// The initiator identity pubkey was not provided
    MissingInitiatorIdentity,
    /// The initiator ephemeral pubkey was not provided
    MissingInitiatorEphemeral,
    /// The responder identity pubkey was not provided
    MissingResponderIdentity,
    /// The responder ephemeral pubkey was not provided
    MissingResponderEphemeral,
    /// The initiator identity pubkey was already provided
    ExistingInitiatorIdentity,
    /// The initiator ephemeral pubkey was already provided
    ExistingInitiatorEphemeral,
    /// The responder identity pubkey was already provided
    ExistingResponderIdentity,
    /// The responder ephemeral pubkey was already provided
    ExistingResponderEphemeral,
    /// Attempted to write a message when a read was expected)
    WriteOutOfOrder,
    /// Attempted to read a message when a write was expected)
    ReadOutOfOrder,
    /// An error occurred during symmetric encryption/decryption: {0}
    Symmetric(SymmetricError),
    /// An error occurred while attempting to parse a public key
    KeyParse,
    /// Message is too short
    MessageTooShort,
    /// Unknown error
    Unknown,
}

impl From<SymmetricError> for HandshakeError {
    fn from(src: SymmetricError) -> Self {
        HandshakeError::Symmetric(src)
    }
}

// lookup table
enum ErrorIdx {
    MissingLocalEphemeral,
    MissingLocalIdentity,
    MissingRemoteEphemeral,
    MissingRemoteIdentity,
    ExistingLocalEphemeral,
    ExistingRemoteEphemeral,
    ExistingRemoteIdentity,
    Last,
}

const HANDSHAKE_ERROR: [[HandshakeError; ErrorIdx::Last as usize]; 2usize] = [
    // is_initiator = 0
    [
        HandshakeError::MissingResponderEphemeral,
        HandshakeError::MissingResponderIdentity,
        HandshakeError::MissingInitiatorEphemeral,
        HandshakeError::MissingInitiatorIdentity,
        HandshakeError::ExistingResponderEphemeral,
        HandshakeError::ExistingInitiatorEphemeral,
        HandshakeError::ExistingInitiatorIdentity,
    ],
    // is_initiator = 1
    [
        HandshakeError::MissingInitiatorEphemeral,
        HandshakeError::MissingInitiatorIdentity,
        HandshakeError::MissingResponderEphemeral,
        HandshakeError::MissingResponderIdentity,
        HandshakeError::ExistingInitiatorEphemeral,
        HandshakeError::ExistingResponderEphemeral,
        HandshakeError::ExistingResponderIdentity,
    ],
];

/// Handshake output is the result of a successful `ReadMessage()` or
/// `WriteMessage()` call.
///
/// This is pretty strange, but mostly because the two API methods have
/// strange variable return types.
pub struct HandshakeOutput<KexAlgo, Cipher, DigestType>
where
    KexAlgo: Kex,
    Cipher: AeadMut + NewAead + NoiseCipher + Sized,
    DigestType: BlockInput + Clone + Default + Digest + FixedOutput + Update + Reset,
{
    /// The payload is the read plaintext or written ciphertext
    pub payload: Vec<u8>,
    /// The status indicates whether the handshake has been completed or not
    pub status: HandshakeStatus<KexAlgo, Cipher, DigestType>,
}

/// An enumeration of resulting states for a `ReadMessage()` and
/// `WriteMessage()`.
pub enum HandshakeStatus<KexAlgo, Cipher, DigestType>
where
    KexAlgo: Kex,
    Cipher: AeadMut + NewAead + NoiseCipher + Sized,
    DigestType: BlockInput + Clone + Default + Digest + FixedOutput + Update + Reset,
{
    InProgress(HandshakeState<KexAlgo, Cipher, DigestType>),
    Complete(SymmetricOutput<Cipher, KexAlgo::Public>),
}

/// A generic implementation of the HandshakeState object from
/// [section 5.3](http://noiseprotocol.org/noise.html#the-handshakestate-object)
/// of the Noise framework.
pub struct HandshakeState<KexAlgo, Cipher, DigestType>
where
    KexAlgo: Kex,
    Cipher: AeadMut + NewAead + NoiseCipher + Sized,
    DigestType: BlockInput + Clone + Default + Digest + FixedOutput + Update + Reset,
{
    /// Whether this state machine is an initiator (true) or a responder (false)
    is_initiator: bool,

    /// The symmetric/cipher state for the handshake.
    symmetric_state: SymmetricState<KexAlgo, Cipher, DigestType>,

    /// An message pattern vector, reversed (last message first).
    ///
    /// This is reversed to provide an effective FIFO structure
    message_patterns: Vec<MessagePattern>,

    /// The local ephemeral private key
    local_ephemeral: Option<KexAlgo::Private>,

    /// The local static identity
    local_identity: Option<KexAlgo::Private>,

    /// The remote ephemeral public key, only available after remote has
    /// transmitted it's "e"
    remote_ephemeral: Option<KexAlgo::Public>,

    /// The remote identity public key, only available if remote is a "K" or
    /// has transmitted it's "s"
    remote_identity: Option<KexAlgo::Public>,
}

impl<KexAlgo, Cipher, DigestType> HandshakeState<KexAlgo, Cipher, DigestType>
where
    KexAlgo: Kex,
    Cipher: AeadMut + NewAead + NoiseCipher + Sized,
    DigestType: BlockInput + Clone + Default + Digest + FixedOutput + Update + Reset,
{
    /// Static method, dispatched from new(), used to perform step 4 of
    /// `HandshakeState::Initialize()`.
    fn mix_premsg_keys<Handshake: HandshakePattern>(
        symmetric_state: &mut SymmetricState<KexAlgo, Cipher, DigestType>,
        initiator_identity: Option<&KexAlgo::Public>,
        initiator_ephemeral: Option<&KexAlgo::Public>,
        responder_identity: Option<&KexAlgo::Public>,
        responder_ephemeral: Option<&KexAlgo::Public>,
    ) -> Result<(), HandshakeError> {
        // we are running as an initiator, so extract our pubkeys and hash them in.
        match Handshake::initiator_premsg() {
            PreMessageToken::Static => {
                initiator_identity
                    .ok_or(HandshakeError::MissingInitiatorIdentity)?
                    .map_bytes(|bytes| symmetric_state.mix_hash(bytes));
            }
            PreMessageToken::Ephemeral => {
                initiator_ephemeral
                    .ok_or(HandshakeError::MissingInitiatorEphemeral)?
                    .map_bytes(|bytes| symmetric_state.mix_hash(bytes));
            }
            PreMessageToken::EphemeralStatic => {
                initiator_ephemeral
                    .ok_or(HandshakeError::MissingInitiatorEphemeral)?
                    .map_bytes(|bytes| symmetric_state.mix_hash(bytes));
                initiator_identity
                    .ok_or(HandshakeError::MissingInitiatorIdentity)?
                    .map_bytes(|bytes| symmetric_state.mix_hash(bytes));
            }
            PreMessageToken::None => {}
        }

        match Handshake::responder_premsg() {
            PreMessageToken::Static => {
                responder_identity
                    .ok_or(HandshakeError::MissingResponderIdentity)?
                    .map_bytes(|bytes| symmetric_state.mix_hash(bytes));
            }
            PreMessageToken::Ephemeral => {
                responder_ephemeral
                    .ok_or(HandshakeError::MissingResponderEphemeral)?
                    .map_bytes(|bytes| symmetric_state.mix_hash(bytes));
            }
            PreMessageToken::EphemeralStatic => {
                responder_ephemeral
                    .ok_or(HandshakeError::MissingResponderEphemeral)?
                    .map_bytes(|bytes| symmetric_state.mix_hash(bytes));
                responder_identity
                    .ok_or(HandshakeError::MissingResponderIdentity)?
                    .map_bytes(|bytes| symmetric_state.mix_hash(bytes));
            }
            PreMessageToken::None => {}
        }

        Ok(())
    }

    /// The `HandshakeState::Initialize()` method.
    ///
    /// This is slightly modified to use the ProtocolName ZWT, instead of
    /// deriving a protocol name from a handshake pattern and the static types
    /// given.
    pub fn new<Handshake: HandshakePattern>(
        is_initiator: bool,
        protocol_name: ProtocolName<Handshake, KexAlgo, Cipher, DigestType>,
        prologue: &[u8],
        local_identity: Option<KexAlgo::Private>,
        local_ephemeral: Option<KexAlgo::Private>,
        remote_identity: Option<KexAlgo::Public>,
        remote_ephemeral: Option<KexAlgo::Public>,
    ) -> Result<Self, HandshakeError>
    where
        ProtocolName<Handshake, KexAlgo, Cipher, DigestType>: AsRef<str>,
    {
        // Initialize step 1
        let mut symmetric_state = SymmetricState::from(protocol_name);

        // Initialize step 2
        symmetric_state.mix_hash(prologue);

        if is_initiator {
            Self::mix_premsg_keys::<Handshake>(
                &mut symmetric_state,
                local_identity.as_ref().map(KexAlgo::Public::from).as_ref(),
                local_ephemeral.as_ref().map(KexAlgo::Public::from).as_ref(),
                remote_identity.as_ref(),
                remote_ephemeral.as_ref(),
            )?;
        } else {
            Self::mix_premsg_keys::<Handshake>(
                &mut symmetric_state,
                remote_identity.as_ref(),
                remote_ephemeral.as_ref(),
                local_identity.as_ref().map(KexAlgo::Public::from).as_ref(),
                local_ephemeral.as_ref().map(KexAlgo::Public::from).as_ref(),
            )?;
        }

        // Initialize steps 3, 5
        Ok(Self {
            is_initiator,
            symmetric_state,
            message_patterns: Handshake::reverse_messages(),
            local_identity,
            local_ephemeral,
            remote_identity,
            remote_ephemeral,
        })
    }

    /// Do an identity-binding DH (that is, an "ee" or "es" operation).
    fn mix_es_se_key(&mut self, identity_is_local: bool) -> Result<(), HandshakeError> {
        let (local, remote, local_err, remote_err) = if identity_is_local {
            (
                self.local_identity.as_ref(),
                self.remote_ephemeral.as_ref(),
                ErrorIdx::MissingLocalIdentity,
                ErrorIdx::MissingRemoteEphemeral,
            )
        } else {
            (
                self.local_ephemeral.as_ref(),
                self.remote_identity.as_ref(),
                ErrorIdx::MissingLocalEphemeral,
                ErrorIdx::MissingRemoteIdentity,
            )
        };

        Ok(self.symmetric_state.mix_key(
            local
                .ok_or(HANDSHAKE_ERROR[self.is_initiator as usize][local_err as usize])?
                .key_exchange(
                    remote
                        .ok_or(HANDSHAKE_ERROR[self.is_initiator as usize][remote_err as usize])?,
                ),
        )?)
    }

    /// Helper function, handles "ee" tokens for both read and write.
    fn mix_ee(&mut self) -> Result<(), HandshakeError> {
        Ok(self.symmetric_state.mix_key(
            self.local_ephemeral
                .as_ref()
                .ok_or(
                    HANDSHAKE_ERROR[self.is_initiator as usize]
                        [ErrorIdx::MissingLocalEphemeral as usize],
                )?
                .key_exchange(self.remote_ephemeral.as_ref().ok_or(
                    HANDSHAKE_ERROR[self.is_initiator as usize]
                        [ErrorIdx::MissingRemoteEphemeral as usize],
                )?),
        )?)
    }

    /// Actually construct a noise protocol message from our internal state
    /// using the tokens and payload provided.
    fn do_write_message(
        &mut self,
        tokens: Vec<Token>,
        csprng: &mut (impl CryptoRng + RngCore),
        payload: &[u8],
    ) -> Result<Vec<u8>, HandshakeError> {
        // Create an output buffer large enough to encrypt our payload and any tokens
        // into
        let mut retval = Vec::with_capacity(
            tokens.len() * 32 + payload.len() + Cipher::CiphertextOverhead::to_usize(),
        );

        for token in tokens {
            match token {
                // For "e"
                Token::Ephemeral => {
                    if self.local_ephemeral.is_some() {
                        return Err(HANDSHAKE_ERROR[self.is_initiator as usize]
                            [ErrorIdx::ExistingLocalEphemeral as usize]);
                    }
                    let ephemeral_privkey = KexAlgo::Private::from_random(csprng);
                    let pubkey = KexAlgo::Public::from(&ephemeral_privkey);
                    pubkey.map_bytes(|pubkey_bytes| {
                        self.symmetric_state.mix_hash(pubkey_bytes);
                        retval.extend_from_slice(pubkey_bytes);
                    });
                    self.local_ephemeral = Some(ephemeral_privkey);
                }
                // For "s"
                Token::Static => {
                    let pubkey = KexAlgo::Public::from(self.local_identity.as_ref().ok_or(
                        HANDSHAKE_ERROR[self.is_initiator as usize]
                            [ErrorIdx::MissingLocalIdentity as usize],
                    )?);
                    let ciphertext =
                        pubkey.map_bytes(|bytes| self.symmetric_state.encrypt_and_hash(bytes))?;
                    retval.extend_from_slice(&ciphertext);
                }
                // For "ee"
                Token::KexEphemeralEphemeral => self.mix_ee()?,
                // For "es"
                Token::KexEphemeralStatic => self.mix_es_se_key(!self.is_initiator)?,
                // For "se"
                Token::KexStaticEphemeral => self.mix_es_se_key(self.is_initiator)?,
                // For "ss"
                Token::KexStaticStatic => {
                    let (local_error, remote_error) = if self.is_initiator {
                        (
                            HandshakeError::MissingInitiatorIdentity,
                            HandshakeError::MissingResponderIdentity,
                        )
                    } else {
                        (
                            HandshakeError::MissingResponderIdentity,
                            HandshakeError::MissingInitiatorIdentity,
                        )
                    };
                    self.symmetric_state.mix_key(
                        self.local_identity
                            .as_ref()
                            .ok_or(local_error)?
                            .key_exchange(self.remote_identity.as_ref().ok_or(remote_error)?),
                    )?;
                }
            }
        }

        let ciphertext = self.symmetric_state.encrypt_and_hash(payload)?;
        retval.extend_from_slice(&ciphertext);
        Ok(retval)
    }

    fn make_handshake_output(
        self,
        output: Vec<u8>,
    ) -> Result<HandshakeOutput<KexAlgo, Cipher, DigestType>, HandshakeError> {
        let status = if self.message_patterns.is_empty() {
            let mut output: SymmetricOutput<Cipher, KexAlgo::Public> =
                self.symmetric_state.try_into()?;
            output.remote_identity = self.remote_identity;
            HandshakeStatus::Complete(output)
        } else {
            HandshakeStatus::InProgress(self)
        };

        Ok(HandshakeOutput {
            payload: output,
            status,
        })
    }

    /// The Noise `HandshakeState::WriteMessage()` interface.
    ///
    /// This method consumes the handshake state, and either returns it again,
    /// as part of a `HandshakeOutput` structure, or deletes it entirely and
    /// returns resulting steady-state ciphers, if there are no more message
    /// patterns left in our handshake.
    pub fn write_message(
        mut self,
        csprng: &mut (impl CryptoRng + RngCore),
        payload: &[u8],
    ) -> Result<HandshakeOutput<KexAlgo, Cipher, DigestType>, HandshakeError> {
        // This method should not be capable of being called when there are no
        // message patterns, hence expect().
        let msg = self
            .message_patterns
            .pop()
            .expect("HandshakeState did not delete itself after message patterns were exhausted");

        let output = match msg {
            MessagePattern::Initiator(tokens) => {
                if !self.is_initiator {
                    Err(HandshakeError::WriteOutOfOrder)
                } else {
                    self.do_write_message(tokens, csprng, payload)
                }
            }
            MessagePattern::Responder(tokens) => {
                if self.is_initiator {
                    Err(HandshakeError::WriteOutOfOrder)
                } else {
                    self.do_write_message(tokens, csprng, payload)
                }
            }
        }?;

        self.make_handshake_output(output)
    }

    /// Private method, decrypts and parses the given message in accordance
    /// with the tokens, and updates our internal state.
    fn do_read_message(
        &mut self,
        tokens: Vec<Token>,
        msg: &[u8],
    ) -> Result<Vec<u8>, HandshakeError> {
        let mut offset = 0usize;
        for token in tokens {
            match token {
                // For "e"
                Token::Ephemeral => {
                    if self.remote_ephemeral.is_some() {
                        return Err(HANDSHAKE_ERROR[self.is_initiator as usize]
                            [ErrorIdx::ExistingRemoteEphemeral as usize]);
                    }
                    let pubkey_size = KexAlgo::Public::size();
                    if offset + pubkey_size > msg.len() {
                        return Err(HandshakeError::MessageTooShort);
                    }
                    let pubkey_bytes = &msg[offset..(offset + pubkey_size)];
                    let ephemeral_pubkey = KexAlgo::Public::try_from(pubkey_bytes)
                        .map_err(|_e| HandshakeError::KeyParse)?;
                    offset += pubkey_size;

                    self.symmetric_state.mix_hash(pubkey_bytes);
                    self.remote_ephemeral = Some(ephemeral_pubkey);
                }
                // For "s"
                Token::Static => {
                    if self.remote_identity.is_some() {
                        return Err(HANDSHAKE_ERROR[self.is_initiator as usize]
                            [ErrorIdx::ExistingRemoteIdentity as usize]);
                    }

                    let text_size = self.symmetric_state.key_len();
                    if offset + text_size > msg.len() {
                        return Err(HandshakeError::MessageTooShort);
                    }
                    let encrypted_key_bytes = &msg[offset..(offset + text_size)];
                    offset += text_size;

                    let decrypted_key_bytes = self
                        .symmetric_state
                        .decrypt_and_hash(&encrypted_key_bytes)?;
                    let pubkey = KexAlgo::Public::try_from(&decrypted_key_bytes[..])
                        .map_err(|_e| HandshakeError::KeyParse)?;
                    self.remote_identity = Some(pubkey);
                }
                // For "ee"
                Token::KexEphemeralEphemeral => self.mix_ee()?,
                // For "es"
                Token::KexEphemeralStatic => self.mix_es_se_key(!self.is_initiator)?,
                // For "se"
                Token::KexStaticEphemeral => self.mix_es_se_key(self.is_initiator)?,
                // For "ss"
                Token::KexStaticStatic => {
                    let (local_error, remote_error) = if self.is_initiator {
                        (
                            HandshakeError::MissingInitiatorIdentity,
                            HandshakeError::MissingResponderIdentity,
                        )
                    } else {
                        (
                            HandshakeError::MissingResponderIdentity,
                            HandshakeError::MissingInitiatorIdentity,
                        )
                    };
                    self.symmetric_state.mix_key(
                        self.local_identity
                            .as_ref()
                            .ok_or(local_error)?
                            .key_exchange(self.remote_identity.as_ref().ok_or(remote_error)?),
                    )?;
                }
            }
        }

        Ok(self.symmetric_state.decrypt_and_hash(&msg[offset..])?)
    }

    /// This noise framework `HandshakeState::ReadMessage()` interface.
    ///
    /// This method consumes the handshake state, and either returns it again,
    /// as part of a `HandshakeOutput` structure, or deletes it entirely and
    /// returns resulting steady-state ciphers, if there are no more message
    /// patterns left in our handshake.
    pub fn read_message(
        mut self,
        payload: &[u8],
    ) -> Result<HandshakeOutput<KexAlgo, Cipher, DigestType>, HandshakeError> {
        // This method should not be capable of being called when there are no
        // message patterns, hence expect().
        let msg = self
            .message_patterns
            .pop()
            .expect("HandshakeState did not delete itself after message patterns were exhausted");

        let output = match msg {
            MessagePattern::Initiator(tokens) => {
                if self.is_initiator {
                    Err(HandshakeError::ReadOutOfOrder)
                } else {
                    self.do_read_message(tokens, payload)
                }
            }
            MessagePattern::Responder(tokens) => {
                if !self.is_initiator {
                    Err(HandshakeError::ReadOutOfOrder)
                } else {
                    self.do_read_message(tokens, payload)
                }
            }
        }?;

        self.make_handshake_output(output)
    }

    /// Retrieve a copy of the local identity public key, if it has been set.
    pub fn local_ephemeral(&self) -> Option<KexAlgo::Public> {
        self.local_ephemeral.as_ref().map(KexAlgo::Public::from)
    }

    /// Retrieve a copy of the local identity public key, if it has been set.
    pub fn local_identity(&self) -> Option<KexAlgo::Public> {
        self.local_identity.as_ref().map(KexAlgo::Public::from)
    }

    /// Retrieve a reference to the remote ephemeral pubkey, if it has been read
    /// yet.
    pub fn remote_ephemeral(&self) -> Option<&KexAlgo::Public> {
        self.remote_ephemeral.as_ref()
    }

    /// Retrieve the remote identity, if it has been read yet.
    pub fn remote_identity(&self) -> Option<&KexAlgo::Public> {
        self.remote_identity.as_ref()
    }
}

#[cfg(test)]
mod test {
    extern crate std;

    use super::*;
    use crate::patterns::{HandshakeIX, HandshakeNX};
    use aes_gcm::Aes256Gcm;
    use mc_crypto_keys::{X25519Private, X25519};
    use rand_core::SeedableRng;
    use rand_hc::Hc128Rng;
    use sha2::Sha512;

    #[test]
    fn walkthrough_ix_25519_aesgcm_sha512() {
        let protocol_name = ProtocolName::<HandshakeIX, X25519, Aes256Gcm, Sha512>::default();
        let mut csprng = Hc128Rng::seed_from_u64(0);
        let initiator_static = X25519Private::from_random(&mut csprng);
        let responder_static = X25519Private::from_random(&mut csprng);

        let prologue = "The past is prologue.";
        let challenge = "Any sufficiently advanced idea is distinguishable from mere magical incantation provided the former is presented as a mathematical proof, verifiable by sufficiently competent mathematicians";
        let response =
            "When I write a paper, I change my notation much more than I change my concepts.";

        let mut initiator = HandshakeState::new(
            true,
            protocol_name.clone(),
            prologue.as_bytes(),
            Some(initiator_static),
            None,
            None,
            None,
        )
        .expect("Could not create initiator");

        let mut responder = HandshakeState::new(
            false,
            protocol_name,
            prologue.as_bytes(),
            Some(responder_static),
            None,
            None,
            None,
        )
        .expect("Could not create responder");

        // Create a message for transmission to the responder
        std::eprintln!("Initiator is writing first message...");
        let output1 = initiator
            .write_message(&mut csprng, challenge.as_bytes())
            .expect("Initiator could not write initial message");

        // Check our output status -- this ugliness is how to actually
        // implement the variable return types of write_message/read_message,
        // and auto-nuke HandshakeState when we're complete.
        match output1.status {
            HandshakeStatus::InProgress(new_state) => initiator = new_state,
            HandshakeStatus::Complete(_symmetric_output) => unreachable!(),
        }

        let payload_len = output1.payload.len();
        let challenge_len = challenge.as_bytes().len();
        assert_eq!(
            challenge.as_bytes(),
            &output1.payload[(payload_len - challenge_len)..]
        );

        // Give the message to the responder to examine/parse/decrypt
        std::eprintln!("Responder is reading first message...");
        let output2 = responder
            .read_message(&output1.payload)
            .expect("Responder could not read first message");

        match output2.status {
            HandshakeStatus::InProgress(new_state) => responder = new_state,
            HandshakeStatus::Complete(_output) => unreachable!(),
        }

        // the payload should be in plaintext here, since we're IX, so check that it is
        assert_eq!(challenge.as_bytes(), output2.payload.as_slice());

        std::eprintln!("Responder has done Kex, writing response message");
        let output3 = responder
            .write_message(&mut csprng, response.as_bytes())
            .expect("Responder could not write reply");

        // At this point, the responder has everything it needs to proceed
        let mut responder_output = match output3.status {
            HandshakeStatus::InProgress(_new_state) => unreachable!(),
            HandshakeStatus::Complete(output) => output,
        };

        let payload_len = output3.payload.len();
        let response_len = response.as_bytes().len();
        std::eprintln!(
            "response = {:02x?}\noutput3.payload = {:02x?}",
            response.as_bytes(),
            &output3.payload
        );
        assert_ne!(
            response.as_bytes(),
            &output3.payload[(payload_len - response_len)..]
        );

        std::eprintln!("Initiator is trying to read response");
        let output4 = initiator
            .read_message(&output3.payload)
            .expect("Initiator could not read response");

        let mut initiator_output = match output4.status {
            HandshakeStatus::InProgress(_new_state) => unreachable!(),
            HandshakeStatus::Complete(output) => output,
        };

        assert_eq!(response.as_bytes(), &output4.payload[..]);

        assert!(initiator_output.initiator_cipher.has_key());
        assert!(initiator_output.responder_cipher.has_key());
        assert!(responder_output.initiator_cipher.has_key());
        assert!(responder_output.responder_cipher.has_key());

        let message1 = "Pay $ to my dude.";
        let encrypted1 = initiator_output
            .initiator_cipher
            .encrypt_with_ad(prologue.as_bytes(), message1.as_bytes())
            .expect("Initiator could not encrypt message 1");
        let decrypted1 = responder_output
            .initiator_cipher
            .decrypt_with_ad(prologue.as_bytes(), &encrypted1)
            .expect("Responder could not decrypt message 1");
        assert_eq!(message1.as_bytes(), decrypted1.as_slice());

        let message2 = "It look's like you're trying to pay a friend without being it generating an advertisement. Would you like some help with that?";
        let encrypted2 = responder_output
            .responder_cipher
            .encrypt_with_ad(prologue.as_bytes(), message2.as_bytes())
            .expect("Responder could not encrypt message2");
        let decrypted2 = initiator_output
            .responder_cipher
            .decrypt_with_ad(prologue.as_bytes(), &encrypted2)
            .expect("Initiator could not decrypt message2");
        assert_eq!(message2.as_bytes(), decrypted2.as_slice());
    }

    #[test]
    fn walkthrough_nx_25519_aesgcm_sha512() {
        let protocol_name = ProtocolName::<HandshakeNX, X25519, Aes256Gcm, Sha512>::default();
        let mut csprng = Hc128Rng::seed_from_u64(0);
        let responder_static = X25519Private::from_random(&mut csprng);

        let prologue = "The past is prologue.";
        let challenge = "Any sufficiently advanced idea is distinguishable from mere magical incantation provided the former is presented as a mathematical proof, verifiable by sufficiently competent mathematicians";
        let response =
            "When I write a paper, I change my notation much more than I change my concepts.";

        let mut initiator = HandshakeState::new(
            true,
            protocol_name.clone(),
            prologue.as_bytes(),
            None,
            None,
            None,
            None,
        )
        .expect("Could not create initiator");

        let mut responder = HandshakeState::new(
            false,
            protocol_name,
            prologue.as_bytes(),
            Some(responder_static),
            None,
            None,
            None,
        )
        .expect("Could not create responder");

        // Create a message for transmission to the responder
        let output1 = initiator
            .write_message(&mut csprng, challenge.as_bytes())
            .expect("Initiator could not write initial message");

        // Check our output status -- this ugliness is how to actually
        // implement the variable return types of write_message/read_message,
        // and auto-nuke HandshakeState when we're complete.
        match output1.status {
            HandshakeStatus::InProgress(new_state) => initiator = new_state,
            HandshakeStatus::Complete(_symmetric_output) => unreachable!(),
        }

        let payload_len = output1.payload.len();
        let challenge_len = challenge.as_bytes().len();
        assert_eq!(
            challenge.as_bytes(),
            &output1.payload[(payload_len - challenge_len)..]
        );

        // Give the message to the responder to examine/parse/decrypt
        let output2 = responder
            .read_message(&output1.payload)
            .expect("Responder could not read first message");

        match output2.status {
            HandshakeStatus::InProgress(new_state) => responder = new_state,
            HandshakeStatus::Complete(_output) => unreachable!(),
        }

        // the payload should be in plaintext here, since we're IX, so check that it is
        assert_eq!(challenge.as_bytes(), output2.payload.as_slice());

        let output3 = responder
            .write_message(&mut csprng, response.as_bytes())
            .expect("Responder could not write reply");

        // At this point, the responder has everything it needs to proceed
        let mut responder_output = match output3.status {
            HandshakeStatus::InProgress(_new_state) => unreachable!(),
            HandshakeStatus::Complete(output) => output,
        };

        let payload_len = output3.payload.len();
        let response_len = response.as_bytes().len();
        assert_ne!(
            response.as_bytes(),
            &output3.payload[(payload_len - response_len)..]
        );

        let output4 = initiator
            .read_message(&output3.payload)
            .expect("Initiator could not read response");

        let mut initiator_output = match output4.status {
            HandshakeStatus::InProgress(_new_state) => unreachable!(),
            HandshakeStatus::Complete(output) => output,
        };

        assert_eq!(response.as_bytes(), &output4.payload[..]);

        assert!(initiator_output.initiator_cipher.has_key());
        assert!(initiator_output.responder_cipher.has_key());
        assert!(responder_output.initiator_cipher.has_key());
        assert!(responder_output.responder_cipher.has_key());

        let message1 = "Pay $ to my dude.";
        let encrypted1 = initiator_output
            .initiator_cipher
            .encrypt_with_ad(prologue.as_bytes(), message1.as_bytes())
            .expect("Initiator could not encrypt message 1");
        let decrypted1 = responder_output
            .initiator_cipher
            .decrypt_with_ad(prologue.as_bytes(), &encrypted1)
            .expect("Responder could not decrypt message 1");
        assert_eq!(message1.as_bytes(), decrypted1.as_slice());

        let message2 = "It look's like you're trying to pay a friend without being it generating an advertisement. Would you like some help with that?";
        let encrypted2 = responder_output
            .responder_cipher
            .encrypt_with_ad(prologue.as_bytes(), message2.as_bytes())
            .expect("Responder could not encrypt message2");
        let decrypted2 = initiator_output
            .responder_cipher
            .decrypt_with_ad(prologue.as_bytes(), &encrypted2)
            .expect("Initiator could not decrypt message2");
        assert_eq!(message2.as_bytes(), decrypted2.as_slice());
    }
}
