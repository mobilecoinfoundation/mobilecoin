// Copyright (c) 2018-2020 MobileCoin Inc.

//! Responder-specific transition functions
use crate::{
    error::Error,
    event::{AuthRequestInput, AuthResponse},
    mealy::Transition,
    state::{Ready, Start},
};
use aead::{AeadMut, NewAead};
use alloc::vec::Vec;
use core::convert::TryFrom;
use digest::{BlockInput, Digest, FixedOutput, Input, Reset};
use mc_attest_core::{QuoteSignType, ReportDataMask, VerificationReport};
use mc_crypto_keys::{Kex, ReprBytes};
use mc_crypto_noise::{
    HandshakeIX, HandshakeNX, HandshakePattern, HandshakeState, HandshakeStatus, NoiseCipher,
    ProtocolName,
};
use mc_util_serial::{deserialize, serialize};
use rand_core::{CryptoRng, RngCore};

/// A trait containing default implementations, used to tack repeatable chunks
/// of code onto the "Start" state for use below.
trait ResponderTransitionMixin {
    fn handle_request<Handshake, KexAlgo, Cipher, DigestType>(
        &self,
        data: &[u8],
        local_identity: KexAlgo::Private,
    ) -> Result<(HandshakeState<KexAlgo, Cipher, DigestType>, Vec<u8>), Error>
    where
        Handshake: HandshakePattern,
        KexAlgo: Kex,
        Cipher: AeadMut + NewAead + NoiseCipher + Sized,
        DigestType: BlockInput + Clone + Default + Digest + FixedOutput + Input + Reset,
        ProtocolName<Handshake, KexAlgo, Cipher, DigestType>: AsRef<str>;

    fn handle_response<KexAlgo, Cipher, DigestType>(
        csprng: &mut (impl CryptoRng + RngCore),
        handshake_state: HandshakeState<KexAlgo, Cipher, DigestType>,
        ias_report: VerificationReport,
    ) -> Result<(Ready<Cipher>, AuthResponse), Error>
    where
        KexAlgo: Kex,
        Cipher: AeadMut + NewAead + NoiseCipher + Sized,
        DigestType: BlockInput + Clone + Default + Digest + FixedOutput + Input + Reset;
}

impl ResponderTransitionMixin for Start {
    fn handle_request<Handshake, KexAlgo, Cipher, DigestType>(
        &self,
        data: &[u8],
        local_identity: KexAlgo::Private,
    ) -> Result<(HandshakeState<KexAlgo, Cipher, DigestType>, Vec<u8>), Error>
    where
        Handshake: HandshakePattern,
        KexAlgo: Kex,
        Cipher: AeadMut + NewAead + NoiseCipher + Sized,
        DigestType: BlockInput + Clone + Default + Digest + FixedOutput + Input + Reset,
        ProtocolName<Handshake, KexAlgo, Cipher, DigestType>: AsRef<str>,
    {
        let handshake_state = HandshakeState::new(
            false,
            ProtocolName::<Handshake, KexAlgo, Cipher, DigestType>::default(),
            self.responder_id.as_ref(),
            Some(local_identity),
            None,
            None,
            None,
        )
        .map_err(Error::HandshakeInit)?;

        // Read the inbound message
        let output = handshake_state
            .read_message(data)
            .map_err(Error::HandshakeWrite)?;

        match output.status {
            HandshakeStatus::InProgress(new_state) => Ok((new_state, output.payload)),
            HandshakeStatus::Complete(_v) => Err(Error::EarlyHandshakeComplete),
        }
    }

    fn handle_response<KexAlgo, Cipher, DigestType>(
        csprng: &mut (impl CryptoRng + RngCore),
        handshake_state: HandshakeState<KexAlgo, Cipher, DigestType>,
        ias_report: VerificationReport,
    ) -> Result<(Ready<Cipher>, AuthResponse), Error>
    where
        KexAlgo: Kex,
        Cipher: AeadMut + NewAead + NoiseCipher + Sized,
        DigestType: BlockInput + Clone + Default + Digest + FixedOutput + Input + Reset,
    {
        // Encrypt the local report for output
        let local_report = serialize(&ias_report).map_err(|_e| Error::ReportSerialization)?;

        let output = handshake_state
            .write_message(csprng, &local_report)
            .map_err(Error::HandshakeWrite)?;

        match output.status {
            HandshakeStatus::InProgress(_state) => Err(Error::HandshakeNotComplete),
            HandshakeStatus::Complete(result) => Ok((
                Ready {
                    writer: result.responder_cipher,
                    reader: result.initiator_cipher,
                    binding: result.channel_binding,
                },
                AuthResponse::from(output.payload),
            )),
        }
    }
}

/// Start + AuthRequestInput<IX> => Ready + AuthResponse
///
/// This defines the responder's action when an AuthRequestInput for an IX
/// exchange is provided.
impl<KexAlgo, Cipher, DigestType>
    Transition<
        Ready<Cipher>,
        AuthRequestInput<HandshakeIX, KexAlgo, Cipher, DigestType>,
        AuthResponse,
    > for Start
where
    KexAlgo: Kex,
    Cipher: AeadMut + NewAead + NoiseCipher + Sized,
    DigestType: BlockInput + Clone + Default + Digest + FixedOutput + Input + Reset,
    ProtocolName<HandshakeIX, KexAlgo, Cipher, DigestType>: AsRef<str>,
{
    type Error = Error;

    fn try_next(
        self,
        csprng: &mut (impl CryptoRng + RngCore),
        input: AuthRequestInput<HandshakeIX, KexAlgo, Cipher, DigestType>,
    ) -> Result<(Ready<Cipher>, AuthResponse), Error> {
        // Read the request and return the payload and state
        let (handshake_state, payload) = self
            .handle_request::<HandshakeIX, KexAlgo, Cipher, DigestType>(
                &input.data.data,
                input.local_identity,
            )?;

        // Parse and verify the received IAS report
        let remote_report: VerificationReport =
            deserialize(&payload).map_err(|_e| Error::ReportDeserialization)?;
        remote_report.verify(
            self.trust_anchors,
            None,
            None,
            None,
            QuoteSignType::Linkable,
            self.allow_debug,
            &self.expected_measurements,
            self.expected_product_id,
            self.expected_minimum_svn,
            &handshake_state
                .remote_identity()
                .ok_or(Error::MissingRemoteIdentity)?
                .map_bytes(|bytes| {
                    ReportDataMask::try_from(bytes).map_err(|_| Error::BadRemoteIdentity)
                })?,
        )?;

        Self::handle_response(csprng, handshake_state, input.ias_report)
    }
}

/// Start + AuthRequestInput<NX> => Ready + AuthResponse
impl<KexAlgo, Cipher, DigestType>
    Transition<
        Ready<Cipher>,
        AuthRequestInput<HandshakeNX, KexAlgo, Cipher, DigestType>,
        AuthResponse,
    > for Start
where
    KexAlgo: Kex,
    Cipher: AeadMut + NewAead + NoiseCipher + Sized,
    DigestType: BlockInput + Clone + Default + Digest + FixedOutput + Input + Reset,
    ProtocolName<HandshakeNX, KexAlgo, Cipher, DigestType>: AsRef<str>,
{
    type Error = Error;

    fn try_next(
        self,
        csprng: &mut (impl CryptoRng + RngCore),
        input: AuthRequestInput<HandshakeNX, KexAlgo, Cipher, DigestType>,
    ) -> Result<(Ready<Cipher>, AuthResponse), Error> {
        let (handshake_state, _payload) = self
            .handle_request::<HandshakeNX, KexAlgo, Cipher, DigestType>(
                &input.data.data,
                input.local_identity,
            )?;
        Self::handle_response(csprng, handshake_state, input.ias_report)
    }
}
