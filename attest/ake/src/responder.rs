// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Responder-specific transition functions
use crate::{
    error::Error,
    event::{AuthResponseOutput, ClientAuthRequestInput, NodeAuthRequestInput},
    mealy::Transition,
    state::{Ready, Start},
};
use aead::{AeadMut, NewAead};
use alloc::vec::Vec;
use core::convert::TryFrom;
use digest::{BlockInput, Digest, FixedOutput, Reset, Update};
use mc_attest_core::{ReportDataMask, VerificationReport};
use mc_crypto_keys::{Kex, ReprBytes};
use mc_crypto_noise::{
    HandshakeIX, HandshakeNX, HandshakePattern, HandshakeState, HandshakeStatus, NoiseCipher,
    ProtocolName,
};
use prost::Message;
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
        DigestType: BlockInput + Clone + Default + Digest + FixedOutput + Update + Reset,
        ProtocolName<Handshake, KexAlgo, Cipher, DigestType>: AsRef<str>;

    fn handle_response<KexAlgo, Cipher, DigestType>(
        csprng: &mut (impl CryptoRng + RngCore),
        handshake_state: HandshakeState<KexAlgo, Cipher, DigestType>,
        ias_report: VerificationReport,
    ) -> Result<(Ready<Cipher>, AuthResponseOutput), Error>
    where
        KexAlgo: Kex,
        Cipher: AeadMut + NewAead + NoiseCipher + Sized,
        DigestType: BlockInput + Clone + Default + Digest + FixedOutput + Update + Reset;
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
        DigestType: BlockInput + Clone + Default + Digest + FixedOutput + Update + Reset,
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
    ) -> Result<(Ready<Cipher>, AuthResponseOutput), Error>
    where
        KexAlgo: Kex,
        Cipher: AeadMut + NewAead + NoiseCipher + Sized,
        DigestType: BlockInput + Clone + Default + Digest + FixedOutput + Update + Reset,
    {
        // Encrypt the local report for output
        let mut report_bytes = Vec::with_capacity(ias_report.encoded_len());
        ias_report
            .encode(&mut report_bytes)
            .expect("Invariant failure, encoded_len insufficient to encode IAS report");

        let output = handshake_state
            .write_message(csprng, &report_bytes)
            .map_err(Error::HandshakeWrite)?;

        match output.status {
            HandshakeStatus::InProgress(_state) => Err(Error::HandshakeNotComplete),
            HandshakeStatus::Complete(result) => Ok((
                Ready {
                    writer: result.responder_cipher,
                    reader: result.initiator_cipher,
                    binding: result.channel_binding,
                },
                AuthResponseOutput::from(output.payload),
            )),
        }
    }
}

/// Start + NodeAuthRequestInput => Ready + AuthResponseOutput
///
/// This defines the responder's action when an AuthRequestInput for an IX
/// exchange is provided.
impl<KexAlgo, Cipher, DigestType>
    Transition<Ready<Cipher>, NodeAuthRequestInput<KexAlgo, Cipher, DigestType>, AuthResponseOutput>
    for Start
where
    KexAlgo: Kex,
    Cipher: AeadMut + NewAead + NoiseCipher + Sized,
    DigestType: BlockInput + Clone + Default + Digest + FixedOutput + Update + Reset,
    ProtocolName<HandshakeIX, KexAlgo, Cipher, DigestType>: AsRef<str>,
{
    type Error = Error;

    fn try_next<R: CryptoRng + RngCore>(
        self,
        csprng: &mut R,
        input: NodeAuthRequestInput<KexAlgo, Cipher, DigestType>,
    ) -> Result<(Ready<Cipher>, AuthResponseOutput), Error> {
        // Read the request and return the payload and state
        let (handshake_state, payload) = self
            .handle_request::<HandshakeIX, KexAlgo, Cipher, DigestType>(
                &input.data.data,
                input.local_identity,
            )?;

        let mut verifier = input.verifier;

        // Parse the received IAS report
        let remote_report = VerificationReport::decode(payload.as_slice())
            .map_err(|_| Error::ReportDeserialization)?;
        // Verify using given verifier, and ensure the first 32B of the report data are
        // the identity pubkey.
        verifier
            .report_data(
                &handshake_state
                    .remote_identity()
                    .ok_or(Error::MissingRemoteIdentity)?
                    .map_bytes(|bytes| {
                        ReportDataMask::try_from(bytes).map_err(|_| Error::BadRemoteIdentity)
                    })?,
            )
            .verify(&remote_report)?;

        Self::handle_response(csprng, handshake_state, input.ias_report)
    }
}

/// Start + ClientAuthRequestInput => Ready + AuthResponseOutput
impl<KexAlgo, Cipher, DigestType>
    Transition<
        Ready<Cipher>,
        ClientAuthRequestInput<KexAlgo, Cipher, DigestType>,
        AuthResponseOutput,
    > for Start
where
    KexAlgo: Kex,
    Cipher: AeadMut + NewAead + NoiseCipher + Sized,
    DigestType: BlockInput + Clone + Default + Digest + FixedOutput + Update + Reset,
    ProtocolName<HandshakeNX, KexAlgo, Cipher, DigestType>: AsRef<str>,
{
    type Error = Error;

    fn try_next<R: CryptoRng + RngCore>(
        self,
        csprng: &mut R,
        input: ClientAuthRequestInput<KexAlgo, Cipher, DigestType>,
    ) -> Result<(Ready<Cipher>, AuthResponseOutput), Error> {
        let (handshake_state, _payload) = self
            .handle_request::<HandshakeNX, KexAlgo, Cipher, DigestType>(
                &input.data.data,
                input.local_identity,
            )?;
        Self::handle_response(csprng, handshake_state, input.ias_report)
    }
}
