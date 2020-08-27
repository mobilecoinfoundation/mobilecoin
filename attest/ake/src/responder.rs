// Copyright (c) 2018-2020 MobileCoin Inc.

//! Responder-specific transition functions
use crate::{
    error::Error,
    event::{AuthResponseOutput, ClientAuthRequestInput, NodeAuthRequestInput},
    mealy::Transition,
    state::{Ready, Start},
};
use aead::{AeadMut, NewAead};
use alloc::vec::Vec;
use digest::{BlockInput, Digest, FixedOutput, Reset, Update};
use mc_attest_core::VerificationReport;
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
        mut input: NodeAuthRequestInput<KexAlgo, Cipher, DigestType>,
    ) -> Result<(Ready<Cipher>, AuthResponseOutput), Error> {
        // Read the request and return the payload and state
        let (handshake_state, payload) = self
            .handle_request::<HandshakeIX, KexAlgo, Cipher, DigestType>(
                &input.data.data,
                input.local_identity,
            )?;

        // Parse and verify the received IAS report
        // FIXME: MCC-1702
        let remote_report: VerificationReport =
            deserialize(&payload).map_err(|_e| Error::ReportDeserialization)?;

        input
            .verifier
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
