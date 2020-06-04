// Copyright (c) 2018-2020 MobileCoin Inc.

//! Initiator-specific transition functions

use crate::{
    error::Error,
    event::{AuthRequestOutput, AuthResponse, AuthSuccess, ClientInitiate, NodeInitiate},
    mealy::Transition,
    state::{AuthPending, Ready, Start},
};
use aead::{AeadMut, NewAead};
use alloc::{string::String, vec::Vec};
use core::convert::TryFrom;
use digest::{BlockInput, Digest, FixedOutput, Input, Reset};
use mc_attest_core::{Measurement, QuoteSignType, ReportDataMask, VerificationReport};
use mc_crypto_keys::{Kex, ReprBytes};
use mc_crypto_noise::{
    HandshakeIX, HandshakeNX, HandshakeOutput, HandshakePattern, HandshakeState, HandshakeStatus,
    NoiseCipher, ProtocolName,
};
use mc_util_serial::{deserialize, serialize};
use rand_core::{CryptoRng, RngCore};

/// Helper function to create the output for an initiate
fn parse_handshake_output<Handshake, KexAlgo, Cipher, DigestType>(
    output: HandshakeOutput<KexAlgo, Cipher, DigestType>,
    expected_measurements: Vec<Measurement>,
    expected_product_id: u16,
    expected_minimum_svn: u16,
    allow_debug: bool,
    trust_anchors: Option<Vec<String>>,
) -> Result<
    (
        AuthPending<KexAlgo, Cipher, DigestType>,
        AuthRequestOutput<Handshake, KexAlgo, Cipher, DigestType>,
    ),
    Error,
>
where
    Handshake: HandshakePattern,
    KexAlgo: Kex,
    Cipher: AeadMut + NewAead + NoiseCipher + Sized,
    DigestType: BlockInput + Clone + Default + Digest + FixedOutput + Input + Reset,
{
    match output.status {
        HandshakeStatus::InProgress(state) => Ok((
            AuthPending::new(
                state,
                expected_measurements,
                expected_product_id,
                expected_minimum_svn,
                allow_debug,
                trust_anchors,
            ),
            AuthRequestOutput::<Handshake, KexAlgo, Cipher, DigestType>::from(output.payload),
        )),
        HandshakeStatus::Complete(_output) => Err(Error::EarlyHandshakeComplete),
    }
}

/// Start + ClientInitiate => AuthPending + AuthRequestOutput
impl<KexAlgo, Cipher, DigestType>
    Transition<
        AuthPending<KexAlgo, Cipher, DigestType>,
        ClientInitiate<KexAlgo, Cipher, DigestType>,
        AuthRequestOutput<HandshakeNX, KexAlgo, Cipher, DigestType>,
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
        _input: ClientInitiate<KexAlgo, Cipher, DigestType>,
    ) -> Result<
        (
            AuthPending<KexAlgo, Cipher, DigestType>,
            AuthRequestOutput<HandshakeNX, KexAlgo, Cipher, DigestType>,
        ),
        Self::Error,
    > {
        let handshake_state = HandshakeState::new(
            true,
            ProtocolName::<HandshakeNX, KexAlgo, Cipher, DigestType>::default(),
            self.responder_id.as_ref(),
            None,
            None,
            None,
            None,
        )
        .map_err(Error::HandshakeInit)?;

        parse_handshake_output(
            handshake_state
                .write_message(csprng, &[])
                .map_err(Error::HandshakeWrite)?,
            self.expected_measurements,
            self.expected_product_id,
            self.expected_minimum_svn,
            self.allow_debug,
            self.trust_anchors,
        )
    }
}

/// Start + NodeInitiate => AuthPending + AuthRequestOutput
impl<KexAlgo, Cipher, DigestType>
    Transition<
        AuthPending<KexAlgo, Cipher, DigestType>,
        NodeInitiate<KexAlgo, Cipher, DigestType>,
        AuthRequestOutput<HandshakeIX, KexAlgo, Cipher, DigestType>,
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
        input: NodeInitiate<KexAlgo, Cipher, DigestType>,
    ) -> Result<
        (
            AuthPending<KexAlgo, Cipher, DigestType>,
            AuthRequestOutput<HandshakeIX, KexAlgo, Cipher, DigestType>,
        ),
        Self::Error,
    > {
        let handshake_state = HandshakeState::new(
            true,
            ProtocolName::<HandshakeIX, KexAlgo, Cipher, DigestType>::default(),
            self.responder_id.as_ref(),
            Some(input.local_identity),
            None,
            None,
            None,
        )
        .map_err(Error::HandshakeInit)?;

        // FIXME: MC-72
        let serialized_report =
            serialize(&input.ias_report).map_err(|_e| Error::ReportSerialization)?;

        parse_handshake_output(
            handshake_state
                .write_message(csprng, &serialized_report)
                .map_err(Error::HandshakeWrite)?,
            self.expected_measurements,
            self.expected_product_id,
            self.expected_minimum_svn,
            self.allow_debug,
            self.trust_anchors,
        )
    }
}

/// AuthPending + AuthResponseInput => Ready + AuthSuccess
impl<KexAlgo, Cipher, DigestType> Transition<Ready<Cipher>, AuthResponse, AuthSuccess>
    for AuthPending<KexAlgo, Cipher, DigestType>
where
    KexAlgo: Kex,
    Cipher: AeadMut + NewAead + NoiseCipher + Sized,
    DigestType: BlockInput + Clone + Default + Digest + FixedOutput + Input + Reset,
{
    type Error = Error;

    fn try_next(
        self,
        _csprng: &mut (impl CryptoRng + RngCore),
        input: AuthResponse,
    ) -> Result<(Ready<Cipher>, AuthSuccess), Self::Error> {
        let output = self
            .state
            .read_message(input.as_ref())
            .map_err(Error::HandshakeRead)?;
        match output.status {
            HandshakeStatus::InProgress(_state) => Err(Error::HandshakeNotComplete),
            HandshakeStatus::Complete(result) => {
                let remote_report: VerificationReport =
                    deserialize(&output.payload).map_err(|_e| Error::ReportDeserialization)?;
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
                    &result
                        .remote_identity
                        .as_ref()
                        .ok_or(Error::MissingRemoteIdentity)?
                        .map_bytes(|bytes| {
                            ReportDataMask::try_from(bytes).map_err(|_| Error::BadRemoteIdentity)
                        })?,
                )?;
                Ok((
                    Ready {
                        writer: result.initiator_cipher,
                        reader: result.responder_cipher,
                        binding: result.channel_binding,
                    },
                    (),
                ))
            }
        }
    }
}
