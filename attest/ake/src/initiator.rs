// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Initiator-specific transition functions

use crate::{
    error::Error,
    event::{AuthRequestOutput, AuthResponseInput, ClientInitiate, NodeInitiate},
    mealy::Transition,
    state::{AuthPending, Ready, Start},
};
use aead::{AeadMut, NewAead};
use alloc::vec::Vec;
use core::convert::TryFrom;
use digest::{BlockInput, Digest, FixedOutput, Reset, Update};
use mc_attest_core::{ReportDataMask, VerificationReport};
use mc_crypto_keys::{Kex, ReprBytes};
use mc_crypto_noise::{
    HandshakeIX, HandshakeNX, HandshakeOutput, HandshakePattern, HandshakeState, HandshakeStatus,
    NoiseCipher, ProtocolName,
};
use prost::Message;
use rand_core::{CryptoRng, RngCore};

/// Helper function to create the output for an initiate
fn parse_handshake_output<Handshake, KexAlgo, Cipher, DigestType>(
    output: HandshakeOutput<KexAlgo, Cipher, DigestType>,
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
    DigestType: BlockInput + Clone + Default + Digest + FixedOutput + Update + Reset,
{
    match output.status {
        HandshakeStatus::InProgress(state) => Ok((
            AuthPending::new(state),
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
    DigestType: BlockInput + Clone + Default + Digest + FixedOutput + Update + Reset,
    ProtocolName<HandshakeNX, KexAlgo, Cipher, DigestType>: AsRef<str>,
{
    type Error = Error;

    fn try_next<R: CryptoRng + RngCore>(
        self,
        csprng: &mut R,
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
    DigestType: BlockInput + Clone + Default + Digest + FixedOutput + Update + Reset,
    ProtocolName<HandshakeIX, KexAlgo, Cipher, DigestType>: AsRef<str>,
{
    type Error = Error;

    fn try_next<R: CryptoRng + RngCore>(
        self,
        csprng: &mut R,
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

        let mut serialized_report = Vec::with_capacity(input.ias_report.encoded_len());
        input
            .ias_report
            .encode(&mut serialized_report)
            .expect("Invariants failure, encoded_len insufficient to encode IAS report");

        parse_handshake_output(
            handshake_state
                .write_message(csprng, &serialized_report)
                .map_err(Error::HandshakeWrite)?,
        )
    }
}

/// AuthPending + AuthResponseInput => Ready + VerificationReport
impl<KexAlgo, Cipher, DigestType> Transition<Ready<Cipher>, AuthResponseInput, VerificationReport>
    for AuthPending<KexAlgo, Cipher, DigestType>
where
    KexAlgo: Kex,
    Cipher: AeadMut + NewAead + NoiseCipher + Sized,
    DigestType: BlockInput + Clone + Default + Digest + FixedOutput + Update + Reset,
{
    type Error = Error;

    fn try_next<R: CryptoRng + RngCore>(
        self,
        _csprng: &mut R,
        input: AuthResponseInput,
    ) -> Result<(Ready<Cipher>, VerificationReport), Self::Error> {
        let output = self
            .state
            .read_message(input.as_ref())
            .map_err(Error::HandshakeRead)?;
        match output.status {
            HandshakeStatus::InProgress(_state) => Err(Error::HandshakeNotComplete),
            HandshakeStatus::Complete(result) => {
                let remote_report = VerificationReport::decode(output.payload.as_slice())
                    .map_err(|_e| Error::ReportDeserialization)?;

                let mut verifier = input.verifier;

                // We are not returning the report data and instead returning the raw report
                // since that also includes the signature and certificate chain.
                // However, we still make sure the report contains valid data
                // before we continue by calling `.verify`. Callers can then
                // safely construct a VerificationReportData object out of the
                // VerificationReport returned.
                let _report_data = verifier
                    .report_data(
                        &result
                            .remote_identity
                            .ok_or(Error::MissingRemoteIdentity)?
                            .map_bytes(|bytes| {
                                ReportDataMask::try_from(bytes)
                                    .map_err(|_| Error::BadRemoteIdentity)
                            })?,
                    )
                    .verify(&remote_report)?;
                Ok((
                    Ready {
                        writer: result.initiator_cipher,
                        reader: result.responder_cipher,
                        binding: result.channel_binding,
                    },
                    remote_report,
                ))
            }
        }
    }
}
