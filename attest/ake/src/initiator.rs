// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Initiator-specific transition functions

use crate::{
    alloc::string::ToString, AuthPending, AuthRequestOutput, AuthResponseInput, ClientInitiate,
    Error, NodeInitiate, Ready, Start, Terminated, Transition, UnverifiedAttestationEvidence,
};
use mc_attest_core::{EnclaveReportDataContents, EvidenceKind, ReportDataMask, VerificationReport};
use mc_attest_verifier::{DcapVerifier, Error as VerifierError, Verifier, DEBUG_ENCLAVE};
use mc_attestation_verifier::{Evidence, VerificationTreeDisplay};
use mc_crypto_keys::{Kex, ReprBytes};
use mc_crypto_noise::{
    HandshakeIX, HandshakeNX, HandshakeOutput, HandshakePattern, HandshakeState, HandshakeStatus,
    NoiseCipher, NoiseDigest, ProtocolName,
};
use mc_sgx_dcap_types::{Collateral, Quote3};
use prost::Message;
use rand_core::{CryptoRng, RngCore};

/// Helper function to create the output for an initiate
fn parse_handshake_output<Handshake, KexAlgo, Cipher, DigestAlgo>(
    output: HandshakeOutput<KexAlgo, Cipher, DigestAlgo>,
) -> Result<
    (
        AuthPending<KexAlgo, Cipher, DigestAlgo>,
        AuthRequestOutput<Handshake, KexAlgo, Cipher, DigestAlgo>,
    ),
    Error,
>
where
    Handshake: HandshakePattern,
    KexAlgo: Kex,
    Cipher: NoiseCipher,
    DigestAlgo: NoiseDigest,
{
    match output.status {
        HandshakeStatus::InProgress(state) => Ok((
            AuthPending::new(state),
            AuthRequestOutput::<Handshake, KexAlgo, Cipher, DigestAlgo>::from(output.payload),
        )),
        HandshakeStatus::Complete(_output) => Err(Error::EarlyHandshakeComplete),
    }
}

/// Start + ClientInitiate => AuthPending + AuthRequestOutput
impl<KexAlgo, Cipher, DigestAlgo>
    Transition<
        AuthPending<KexAlgo, Cipher, DigestAlgo>,
        ClientInitiate<KexAlgo, Cipher, DigestAlgo>,
        AuthRequestOutput<HandshakeNX, KexAlgo, Cipher, DigestAlgo>,
    > for Start
where
    KexAlgo: Kex,
    Cipher: NoiseCipher,
    DigestAlgo: NoiseDigest,
    ProtocolName<HandshakeNX, KexAlgo, Cipher, DigestAlgo>: AsRef<str>,
{
    type Error = Error;

    fn try_next<R: CryptoRng + RngCore>(
        self,
        csprng: &mut R,
        _input: ClientInitiate<KexAlgo, Cipher, DigestAlgo>,
    ) -> Result<
        (
            AuthPending<KexAlgo, Cipher, DigestAlgo>,
            AuthRequestOutput<HandshakeNX, KexAlgo, Cipher, DigestAlgo>,
        ),
        Self::Error,
    > {
        let handshake_state = HandshakeState::new(
            true,
            ProtocolName::<HandshakeNX, KexAlgo, Cipher, DigestAlgo>::default(),
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
impl<KexAlgo, Cipher, DigestAlgo>
    Transition<
        AuthPending<KexAlgo, Cipher, DigestAlgo>,
        NodeInitiate<KexAlgo, Cipher, DigestAlgo>,
        AuthRequestOutput<HandshakeIX, KexAlgo, Cipher, DigestAlgo>,
    > for Start
where
    KexAlgo: Kex,
    Cipher: NoiseCipher,
    DigestAlgo: NoiseDigest,
    ProtocolName<HandshakeIX, KexAlgo, Cipher, DigestAlgo>: AsRef<str>,
{
    type Error = Error;

    fn try_next<R: CryptoRng + RngCore>(
        self,
        csprng: &mut R,
        input: NodeInitiate<KexAlgo, Cipher, DigestAlgo>,
    ) -> Result<
        (
            AuthPending<KexAlgo, Cipher, DigestAlgo>,
            AuthRequestOutput<HandshakeIX, KexAlgo, Cipher, DigestAlgo>,
        ),
        Self::Error,
    > {
        let handshake_state = HandshakeState::new(
            true,
            ProtocolName::<HandshakeIX, KexAlgo, Cipher, DigestAlgo>::default(),
            self.responder_id.as_ref(),
            Some(input.local_identity),
            None,
            None,
            None,
        )
        .map_err(Error::HandshakeInit)?;
        let serialized_evidence = input.attestation_evidence.into_bytes();

        parse_handshake_output(
            handshake_state
                .write_message(csprng, &serialized_evidence)
                .map_err(Error::HandshakeWrite)?,
        )
    }
}

/// AuthPending + AuthResponseInput => Ready + EvidenceKind
impl<KexAlgo, Cipher, DigestAlgo> Transition<Ready<Cipher>, AuthResponseInput, EvidenceKind>
    for AuthPending<KexAlgo, Cipher, DigestAlgo>
where
    KexAlgo: Kex,
    Cipher: NoiseCipher,
    DigestAlgo: NoiseDigest,
{
    type Error = Error;

    fn try_next<R: CryptoRng + RngCore>(
        self,
        _csprng: &mut R,
        input: AuthResponseInput,
    ) -> Result<(Ready<Cipher>, EvidenceKind), Self::Error> {
        let output = self
            .state
            .read_message(input.as_ref())
            .map_err(Error::HandshakeRead)?;
        match output.status {
            HandshakeStatus::InProgress(_state) => Err(Error::HandshakeNotComplete),
            HandshakeStatus::Complete(result) => {
                if let Ok(remote_evidence) = EvidenceKind::from_bytes(output.payload.as_slice()) {
                    let (quote, collateral, report_data) = match remote_evidence.clone() {
                        EvidenceKind::Dcap(mc_attest_verifier_types::prost::DcapEvidence {
                            quote: Some(quote),
                            collateral: Some(collateral),
                            report_data: Some(report_data),
                        }) => (quote, collateral, report_data),
                        _ => Err(Error::AttestationEvidenceDeserialization)?,
                    };
                    let quote = Quote3::try_from(&quote)
                        .map_err(|_| Error::AttestationEvidenceDeserialization)?;
                    let collateral = Collateral::try_from(&collateral)
                        .map_err(|_| Error::AttestationEvidenceDeserialization)?;
                    let report_data = EnclaveReportDataContents::try_from(&report_data)
                        .map_err(|_| Error::AttestationEvidenceDeserialization)?;
                    let verifier = DcapVerifier::new(input.identities, input.time, report_data);
                    let evidence = Evidence::new(quote, collateral)
                        .map_err(|_| Error::AttestationEvidenceDeserialization)?;
                    let verification_output = verifier.verify(&evidence);
                    if verification_output.is_success().into() {
                        Ok((
                            Ready {
                                writer: result.initiator_cipher,
                                reader: result.responder_cipher,
                                binding: result.channel_binding,
                            },
                            remote_evidence,
                        ))
                    } else {
                        let display_tree =
                            VerificationTreeDisplay::new(&verifier, verification_output);
                        Err(Error::AttestationEvidenceVerification(
                            VerifierError::Verification(display_tree.to_string()),
                        ))
                    }
                } else {
                    let remote_report = VerificationReport::decode(output.payload.as_slice())
                        .map_err(|_| Error::AttestationEvidenceDeserialization)?;

                    let identities = input.identities;
                    let mut verifier = Verifier::default();
                    verifier.identities(&identities).debug(DEBUG_ENCLAVE);

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
                        EvidenceKind::Epid(remote_report),
                    ))
                }
            }
        }
    }
}

/// AuthPending + UnverifiedAttestationEvidence => Terminated + EvidenceKind
impl<KexAlgo, Cipher, DigestAlgo>
    Transition<Terminated, UnverifiedAttestationEvidence, EvidenceKind>
    for AuthPending<KexAlgo, Cipher, DigestAlgo>
where
    KexAlgo: Kex,
    Cipher: NoiseCipher,
    DigestAlgo: NoiseDigest,
{
    type Error = Error;

    fn try_next<R: CryptoRng + RngCore>(
        self,
        _csprng: &mut R,
        input: UnverifiedAttestationEvidence,
    ) -> Result<(Terminated, EvidenceKind), Self::Error> {
        let output = self
            .state
            .read_message(input.as_ref())
            .map_err(Error::HandshakeRead)?;
        match output.status {
            HandshakeStatus::InProgress(_state) => Err(Error::HandshakeNotComplete),
            HandshakeStatus::Complete(_) => {
                if let Ok(remote_evidence) = EvidenceKind::from_bytes(output.payload.as_slice()) {
                    Ok((Terminated, remote_evidence))
                } else {
                    let remote_report = VerificationReport::decode(output.payload.as_slice())
                        .map_err(|_| Error::AttestationEvidenceDeserialization)?;

                    Ok((Terminated, EvidenceKind::Epid(remote_report)))
                }
            }
        }
    }
}
