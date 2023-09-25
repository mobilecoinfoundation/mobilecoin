// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Responder-specific transition functions
use crate::{
    error::Error,
    event::{AuthResponseOutput, ClientAuthRequestInput, NodeAuthRequestInput},
    mealy::Transition,
    state::{Ready, Start},
};
use ::prost::Message;
use alloc::{string::ToString, vec::Vec};
use mc_attest_verifier::DcapVerifier;
use mc_attest_verifier_types::{prost, DcapEvidence};
use mc_attestation_verifier::{Evidence, VerificationTreeDisplay};
use mc_crypto_keys::Kex;
use mc_crypto_noise::{
    HandshakeIX, HandshakeNX, HandshakePattern, HandshakeState, HandshakeStatus, NoiseCipher,
    NoiseDigest, ProtocolName,
};
use rand_core::{CryptoRng, RngCore};

/// A trait containing default implementations, used to tack repeatable chunks
/// of code onto the "Start" state for use below.
trait ResponderTransitionMixin {
    fn handle_request<Handshake, KexAlgo, Cipher, DigestAlgo>(
        &self,
        data: &[u8],
        local_identity: KexAlgo::Private,
    ) -> Result<(HandshakeState<KexAlgo, Cipher, DigestAlgo>, Vec<u8>), Error>
    where
        Handshake: HandshakePattern,
        KexAlgo: Kex,
        Cipher: NoiseCipher,
        DigestAlgo: NoiseDigest,
        ProtocolName<Handshake, KexAlgo, Cipher, DigestAlgo>: AsRef<str>;

    fn handle_response<KexAlgo, Cipher, DigestAlgo>(
        csprng: &mut (impl CryptoRng + RngCore),
        handshake_state: HandshakeState<KexAlgo, Cipher, DigestAlgo>,
        attestation_evidence: DcapEvidence,
    ) -> Result<(Ready<Cipher>, AuthResponseOutput), Error>
    where
        KexAlgo: Kex,
        Cipher: NoiseCipher,
        DigestAlgo: NoiseDigest;
}

impl ResponderTransitionMixin for Start {
    fn handle_request<Handshake, KexAlgo, Cipher, DigestAlgo>(
        &self,
        data: &[u8],
        local_identity: KexAlgo::Private,
    ) -> Result<(HandshakeState<KexAlgo, Cipher, DigestAlgo>, Vec<u8>), Error>
    where
        Handshake: HandshakePattern,
        KexAlgo: Kex,
        Cipher: NoiseCipher,
        DigestAlgo: NoiseDigest,
        ProtocolName<Handshake, KexAlgo, Cipher, DigestAlgo>: AsRef<str>,
    {
        let handshake_state = HandshakeState::new(
            false,
            ProtocolName::<Handshake, KexAlgo, Cipher, DigestAlgo>::default(),
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

    fn handle_response<KexAlgo, Cipher, DigestAlgo>(
        csprng: &mut (impl CryptoRng + RngCore),
        handshake_state: HandshakeState<KexAlgo, Cipher, DigestAlgo>,
        attestation_evidence: DcapEvidence,
    ) -> Result<(Ready<Cipher>, AuthResponseOutput), Error>
    where
        KexAlgo: Kex,
        Cipher: NoiseCipher,
        DigestAlgo: NoiseDigest,
    {
        let serialized_evidence = prost::DcapEvidence::try_from(&attestation_evidence)
            .map_err(|_| Error::AttestationEvidenceSerialization)?
            .encode_to_vec();

        let output = handshake_state
            .write_message(csprng, &serialized_evidence)
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
impl<KexAlgo, Cipher, DigestAlgo>
    Transition<Ready<Cipher>, NodeAuthRequestInput<KexAlgo, Cipher, DigestAlgo>, AuthResponseOutput>
    for Start
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
        input: NodeAuthRequestInput<KexAlgo, Cipher, DigestAlgo>,
    ) -> Result<(Ready<Cipher>, AuthResponseOutput), Error> {
        // Read the request and return the payload and state
        let (handshake_state, payload) = self
            .handle_request::<HandshakeIX, KexAlgo, Cipher, DigestAlgo>(
                &input.data.data,
                input.local_identity,
            )?;

        let identities = input.identities;

        // Parse the received DCAP evidence from the other node
        let prost_evidence = prost::DcapEvidence::decode(payload.as_slice())
            .map_err(|_| Error::AttestationEvidenceDeserialization)?;
        let dcap_evidence = DcapEvidence::try_from(&prost_evidence)
            .map_err(|_| Error::AttestationEvidenceDeserialization)?;

        let DcapEvidence {
            quote,
            collateral,
            report_data,
        } = dcap_evidence;

        let verifier = DcapVerifier::new(identities, None, report_data);
        let evidence = Evidence::new(quote, collateral).expect("Failed to get evidence");

        let verification = verifier.verify(&evidence);
        if verification.is_failure().into() {
            let display_tree = VerificationTreeDisplay::new(&verifier, verification);
            return Err(mc_attest_verifier::Error::Verification(display_tree.to_string()).into());
        }

        // Provide a response with our local DCAP evidence
        Self::handle_response(csprng, handshake_state, input.attestation_evidence)
    }
}

/// Start + ClientAuthRequestInput => Ready + AuthResponseOutput
impl<KexAlgo, Cipher, DigestAlgo>
    Transition<
        Ready<Cipher>,
        ClientAuthRequestInput<KexAlgo, Cipher, DigestAlgo>,
        AuthResponseOutput,
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
        input: ClientAuthRequestInput<KexAlgo, Cipher, DigestAlgo>,
    ) -> Result<(Ready<Cipher>, AuthResponseOutput), Error> {
        let (handshake_state, _payload) = self
            .handle_request::<HandshakeNX, KexAlgo, Cipher, DigestAlgo>(
                &input.data.data,
                input.local_identity,
            )?;
        Self::handle_response(csprng, handshake_state, input.attestation_evidence)
    }
}
