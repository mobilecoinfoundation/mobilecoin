// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Conversions from gRPC message types into consensus_enclave_api types.

use crate::attest::{AuthMessage, Message};
use mc_attest_ake::{AuthRequestOutput, AuthResponseOutput};
use mc_attest_enclave_api::{
    ClientAuthRequest, ClientAuthResponse, EnclaveMessage, PeerAuthRequest, PeerAuthResponse,
    Session,
};
use mc_crypto_keys::Kex;
use mc_crypto_noise::{HandshakePattern, NoiseCipher, NoiseDigest};

impl<Handshake, KexAlgo, Cipher, DigestAlgo>
    From<AuthRequestOutput<Handshake, KexAlgo, Cipher, DigestAlgo>> for AuthMessage
where
    Handshake: HandshakePattern,
    KexAlgo: Kex,
    Cipher: NoiseCipher,
    DigestAlgo: NoiseDigest,
{
    fn from(src: AuthRequestOutput<Handshake, KexAlgo, Cipher, DigestAlgo>) -> Self {
        Self { data: src.into() }
    }
}

impl From<AuthMessage> for AuthResponseOutput {
    fn from(src: AuthMessage) -> AuthResponseOutput {
        src.data.into()
    }
}

impl From<AuthMessage> for PeerAuthRequest {
    fn from(src: AuthMessage) -> PeerAuthRequest {
        src.data.into()
    }
}

impl From<PeerAuthRequest> for AuthMessage {
    fn from(src: PeerAuthRequest) -> AuthMessage {
        AuthMessage { data: src.into() }
    }
}

impl From<AuthMessage> for ClientAuthRequest {
    fn from(src: AuthMessage) -> ClientAuthRequest {
        src.data.into()
    }
}

impl From<ClientAuthRequest> for AuthMessage {
    fn from(src: ClientAuthRequest) -> AuthMessage {
        AuthMessage { data: src.into() }
    }
}

impl From<AuthMessage> for PeerAuthResponse {
    fn from(src: AuthMessage) -> PeerAuthResponse {
        src.data.into()
    }
}

impl From<PeerAuthResponse> for AuthMessage {
    fn from(src: PeerAuthResponse) -> AuthMessage {
        AuthMessage { data: src.into() }
    }
}

impl From<AuthMessage> for ClientAuthResponse {
    fn from(src: AuthMessage) -> ClientAuthResponse {
        src.data.into()
    }
}

impl From<ClientAuthResponse> for AuthMessage {
    fn from(src: ClientAuthResponse) -> AuthMessage {
        AuthMessage { data: src.into() }
    }
}

impl<S: Session> From<Message> for EnclaveMessage<S> {
    fn from(src: Message) -> EnclaveMessage<S> {
        EnclaveMessage {
            aad: src.aad,
            channel_id: (&src.channel_id[..]).into(),
            data: src.data,
        }
    }
}

impl<S: Session> From<EnclaveMessage<S>> for Message {
    fn from(src: EnclaveMessage<S>) -> Message {
        Message {
            aad: src.aad,
            channel_id: src.channel_id.into(),
            data: src.data,
        }
    }
}
