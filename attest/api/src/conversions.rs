// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Conversions from gRPC message types into consensus_enclave_api types.

use crate::attest::{AuthMessage, Message, NonceMessage};
use mc_attest_ake::{AuthRequestOutput, AuthResponseOutput};
use mc_attest_enclave_api::{
    ClientAuthRequest, ClientAuthResponse, EnclaveMessage, NonceAuthRequest, NonceAuthResponse,
    NonceSession, PeerAuthRequest, PeerAuthResponse, Session,
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
        let mut retval = Self::default();
        retval.set_data(src.into());
        retval
    }
}

impl From<AuthMessage> for AuthResponseOutput {
    fn from(src: AuthMessage) -> AuthResponseOutput {
        let mut taken_self = src;
        AuthResponseOutput::from(taken_self.take_data())
    }
}

impl From<AuthMessage> for PeerAuthRequest {
    fn from(src: AuthMessage) -> PeerAuthRequest {
        src.data.into()
    }
}

impl From<PeerAuthRequest> for AuthMessage {
    fn from(src: PeerAuthRequest) -> AuthMessage {
        let mut retval = AuthMessage::default();
        retval.set_data(src.into());
        retval
    }
}

impl From<AuthMessage> for ClientAuthRequest {
    fn from(src: AuthMessage) -> ClientAuthRequest {
        src.data.into()
    }
}

impl From<ClientAuthRequest> for AuthMessage {
    fn from(src: ClientAuthRequest) -> AuthMessage {
        let mut retval = AuthMessage::default();
        retval.set_data(src.into());
        retval
    }
}

impl From<AuthMessage> for NonceAuthRequest {
    fn from(src: AuthMessage) -> NonceAuthRequest {
        src.data.into()
    }
}

impl From<NonceAuthRequest> for AuthMessage {
    fn from(src: NonceAuthRequest) -> AuthMessage {
        let mut retval = AuthMessage::default();
        retval.set_data(src.into());
        retval
    }
}

impl From<AuthMessage> for NonceAuthResponse {
    fn from(src: AuthMessage) -> NonceAuthResponse {
        src.data.into()
    }
}

impl From<NonceAuthResponse> for AuthMessage {
    fn from(src: NonceAuthResponse) -> AuthMessage {
        let mut retval = AuthMessage::default();
        retval.set_data(src.into());
        retval
    }
}

impl From<AuthMessage> for PeerAuthResponse {
    fn from(src: AuthMessage) -> PeerAuthResponse {
        src.data.into()
    }
}

impl From<PeerAuthResponse> for AuthMessage {
    fn from(src: PeerAuthResponse) -> AuthMessage {
        let mut retval = AuthMessage::default();
        retval.set_data(src.into());
        retval
    }
}

impl From<AuthMessage> for ClientAuthResponse {
    fn from(src: AuthMessage) -> ClientAuthResponse {
        src.data.into()
    }
}

impl From<ClientAuthResponse> for AuthMessage {
    fn from(src: ClientAuthResponse) -> AuthMessage {
        let mut retval = AuthMessage::default();
        retval.set_data(src.into());
        retval
    }
}

impl<S: Session> From<Message> for EnclaveMessage<S> {
    fn from(src: Message) -> EnclaveMessage<S> {
        EnclaveMessage {
            aad: src.aad,
            channel_id: S::from(&src.channel_id),
            data: src.data,
        }
    }
}

impl<S: Session> From<EnclaveMessage<S>> for Message {
    fn from(src: EnclaveMessage<S>) -> Message {
        let mut retval = Message::default();
        retval.set_aad(src.aad);
        retval.set_channel_id(src.channel_id.into());
        retval.set_data(src.data);
        retval
    }
}

impl From<NonceMessage> for EnclaveMessage<NonceSession> {
    fn from(src: NonceMessage) -> Self {
        let channel_id = NonceSession::new(src.channel_id, src.nonce);
        Self {
            aad: src.aad,
            channel_id,
            data: src.data,
        }
    }
}

impl From<EnclaveMessage<NonceSession>> for NonceMessage {
    fn from(src: EnclaveMessage<NonceSession>) -> NonceMessage {
        let mut retval = NonceMessage::default();
        retval.set_aad(src.aad);
        // it doesn't matter if we don't bump the nonce when retrieving it,
        // src.channel_id will be discarded anyways.
        retval.set_nonce(src.channel_id.peek_nonce());
        retval.set_channel_id(src.channel_id.into());
        retval.set_data(src.data);
        retval
    }
}
