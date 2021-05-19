// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Conversions from gRPC message types into consensus_enclave_api types.

use crate::attest::{AuthMessage, Message};
use aead::{AeadMut, NewAead};
use digest::{BlockInput, FixedOutput, Reset, Update};
use mc_attest_ake::{AuthRequestOutput, AuthResponseOutput};
use mc_attest_enclave_api::{
    ClientAuthRequest, ClientAuthResponse, EnclaveMessage, PeerAuthRequest, PeerAuthResponse,
    Session,
};
use mc_crypto_keys::Kex;
use mc_crypto_noise::{HandshakePattern, NoiseCipher};

impl<Handshake, KexAlgo, Cipher, DigestType>
    From<AuthRequestOutput<Handshake, KexAlgo, Cipher, DigestType>> for AuthMessage
where
    Handshake: HandshakePattern,
    KexAlgo: Kex,
    Cipher: AeadMut + NewAead + NoiseCipher + Sized,
    DigestType: BlockInput + Clone + Default + FixedOutput + Update + Reset,
{
    fn from(src: AuthRequestOutput<Handshake, KexAlgo, Cipher, DigestType>) -> Self {
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
        retval.set_channel_id(src.channel_id.clone().into());
        retval.set_data(src.data);
        retval
    }
}
