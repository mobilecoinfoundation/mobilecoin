// Copyright (c) 2018-2020 MobileCoin Inc.

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

impl Into<AuthResponseOutput> for AuthMessage {
    fn into(self) -> AuthResponseOutput {
        let mut taken_self = self;
        AuthResponseOutput::from(taken_self.take_data())
    }
}

impl Into<PeerAuthRequest> for AuthMessage {
    fn into(self) -> PeerAuthRequest {
        self.data.into()
    }
}

impl From<PeerAuthRequest> for AuthMessage {
    fn from(src: PeerAuthRequest) -> AuthMessage {
        let mut retval = AuthMessage::default();
        retval.set_data(src.into());
        retval
    }
}

impl Into<ClientAuthRequest> for AuthMessage {
    fn into(self) -> ClientAuthRequest {
        self.data.into()
    }
}

impl From<ClientAuthRequest> for AuthMessage {
    fn from(src: ClientAuthRequest) -> AuthMessage {
        let mut retval = AuthMessage::default();
        retval.set_data(src.into());
        retval
    }
}

impl Into<PeerAuthResponse> for AuthMessage {
    fn into(self) -> PeerAuthResponse {
        self.data.into()
    }
}

impl From<PeerAuthResponse> for AuthMessage {
    fn from(src: PeerAuthResponse) -> AuthMessage {
        let mut retval = AuthMessage::default();
        retval.set_data(src.into());
        retval
    }
}

impl Into<ClientAuthResponse> for AuthMessage {
    fn into(self) -> ClientAuthResponse {
        self.data.into()
    }
}

impl From<ClientAuthResponse> for AuthMessage {
    fn from(src: ClientAuthResponse) -> AuthMessage {
        let mut retval = AuthMessage::default();
        retval.set_data(src.into());
        retval
    }
}

impl<S: Session> Into<EnclaveMessage<S>> for Message {
    fn into(self) -> EnclaveMessage<S> {
        EnclaveMessage {
            aad: self.aad,
            channel_id: S::from(&self.channel_id),
            data: self.data,
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
