// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Conversions from gRPC message types into attest api types.
pub mod collateral;
pub mod enclave_report_data_contents;
pub mod quote3;

use crate::attest::{AuthMessage, Message, NonceMessage};
use mc_attest_ake::{AuthRequestOutput, AuthResponseOutput};
use mc_attest_enclave_api::{
    ClientAuthRequest, ClientAuthResponse, EnclaveMessage, NonceAuthRequest, NonceAuthResponse,
    NonceSession, PeerAuthRequest, PeerAuthResponse, Session,
};
use mc_attest_verifier_types::ConversionError;
use mc_crypto_keys::Kex;
use mc_crypto_noise::{HandshakePattern, NoiseCipher, NoiseDigest};
use protobuf::{CodedOutputStream, Message as ProtoMessage};

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
        retval.set_nonce(src.channel_id.nonce());
        retval.set_channel_id(src.channel_id.into());
        retval.set_data(src.data);
        retval
    }
}

/// Encode a protobuf type to the protobuf representation.
///
/// This makes it easy to convert from a protobuf to a rust type by way of a
/// prost implementation. While this requires converting to a protobuf stream
/// and back again, this allows for placing most of the complex logic in the
/// `prost` implementation and keeping the local `try_from` implementations
/// simple.
///
/// For example:
/// ```ignore
///     let bytes = encode_to_protobuf_vec(proto_type)?;
///     let prost = prost::TYPENAME::decode(bytes.as_slice())?;
///     let rust_type = TYPENAME::try_from(prost)?;
/// ```
pub(crate) fn encode_to_protobuf_vec<T: ProtoMessage>(msg: &T) -> Result<Vec<u8>, ConversionError> {
    let mut bytes = vec![];
    let mut stream = CodedOutputStream::vec(&mut bytes);
    msg.write_to_with_cached_sizes(&mut stream)
        .map_err(|e| ConversionError::Other(e.to_string()))?;
    stream
        .flush()
        .map_err(|e| ConversionError::Other(e.to_string()))?;
    Ok(bytes)
}
