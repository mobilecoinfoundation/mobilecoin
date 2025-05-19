// Copyright (c) 2018-2023 The MobileCoin Foundation

use aes_gcm::Aes256Gcm;
use der::DateTime;
use futures::{executor::block_on, SinkExt, TryStreamExt};
use grpcio::{ChannelBuilder, ClientDuplexReceiver, ClientDuplexSender, Environment};
use mc_attest_ake::{
    AuthResponseInput, ClientInitiate, Error as AttestAkeError, Ready, Start, Transition,
};
use mc_attest_core::EvidenceKind;
use mc_attestation_verifier::TrustedIdentity;
use mc_common::{
    logger::{log, o, Logger},
    time::{SystemTimeProvider, TimeProvider},
    trace_time,
};
use mc_crypto_keys::X25519;
use mc_crypto_noise::CipherError;
use mc_fog_api::{
    attest::{AuthMessage, Message},
    fog_ledger::{ledger_request, ledger_response, LedgerApiClient, LedgerRequest, LedgerResponse},
};
use mc_fog_types::ledger::{CheckKeyImagesRequest, CheckKeyImagesResponse, KeyImageQuery};
use mc_fog_uri::FogLedgerUri;
use mc_rand::McRng;
use mc_transaction_core::ring_signature::KeyImage;
use mc_util_grpc::ConnectionUriGrpcioChannel;
use mc_util_serial::DecodeError;
use mc_util_uri::{ConnectionUri, UriConversionError};
use sha2::Sha512;
use std::sync::Arc;

/// A high-level object mediating requests to the fog ledger router service
pub struct LedgerGrpcClient {
    /// A logger object
    logger: Logger,

    /// The URI of the router to communicate with
    uri: FogLedgerUri,

    /// The identities that a fog node's attestation evidence must match, one of
    identities: Vec<TrustedIdentity>,

    /// The AKE state machine object, if one is available.
    attest_cipher: Option<Ready<Aes256Gcm>>,

    /// Sends requests to the fog ledger router
    request_sender: ClientDuplexSender<LedgerRequest>,

    /// Receives responses from the fog ledger router
    response_receiver: ClientDuplexReceiver<LedgerResponse>,

    /// Low-lever ledger API client
    _client: LedgerApiClient,
}

impl LedgerGrpcClient {
    /// Creates a new fog ledger router grpc client and opens a streaming
    /// connection to the fog ledger router service.
    ///
    /// Arguments:
    /// * uri: The Uri to connect to
    /// * identities: The identities that are allowed for attestation
    /// * env: A grpc environment (thread pool) to use for this connection
    /// * logger: For logging
    pub fn new(
        uri: FogLedgerUri,
        identities: impl Into<Vec<TrustedIdentity>>,
        env: Arc<Environment>,
        logger: Logger,
    ) -> Self {
        let logger = logger.new(o!("mc.fog.ledger.router.uri" => uri.to_string()));

        let ch = ChannelBuilder::default_channel_builder(env).connect_to_uri(&uri, &logger);
        let client = LedgerApiClient::new(ch);
        let (request_sender, response_receiver) = client
            .request()
            .expect("Could not retrieve grpc sender and receiver.");

        Self {
            logger,
            attest_cipher: None,
            _client: client,
            request_sender,
            response_receiver,
            uri,
            identities: identities.into(),
        }
    }

    fn is_attested(&self) -> bool {
        self.attest_cipher.is_some()
    }

    async fn attest(&mut self) -> Result<EvidenceKind, Error> {
        // If we have an existing attestation, nuke it.
        self.deattest();

        let mut csprng = McRng;

        let initiator = Start::new(self.uri.responder_id()?.to_string());

        let init_input = ClientInitiate::<X25519, Aes256Gcm, Sha512>::default();
        let (initiator, auth_request_output) = initiator.try_next(&mut csprng, init_input)?;

        let attested_message: AuthMessage = auth_request_output.into();
        let request = LedgerRequest {
            request_data: Some(ledger_request::RequestData::Auth(attested_message)),
        };
        self.request_sender
            .send((request.clone(), grpcio::WriteFlags::default()))
            .await?;

        let response = self
            .response_receiver
            .try_next()
            .await?
            .ok_or(Error::ResponseNotReceived)?;
        let auth_response_msg = if let Some(ledger_response::ResponseData::Auth(auth_response)) =
            response.response_data
        {
            auth_response
        } else {
            Default::default()
        };

        let epoch_time = SystemTimeProvider
            .since_epoch()
            .map_err(|_| Error::Other("Time went backwards".to_owned()))?;
        let time = DateTime::from_unix_duration(epoch_time)
            .map_err(|_| Error::Other("Time out of range".to_owned()))?;

        // Process server response, check if key exchange is successful
        let auth_response_event =
            AuthResponseInput::new(auth_response_msg.into(), self.identities.clone(), time);
        let (initiator, attestation_evidence) =
            initiator.try_next(&mut csprng, auth_response_event)?;

        self.attest_cipher = Some(initiator);

        Ok(attestation_evidence)
    }

    fn deattest(&mut self) {
        if self.is_attested() {
            log::trace!(self.logger, "Tearing down existing attested connection.");
            self.attest_cipher = None;
        }
    }

    /// Check one or more key images against the ledger router service
    pub async fn check_key_images(
        &mut self,
        key_images: &[KeyImage],
    ) -> Result<CheckKeyImagesResponse, Error> {
        trace_time!(self.logger, "LedgerGrpcClient::check_key_images");

        if !self.is_attested() {
            let verification_report = self.attest().await;
            verification_report?;
        }

        let key_images_queries = key_images
            .iter()
            .map(|&key_image| KeyImageQuery {
                key_image,
                start_block: 0,
            })
            .collect();
        let key_images_request = CheckKeyImagesRequest {
            queries: key_images_queries,
        };

        // No authenticated data associated with ledger query
        let aad = vec![];

        let msg = {
            let attest_cipher = self
                .attest_cipher
                .as_mut()
                .expect("no enclave_connection even though attest succeeded");

            let plaintext_bytes = mc_util_serial::encode(&key_images_request);

            let request_ciphertext = attest_cipher.encrypt(&aad, &plaintext_bytes)?;
            Message {
                channel_id: Vec::from(attest_cipher.binding()),
                aad: aad.clone(),
                data: request_ciphertext,
            }
        };
        let request = LedgerRequest {
            request_data: Some(ledger_request::RequestData::CheckKeyImages(msg)),
        };

        self.request_sender
            .send((request.clone(), grpcio::WriteFlags::default()))
            .await?;

        let response = self
            .response_receiver
            .try_next()
            .await?
            .ok_or(Error::ResponseNotReceived)?;
        let message = if let Some(ledger_response::ResponseData::CheckKeyImageResponse(msg)) =
            response.response_data
        {
            msg
        } else {
            Default::default()
        };

        {
            let attest_cipher = self
                .attest_cipher
                .as_mut()
                .expect("no enclave_connection even though attest succeeded");

            let plaintext_bytes =
                attest_cipher.decrypt(message.aad.as_slice(), message.data.as_slice())?;
            let plaintext_response: CheckKeyImagesResponse =
                mc_util_serial::decode(&plaintext_bytes)?;
            Ok(plaintext_response)
        }
    }
}

impl Drop for LedgerGrpcClient {
    fn drop(&mut self) {
        block_on(self.request_sender.close()).expect("Couldn't close the router request sender");
    }
}

/// Errors related to the Fog View Router Client.
#[derive(Debug)]
pub enum Error {
    /// Decode errors.
    Decode(DecodeError),

    /// Uri conversion errors.
    UriConversion(UriConversionError),

    /// Cipher errors.
    Cipher(CipherError),

    /// Attestation errors.
    Attestation(AttestAkeError),

    /// Grpc errors.
    Grpc(grpcio::Error),

    /// Response not received
    ResponseNotReceived,

    /// Other
    Other(String),
}

impl From<DecodeError> for Error {
    fn from(err: DecodeError) -> Self {
        Self::Decode(err)
    }
}

impl From<CipherError> for Error {
    fn from(err: CipherError) -> Self {
        Self::Cipher(err)
    }
}

impl From<grpcio::Error> for Error {
    fn from(err: grpcio::Error) -> Self {
        Self::Grpc(err)
    }
}

impl From<UriConversionError> for Error {
    fn from(err: UriConversionError) -> Self {
        Self::UriConversion(err)
    }
}

impl From<AttestAkeError> for Error {
    fn from(err: AttestAkeError) -> Self {
        Self::Attestation(err)
    }
}
