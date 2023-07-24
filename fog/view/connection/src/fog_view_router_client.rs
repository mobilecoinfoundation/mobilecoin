// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Makes requests to the fog view router service

use aes_gcm::Aes256Gcm;
use futures::{executor::block_on, SinkExt, TryStreamExt};
use grpcio::{ChannelBuilder, ClientDuplexReceiver, ClientDuplexSender, Environment};
use mc_attest_ake::{
    AuthResponseInput, ClientInitiate, Error as AttestAkeError, Ready, Start, Transition,
};
use mc_attest_api::attest::{AuthMessage, Message};
use mc_attest_core::VerificationReport;
use mc_attestation_verifier::TrustedIdentity;
use mc_common::logger::{log, o, Logger};
use mc_crypto_keys::X25519;
use mc_crypto_noise::CipherError;
use mc_fog_api::{
    view::{FogViewRouterRequest, FogViewRouterResponse},
    view_grpc::FogViewRouterApiClient,
};
use mc_fog_types::view::{QueryRequest, QueryRequestAAD, QueryResponse};
use mc_fog_uri::{ConnectionUri, FogViewRouterUri};
use mc_rand::McRng;
use mc_util_grpc::ConnectionUriGrpcioChannel;
use mc_util_serial::DecodeError;
use mc_util_uri::UriConversionError;
use sha2::Sha512;
use std::sync::Arc;

/// A high-level object mediating requests to the fog view router service
pub struct FogViewRouterGrpcClient {
    /// A logger object
    logger: Logger,

    /// The AKE state machine object, if one is available.
    attest_cipher: Option<Ready<Aes256Gcm>>,

    _fog_view_router_client: FogViewRouterApiClient,

    /// Sends requests to the fog view router
    request_sender: ClientDuplexSender<FogViewRouterRequest>,

    /// Receives responses from the fog view router
    response_receiver: ClientDuplexReceiver<FogViewRouterResponse>,

    uri: FogViewRouterUri,

    /// The identities that a fog node's IAS report must match one of
    identities: Vec<TrustedIdentity>,
}

impl FogViewRouterGrpcClient {
    /// Creates a new fog view router grpc client and opens a streaming
    /// connection to the fog view router service.
    ///
    /// Arguments:
    /// * uri: The Uri to connect to
    /// * identities: The identities that are allowed for attestation
    /// * env: A grpc environment (thread pool) to use for this connection
    /// * logger: For logging
    pub fn new(
        uri: FogViewRouterUri,
        identities: impl Into<Vec<TrustedIdentity>>,
        env: Arc<Environment>,
        logger: Logger,
    ) -> Self {
        let logger = logger.new(o!("mc.fog.view.router.uri" => uri.to_string()));

        let ch = ChannelBuilder::default_channel_builder(env).connect_to_uri(&uri, &logger);
        let fog_view_router_client = FogViewRouterApiClient::new(ch);
        let (request_sender, response_receiver) = fog_view_router_client
            .request()
            .expect("Could not retrieve grpc sender and receiver.");

        Self {
            logger,
            attest_cipher: None,
            _fog_view_router_client: fog_view_router_client,
            request_sender,
            response_receiver,
            uri,
            identities: identities.into(),
        }
    }

    fn is_attested(&self) -> bool {
        self.attest_cipher.is_some()
    }

    async fn attest(&mut self) -> Result<VerificationReport, Error> {
        // If we have an existing attestation, nuke it.
        self.deattest();

        let mut csprng = McRng::default();

        let initiator = Start::new(self.uri.responder_id()?.to_string());

        let init_input = ClientInitiate::<X25519, Aes256Gcm, Sha512>::default();
        let (initiator, auth_request_output) = initiator.try_next(&mut csprng, init_input)?;

        let attested_message: AuthMessage = auth_request_output.into();
        let mut request = FogViewRouterRequest::new();
        request.set_auth(attested_message);
        self.request_sender
            .send((request, grpcio::WriteFlags::default()))
            .await?;

        let mut response = self
            .response_receiver
            .try_next()
            .await?
            .ok_or(Error::ResponseNotReceived)?;
        let auth_response_msg = response.take_auth();

        // Process server response, check if key exchange is successful
        let auth_response_event =
            AuthResponseInput::new(auth_response_msg.into(), self.identities.clone());
        let (initiator, verification_report) =
            initiator.try_next(&mut csprng, auth_response_event)?;

        self.attest_cipher = Some(initiator);

        Ok(verification_report)
    }

    fn deattest(&mut self) {
        if self.is_attested() {
            log::trace!(self.logger, "Tearing down existing attested connection.");
            self.attest_cipher = None;
        }
    }

    /// Makes streaming requests to the fog view router service.
    pub async fn query(
        &mut self,
        start_from_user_event_id: i64,
        start_from_block_index: u64,
        search_keys: Vec<Vec<u8>>,
    ) -> Result<QueryResponse, Error> {
        log::trace!(self.logger, "Query was called");
        if !self.is_attested() {
            let verification_report = self.attest().await;
            verification_report?;
        }

        let plaintext_request = QueryRequest {
            get_txos: search_keys,
        };

        let req_aad = QueryRequestAAD {
            start_from_user_event_id,
            start_from_block_index,
        };

        let aad = mc_util_serial::encode(&req_aad);

        let msg = {
            let attest_cipher = self
                .attest_cipher
                .as_mut()
                .expect("no enclave_connection even though attest succeeded");

            let mut msg = Message::new();
            msg.set_channel_id(Vec::from(attest_cipher.binding()));
            msg.set_aad(aad.clone());

            let plaintext_bytes = mc_util_serial::encode(&plaintext_request);

            let request_ciphertext = attest_cipher.encrypt(&aad, &plaintext_bytes)?;
            msg.set_data(request_ciphertext);
            msg
        };
        let mut request = FogViewRouterRequest::new();
        request.set_query(msg);

        self.request_sender
            .send((request, grpcio::WriteFlags::default()))
            .await?;

        let message = self
            .response_receiver
            .try_next()
            .await?
            .ok_or(Error::ResponseNotReceived)?
            .take_query();

        {
            let attest_cipher = self
                .attest_cipher
                .as_mut()
                .expect("no enclave_connection even though attest succeeded");

            let plaintext_bytes = attest_cipher.decrypt(message.get_aad(), message.get_data())?;
            let plaintext_response: QueryResponse = mc_util_serial::decode(&plaintext_bytes)?;
            Ok(plaintext_response)
        }
    }
}

impl Drop for FogViewRouterGrpcClient {
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
