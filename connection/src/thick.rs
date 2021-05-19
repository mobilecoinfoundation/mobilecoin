// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Connection implementations required for the thick client.
//! The attested client implementation.

use crate::{
    credentials::{AuthenticationError, CredentialsProvider, CredentialsProviderError},
    error::{Error, Result},
    traits::{
        AttestationError, AttestedConnection, BlockInfo, BlockchainConnection, Connection,
        UserTxConnection,
    },
};
use aes_gcm::Aes256Gcm;
use cookie::CookieJar;
use displaydoc::Display;
use grpcio::{CallOption, ChannelBuilder, Environment, Error as GrpcError, MetadataBuilder};
use mc_attest_ake::{
    AuthResponseInput, ClientInitiate, Error as AkeError, Ready, Start, Transition,
};
use mc_attest_api::{attest::Message, attest_grpc::AttestedApiClient};
use mc_attest_core::{VerificationReport, Verifier};
use mc_common::{
    logger::{log, o, Logger},
    trace_time,
};
use mc_consensus_api::{
    consensus_client_grpc::ConsensusClientApiClient,
    consensus_common::{BlocksRequest, ProposeTxResult},
    consensus_common_grpc::BlockchainApiClient,
    empty::Empty,
};
use mc_crypto_keys::X25519;
use mc_crypto_noise::CipherError;
use mc_crypto_rand::McRng;
use mc_transaction_core::{tx::Tx, Block, BlockID, BlockIndex};
use mc_util_grpc::{ConnectionUriGrpcioChannel, GrpcCookieStore};
use mc_util_serial::encode;
use mc_util_uri::{ConnectionUri, ConsensusClientUri as ClientUri, UriConversionError};
use secrecy::{ExposeSecret, SecretVec};
use sha2::Sha512;
use std::{
    cmp::Ordering,
    convert::TryFrom,
    fmt::{Display, Formatter, Result as FmtResult},
    hash::{Hash, Hasher},
    ops::Range,
    result::Result as StdResult,
    sync::Arc,
};

/// Attestation failures a thick client can generate
#[derive(Debug, Display)]
pub enum ThickClientAttestationError {
    /// gRPC failure in attestation: {0}
    Grpc(GrpcError),
    /// Key exchange failure: {0}
    Ake(AkeError),
    /// Encryption/decryption failure in attestation: {0}
    Cipher(CipherError),
    /// Could not create ResponderID from URI {0}: {1}
    InvalidResponderID(String, UriConversionError),
    /// Unexpected Error Converting URI {0}
    UriConversionError(UriConversionError),
    /// Credentials provider error: {0}
    CredentialsProvider(Box<dyn CredentialsProviderError + 'static>),
}

impl From<GrpcError> for ThickClientAttestationError {
    fn from(src: GrpcError) -> Self {
        ThickClientAttestationError::Grpc(src)
    }
}

impl From<AkeError> for ThickClientAttestationError {
    fn from(src: AkeError) -> Self {
        ThickClientAttestationError::Ake(src)
    }
}

impl From<CipherError> for ThickClientAttestationError {
    fn from(src: CipherError) -> Self {
        ThickClientAttestationError::Cipher(src)
    }
}

impl From<UriConversionError> for ThickClientAttestationError {
    fn from(src: UriConversionError) -> Self {
        match src.clone() {
            UriConversionError::ResponderId(uri, _err) => {
                ThickClientAttestationError::InvalidResponderID(uri, src)
            }
            _ => ThickClientAttestationError::UriConversionError(src),
        }
    }
}

impl From<Box<dyn CredentialsProviderError + 'static>> for ThickClientAttestationError {
    fn from(src: Box<dyn CredentialsProviderError + 'static>) -> Self {
        Self::CredentialsProvider(src)
    }
}

impl AuthenticationError for ThickClientAttestationError {
    fn is_unauthenticated(&self) -> bool {
        match self {
            Self::Grpc(grpc_error) => grpc_error.is_unauthenticated(),
            _ => false,
        }
    }
}

impl AttestationError for ThickClientAttestationError {}

/// A connection from a client to a consensus enclave.
pub struct ThickClient<CP: CredentialsProvider> {
    /// The destination's URI
    uri: ClientUri,
    /// The logging instance
    logger: Logger,
    /// The gRPC API client we will use for blockchain detail retrieval.
    blockchain_api_client: BlockchainApiClient,
    /// The gRPC API client we will use for attestation and (eventually)
    /// transactions
    attested_api_client: AttestedApiClient,
    /// The gRPC API client we will use for legacy transaction submission.
    consensus_client_api_client: ConsensusClientApiClient,
    /// An object which can verify a consensus node's provided IAS report
    verifier: Verifier,
    /// The AKE state machine object, if one is available.
    enclave_connection: Option<Ready<Aes256Gcm>>,
    /// Generic interface for retreiving GRPC credentials.
    credentials_provider: CP,
    /// A hash map of metadata to set on outbound requests, filled by inbound
    /// `Set-Cookie` metadata
    cookies: CookieJar,
}

impl<CP: CredentialsProvider> ThickClient<CP> {
    /// Create a new attested connection to the given consensus node.
    pub fn new(
        uri: ClientUri,
        verifier: Verifier,
        env: Arc<Environment>,
        credentials_provider: CP,
        logger: Logger,
    ) -> Result<Self> {
        let logger = logger.new(o!("mc.cxn" => uri.to_string()));

        let ch = ChannelBuilder::default_channel_builder(env).connect_to_uri(&uri, &logger);

        let attested_api_client = AttestedApiClient::new(ch.clone());
        let blockchain_api_client = BlockchainApiClient::new(ch.clone());
        let consensus_client_api_client = ConsensusClientApiClient::new(ch);

        Ok(Self {
            uri,
            logger,
            blockchain_api_client,
            consensus_client_api_client,
            attested_api_client,
            verifier,
            enclave_connection: None,
            credentials_provider,
            cookies: CookieJar::default(),
        })
    }

    /// A wrapper for performing an authenticated call. This also takes care to
    /// properly include cookie information in the request.
    fn authenticated_call<
        T,
        E: AuthenticationError + From<Box<dyn CredentialsProviderError + 'static>>,
    >(
        &mut self,
        func: impl FnOnce(&mut Self, CallOption) -> StdResult<T, E>,
    ) -> StdResult<T, E> {
        // Make the actual RPC call.
        let call_option = self.call_option()?;
        let result = func(self, call_option);

        // If the call failed due to authentication (credentials) error, reset creds so
        // that it gets re-created on the next call.
        if let Err(err) = result.as_ref() {
            if err.is_unauthenticated() {
                self.credentials_provider.clear();
            }
        }
        result
    }

    /// A convenience wrapper for performing authenticated+attested GRPC calls
    fn authenticated_attested_call<T>(
        &mut self,
        func: impl FnOnce(&mut Self, CallOption) -> StdResult<T, GrpcError>,
    ) -> StdResult<T, ThickClientAttestationError> {
        self.authenticated_call(|this, call_option| {
            this.attested_call(|this| func(this, call_option))
        })
    }

    fn call_option(&self) -> StdResult<CallOption, Box<dyn CredentialsProviderError + 'static>> {
        let retval = CallOption::default();

        // Create metadata from cookies and credentials
        let mut metadata_builder = self
            .cookies
            .to_client_metadata()
            .unwrap_or_else(|_| MetadataBuilder::new());

        if let Some(creds) = self
            .credentials_provider
            .get_credentials()
            .map_err(|err| -> Box<dyn CredentialsProviderError + 'static> { Box::new(err) })?
        {
            if !creds.username().is_empty() && !creds.password().is_empty() {
                metadata_builder
                    .add_str("Authorization", &creds.authorization_header())
                    .expect("Error setting authorization header");
            }
        }

        Ok(retval.headers(metadata_builder.build()))
    }
}

impl<CP: CredentialsProvider> Connection for ThickClient<CP> {
    type Uri = ClientUri;

    fn uri(&self) -> Self::Uri {
        self.uri.clone()
    }
}

impl<CP: CredentialsProvider> AttestedConnection for ThickClient<CP> {
    type Error = ThickClientAttestationError;

    fn is_attested(&self) -> bool {
        self.enclave_connection.is_some()
    }

    fn attest(&mut self) -> StdResult<VerificationReport, Self::Error> {
        trace_time!(self.logger, "ThickClient::attest");
        // If we have an existing attestation, nuke it.
        self.deattest();

        let mut csprng = McRng::default();

        let initiator = Start::new(self.uri.responder_id()?.to_string());

        let init_input = ClientInitiate::<X25519, Aes256Gcm, Sha512>::default();
        let (initiator, auth_request_output) = initiator.try_next(&mut csprng, init_input)?;

        // Do the gRPC Call
        let (header, auth_response_msg, trailer) =
            self.authenticated_call(|this, call_option| -> StdResult<_, Self::Error> {
                Ok(this
                    .attested_api_client
                    .auth_full(&auth_request_output.into(), call_option)?)
            })?;

        // Update cookies from server-sent metadata
        if let Err(e) = self
            .cookies
            .update_from_server_metadata(header.as_ref(), trailer.as_ref())
        {
            log::warn!(
                self.logger,
                "Could not update cookies from gRPC metadata: {}",
                e
            )
        }

        let auth_response_event =
            AuthResponseInput::new(auth_response_msg.into(), self.verifier.clone());
        let (initiator, verification_report) =
            initiator.try_next(&mut csprng, auth_response_event)?;

        self.enclave_connection = Some(initiator);

        Ok(verification_report)
    }

    fn deattest(&mut self) {
        if self.is_attested() {
            log::trace!(
                self.logger,
                "Tearing down existing attested connection and clearing cookies."
            );
            self.enclave_connection = None;
            self.cookies = CookieJar::default();
        }
    }
}

impl<CP: CredentialsProvider> BlockchainConnection for ThickClient<CP> {
    fn fetch_blocks(&mut self, range: Range<BlockIndex>) -> Result<Vec<Block>> {
        trace_time!(self.logger, "ThickClient::get_blocks");

        let mut request = BlocksRequest::new();
        request.set_offset(range.start);
        let limit = u32::try_from(range.end - range.start).or(Err(Error::RequestTooLarge))?;
        request.set_limit(limit);

        self.authenticated_attested_call(|this, call_option| {
            let (header, message, trailer) = this
                .blockchain_api_client
                .get_blocks_full(&request, call_option)?;

            // Update cookies from server-sent metadata
            if let Err(e) = this
                .cookies
                .update_from_server_metadata(header.as_ref(), trailer.as_ref())
            {
                log::warn!(
                    this.logger,
                    "Could not update cookies from gRPC metadata: {}",
                    e
                )
            }

            Ok(message)
        })?
        .get_blocks()
        .iter()
        .map(|proto_block| Block::try_from(proto_block).map_err(Error::from))
        .collect::<Result<Vec<Block>>>()
    }

    fn fetch_block_ids(&mut self, range: Range<BlockIndex>) -> Result<Vec<BlockID>> {
        trace_time!(self.logger, "ThickClient::get_block_ids");

        let mut request = BlocksRequest::new();
        request.set_offset(range.start);
        let limit = u32::try_from(range.end - range.start).or(Err(Error::RequestTooLarge))?;
        request.set_limit(limit);

        self.authenticated_attested_call(|this, call_option| {
            let (header, message, trailer) = this
                .blockchain_api_client
                .get_blocks_full(&request, call_option)?;

            // Update cookies from server-sent metadata
            if let Err(e) = this
                .cookies
                .update_from_server_metadata(header.as_ref(), trailer.as_ref())
            {
                log::warn!(
                    this.logger,
                    "Could not update cookies from gRPC metadata: {}",
                    e
                )
            }

            Ok(message)
        })?
        .get_blocks()
        .iter()
        .map(|proto_block| BlockID::try_from(proto_block.get_id()).map_err(Error::from))
        .collect::<Result<Vec<BlockID>>>()
    }

    fn fetch_block_height(&mut self) -> Result<BlockIndex> {
        trace_time!(self.logger, "ThickClient::fetch_block_height");

        Ok(self
            .authenticated_attested_call(|this, call_option| {
                let (header, message, trailer) = this
                    .blockchain_api_client
                    .get_last_block_info_full(&Empty::new(), call_option)?;

                // Update cookies from server-sent metadata
                if let Err(e) = this
                    .cookies
                    .update_from_server_metadata(header.as_ref(), trailer.as_ref())
                {
                    log::warn!(
                        this.logger,
                        "Could not update cookies from gRPC metadata: {}",
                        e
                    )
                }

                Ok(message)
            })?
            .index)
    }

    fn fetch_block_info(&mut self) -> Result<BlockInfo> {
        trace_time!(self.logger, "ThickClient::fetch_block_height");

        let block_info = self.authenticated_attested_call(|this, call_option| {
            let (header, message, trailer) = this
                .blockchain_api_client
                .get_last_block_info_full(&Empty::new(), call_option)?;

            // Update cookies from server-sent metadata
            if let Err(e) = this
                .cookies
                .update_from_server_metadata(header.as_ref(), trailer.as_ref())
            {
                log::warn!(
                    this.logger,
                    "Could not update cookies from gRPC metadata: {}",
                    e
                )
            }

            Ok(message)
        })?;

        Ok(block_info.into())
    }
}

impl<CP: CredentialsProvider> UserTxConnection for ThickClient<CP> {
    fn propose_tx(&mut self, tx: &Tx) -> Result<BlockIndex> {
        trace_time!(self.logger, "ThickClient::propose_tx");

        if !self.is_attested() {
            let _verification_report = self.attest()?;
        }

        let enclave_connection = self
            .enclave_connection
            .as_mut()
            .expect("no enclave_connection even though attest succeeded");

        let mut msg = Message::new();
        msg.set_channel_id(Vec::from(enclave_connection.binding()));

        // Don't leave the plaintext serialization floating around
        let tx_plaintext = SecretVec::new(encode(tx));
        let tx_ciphertext =
            enclave_connection.encrypt(&[], tx_plaintext.expose_secret().as_ref())?;
        msg.set_data(tx_ciphertext);

        let resp = self.authenticated_attested_call(|this, call_option| {
            let (header, message, trailer) = this
                .consensus_client_api_client
                .client_tx_propose_full(&msg, call_option)?;

            // Update cookies from server-sent metadata
            if let Err(e) = this
                .cookies
                .update_from_server_metadata(header.as_ref(), trailer.as_ref())
            {
                log::warn!(
                    this.logger,
                    "Could not update cookies from gRPC metadata: {}",
                    e
                )
            }

            Ok(message)
        })?;

        if resp.get_result() == ProposeTxResult::Ok {
            Ok(resp.get_block_count())
        } else {
            Err(resp.get_result().into())
        }
    }
}

impl<CP: CredentialsProvider> Display for ThickClient<CP> {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "{}", self.uri)
    }
}

impl<CP: CredentialsProvider> Eq for ThickClient<CP> {}

impl<CP: CredentialsProvider> Hash for ThickClient<CP> {
    fn hash<H: Hasher>(&self, hasher: &mut H) {
        self.uri.addr().hash(hasher);
    }
}

impl<CP: CredentialsProvider> PartialEq for ThickClient<CP> {
    fn eq(&self, other: &Self) -> bool {
        self.uri.addr() == other.uri.addr()
    }
}

impl<CP: CredentialsProvider> Ord for ThickClient<CP> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.uri.addr().cmp(&other.uri.addr())
    }
}

impl<CP: CredentialsProvider> PartialOrd for ThickClient<CP> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.uri.addr().partial_cmp(&other.uri.addr())
    }
}
