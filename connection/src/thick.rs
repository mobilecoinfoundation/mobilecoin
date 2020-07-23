// Copyright (c) 2018-2020 MobileCoin Inc.

//! Connection implementations required for the thick client.
//! The attested client implementation.

use crate::{
    error::{Error, Result},
    traits::{
        AttestationError, AttestedConnection, BlockchainConnection, Connection, UserTxConnection,
    },
};
use aes_gcm::Aes256Gcm;
use failure::Fail;
use grpcio::{ChannelBuilder, Environment, Error as GrpcError};
use mc_attest_ake::{ClientInitiate, Error as AkeError, Ready, Start, Transition};
use mc_attest_api::{attest::Message, attest_grpc::AttestedApiClient};
use mc_attest_core::Measurement;
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
use mc_util_grpc::ConnectionUriGrpcioChannel;
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

// FIXME: MC-530 (better place to store MobileCoin-specific enclave details)
const MC_NODE_PRODUCT_ID: u16 = 1;
const MC_SECURITY_VERSION: u16 = 1;

#[derive(Debug, Fail)]
pub enum ThickClientAttestationError {
    #[fail(display = "gRPC failure in attestation: {}", _0)]
    Grpc(GrpcError),
    #[fail(display = "Key exchange failure: {}", _0)]
    Ake(AkeError),
    #[fail(display = "Encryption/decryption failure in attestation: {}", _0)]
    Cipher(CipherError),
    #[fail(display = "Could not create ResponderID from URI {} due to {}", _0, _1)]
    InvalidResponderID(String, UriConversionError),
    #[fail(display = "Unexpected Error Converting URI {}", _0)]
    UriConversionError(UriConversionError),
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

impl AttestationError for ThickClientAttestationError {}

/// A connection from a client to a consensus enclave.
pub struct ThickClient {
    /// The destination's URI
    uri: ClientUri,
    /// The logging instance
    logger: Logger,
    /// The gRPC API client we will use for blockchain detail retrieval.
    blockchain_api_client: BlockchainApiClient,
    /// The gRPC API client we will use for attestation and (eventually) transactions
    attested_api_client: AttestedApiClient,
    /// The gRPC API client we will use for legacy transaction submission.
    consensus_client_api_client: ConsensusClientApiClient,
    /// The expected node enclave measurement value.
    expected_measurements: Vec<Measurement>,
    /// The AKE state machine object, if one is available.
    enclave_connection: Option<Ready<Aes256Gcm>>,
}

impl ThickClient {
    /// Create a new attested connection to the given consensus node.
    pub fn new(
        uri: ClientUri,
        expected_measurements: Vec<Measurement>,
        env: Arc<Environment>,
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
            expected_measurements,
            enclave_connection: None,
        })
    }
}

impl Connection for ThickClient {
    type Uri = ClientUri;

    fn uri(&self) -> Self::Uri {
        self.uri.clone()
    }
}

impl AttestedConnection for ThickClient {
    type Error = ThickClientAttestationError;

    fn is_attested(&self) -> bool {
        self.enclave_connection.is_some()
    }

    fn attest(&mut self) -> StdResult<(), Self::Error> {
        trace_time!(self.logger, "ThickClient::attest");
        // If we have an existing attestation, nuke it.
        self.deattest();

        let mut csprng = McRng::default();

        let initiator = Start::new(
            self.uri.responder_id()?.to_string(),
            self.expected_measurements.clone(),
            MC_NODE_PRODUCT_ID,
            MC_SECURITY_VERSION,
            mc_attest_core::DEBUG_ENCLAVE,
        );

        let init_input = ClientInitiate::<X25519, Aes256Gcm, Sha512>::default();
        let (initiator, auth_request_output) = initiator.try_next(&mut csprng, init_input)?;

        let auth_response = self.attested_api_client.auth(&auth_request_output.into())?;

        let (initiator, _) = initiator.try_next(&mut csprng, auth_response.into())?;

        self.enclave_connection = Some(initiator);

        Ok(())
    }

    fn deattest(&mut self) {
        if self.is_attested() {
            log::trace!(self.logger, "Tearing down existing attested connection.");
            self.enclave_connection = None;
        }
    }
}

impl BlockchainConnection for ThickClient {
    fn fetch_blocks(&mut self, range: Range<BlockIndex>) -> Result<Vec<Block>> {
        trace_time!(self.logger, "ThickClient::get_blocks");

        let mut request = BlocksRequest::new();
        request.set_offset(range.start);
        let limit = u32::try_from(range.end - range.start).or(Err(Error::RequestTooLarge))?;
        request.set_limit(limit);

        self.attested_call(|this| this.blockchain_api_client.get_blocks(&request))?
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

        self.attested_call(|this| this.blockchain_api_client.get_blocks(&request))?
            .get_blocks()
            .iter()
            .map(|proto_block| BlockID::try_from(proto_block.get_id()).map_err(Error::from))
            .collect::<Result<Vec<BlockID>>>()
    }

    fn fetch_block_height(&mut self) -> Result<BlockIndex> {
        trace_time!(self.logger, "ThickClient::fetch_block_height");

        Ok(self
            .attested_call(|this| {
                this.blockchain_api_client
                    .get_last_block_info(&Empty::new())
            })?
            .index)
    }
}

impl UserTxConnection for ThickClient {
    fn propose_tx(&mut self, tx: &Tx) -> Result<BlockIndex> {
        trace_time!(self.logger, "ThickClient::propose_tx");

        if !self.is_attested() {
            self.attest()?
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
        let resp =
            self.attested_call(|this| this.consensus_client_api_client.client_tx_propose(&msg))?;

        if resp.get_result() == ProposeTxResult::Ok {
            Ok(resp.get_num_blocks())
        } else {
            Err(resp.get_result().into())
        }
    }
}

impl Display for ThickClient {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "{}", self.uri)
    }
}

impl Eq for ThickClient {}

impl Hash for ThickClient {
    fn hash<H: Hasher>(&self, hasher: &mut H) {
        self.uri.addr().hash(hasher);
    }
}

impl PartialEq for ThickClient {
    fn eq(&self, other: &Self) -> bool {
        self.uri.addr() == other.uri.addr()
    }
}

impl Ord for ThickClient {
    fn cmp(&self, other: &Self) -> Ordering {
        self.uri.addr().cmp(&other.uri.addr())
    }
}

impl PartialOrd for ThickClient {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.uri.addr().partial_cmp(&other.uri.addr())
    }
}
