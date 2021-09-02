// Copyright (c) 2018-2021 MobileCoin Inc.

//! Peer-to-Peer Networking with SGX.

use crate::{
    connection_error::{Error, PeerAttestationError, Result},
    connection_traits::IngestConnection,
};
use core::fmt::{Display, Formatter, Result as FmtResult};
use grpcio::{ChannelBuilder, Environment};
use mc_attest_api::{attest::Message, attest_grpc::AttestedApiClient};
use mc_attest_core::VerificationReport;
use mc_attest_enclave_api::PeerSession;
use mc_common::{
    logger::{log, o, Logger},
    trace_time, ResponderId,
};
use mc_connection::{AttestedConnection, Connection};
use mc_crypto_keys::CompressedRistrettoPublic;
use mc_fog_api::{
    ingest_common::{IngestSummary, SetPeersRequest},
    ingest_peer::GetPrivateKeyRequest,
    ingest_peer_grpc::AccountIngestPeerApiClient,
};
use mc_fog_ingest_enclave_api::IngestEnclaveProxy;
use mc_fog_uri::IngestPeerUri;
use mc_util_grpc::ConnectionUriGrpcioChannel;
use mc_util_uri::ConnectionUri;
use std::{
    cmp::Ordering,
    collections::BTreeSet,
    hash::{Hash, Hasher},
    result::Result as StdResult,
    sync::Arc,
};

/// This is a PeerConnection implementation which ensures transparent
/// attestation between the local and remote enclaves.
pub struct PeerConnection<Enclave: IngestEnclaveProxy> {
    /// The local enclave, which the remote node will be peered with.
    enclave: Enclave,

    /// When communicating with the remote enclave, this is the handshake hash /
    /// session ID / channel ID.
    channel_id: Option<PeerSession>,

    /// The local node ID
    local_node_id: ResponderId,

    /// The remote node ID
    remote_responder_id: ResponderId,

    /// The remote node's URI.
    uri: IngestPeerUri,

    /// The logger instance we will be using.
    logger: Logger,

    /// The gRPC client used to access the remote attestation API.
    attested_api_client: AttestedApiClient,

    /// The gRPC client used to communicate once we have attested.
    ingest_peer_api_client: AccountIngestPeerApiClient,
}

impl<Enclave: IngestEnclaveProxy> PeerConnection<Enclave> {
    /// Construct a new PeerConnection, optionally with TLS enabled.
    pub fn new(
        enclave: Enclave,
        local_node_id: ResponderId,
        uri: IngestPeerUri,
        env: Arc<Environment>,
        logger: Logger,
    ) -> Self {
        let remote_responder_id = uri.responder_id().unwrap_or_else(|_| {
            panic!("Could not get responder id from uri {:?}", uri.to_string())
        });
        let host_port = uri.addr();

        let logger = logger.new(o!("mc.peers.addr" => host_port));

        let ch = ChannelBuilder::default_channel_builder(env)
            .max_receive_message_len(std::i32::MAX)
            .max_send_message_len(std::i32::MAX)
            .connect_to_uri(&uri, &logger);

        let attested_api_client = AttestedApiClient::new(ch.clone());
        let ingest_peer_api_client = AccountIngestPeerApiClient::new(ch);

        Self {
            enclave,
            local_node_id,
            remote_responder_id,
            uri,
            channel_id: None,
            logger,
            attested_api_client,
            ingest_peer_api_client,
        }
    }
}

impl<Enclave: IngestEnclaveProxy> Display for PeerConnection<Enclave> {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "{}", self.uri)
    }
}

impl<Enclave: IngestEnclaveProxy> Eq for PeerConnection<Enclave> {}

impl<Enclave: IngestEnclaveProxy> Hash for PeerConnection<Enclave> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.uri.addr().hash(state);
    }
}

impl<Enclave: IngestEnclaveProxy> Ord for PeerConnection<Enclave> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.uri.addr().cmp(&other.uri.addr())
    }
}

impl<Enclave: IngestEnclaveProxy> PartialEq for PeerConnection<Enclave> {
    fn eq(&self, other: &Self) -> bool {
        self.uri.addr() == other.uri.addr()
    }
}

impl<Enclave: IngestEnclaveProxy> PartialOrd for PeerConnection<Enclave> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.uri.addr().partial_cmp(&other.uri.addr())
    }
}

impl<Enclave: IngestEnclaveProxy> Connection for PeerConnection<Enclave> {
    type Uri = IngestPeerUri;

    fn uri(&self) -> Self::Uri {
        self.uri.clone()
    }
}

impl<Enclave: IngestEnclaveProxy> AttestedConnection for PeerConnection<Enclave> {
    type Error = PeerAttestationError;

    fn is_attested(&self) -> bool {
        self.channel_id.is_some()
    }

    fn attest(&mut self) -> StdResult<VerificationReport, Self::Error> {
        self.deattest();
        let req = self.enclave.peer_init(&self.remote_responder_id())?;
        let res = self.attested_api_client.auth(&req.into())?;
        let (peer_session, verification_report) = self
            .enclave
            .peer_connect(&self.remote_responder_id(), res.into())?;

        self.channel_id = Some(peer_session);

        Ok(verification_report)
    }

    fn deattest(&mut self) {
        if self.is_attested() {
            log::trace!(self.logger, "Tearing down existing attested connection.");
            self.channel_id = None;
        }
    }
}

impl<Enclave: IngestEnclaveProxy> IngestConnection for PeerConnection<Enclave> {
    fn remote_responder_id(&self) -> ResponderId {
        self.remote_responder_id.clone()
    }

    fn local_node_id(&self) -> ResponderId {
        self.local_node_id.clone()
    }

    fn get_status(&mut self) -> Result<IngestSummary> {
        trace_time!(self.logger, "PeerConnection::get_status");

        // This call is not attested
        let request = Default::default();
        Ok(self.ingest_peer_api_client.get_status(&request)?)
    }

    fn set_peers(&mut self, peers: BTreeSet<IngestPeerUri>) -> Result<IngestSummary> {
        trace_time!(self.logger, "PeerConnection::set_peers");

        // This call is not attested
        let mut request = SetPeersRequest::new();
        request.ingest_peer_uris =
            protobuf::RepeatedField::from_vec(peers.iter().map(|x| x.to_string()).collect());
        Ok(self.ingest_peer_api_client.set_peers(&request)?)
    }

    fn get_ingress_private_key(&mut self) -> Result<Message> {
        trace_time!(self.logger, "PeerConnection::get_private_key");

        if self.channel_id.is_none() {
            self.attest()?;
        }

        match self.channel_id.clone() {
            Some(peer_session) => {
                let mut request = GetPrivateKeyRequest::new();
                request.set_channel_id(peer_session.into());

                let message = self.attested_call(|this| {
                    this.ingest_peer_api_client
                        .get_ingress_private_key(&request)
                })?;
                Ok(message)
            }
            None => Err(Error::ChannelSend),
        }
    }

    fn set_ingress_private_key(
        &mut self,
        current_ingress_public_key: &CompressedRistrettoPublic,
    ) -> Result<IngestSummary> {
        trace_time!(self.logger, "PeerConnection::set_private_key");

        if self.channel_id.is_none() {
            self.attest()?;
        }

        match self.channel_id.clone() {
            Some(peer_session) => {
                let (msg, ingress_pubkey) = self.enclave.get_ingress_private_key(peer_session)?;
                if ingress_pubkey != *current_ingress_public_key {
                    return Err(Error::UnexpectedKeyInEnclave(ingress_pubkey));
                }

                let summary = self.attested_call(|this| {
                    this.ingest_peer_api_client
                        .set_ingress_private_key(&(msg.into()))
                })?;
                Ok(summary)
            }
            None => Err(Error::ChannelSend),
        }
    }
}
