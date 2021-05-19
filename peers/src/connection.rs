// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Peer-to-Peer Networking with SGX.

use crate::{
    consensus_msg::{ConsensusMsg, TxProposeAAD},
    error::{Error, PeerAttestationError, Result},
    traits::ConsensusConnection,
};
use core::fmt::{Display, Formatter, Result as FmtResult};
use grpcio::{ChannelBuilder, Environment, Error as GrpcError};
use mc_attest_api::attest_grpc::AttestedApiClient;
use mc_attest_core::VerificationReport;
use mc_attest_enclave_api::PeerSession;
use mc_common::{
    logger::{log, o, Logger},
    trace_time, NodeID, ResponderId,
};
use mc_connection::{
    AttestedConnection, BlockInfo, BlockchainConnection, Connection, Error as ConnectionError,
    Result as ConnectionResult,
};
use mc_consensus_api::{
    consensus_common::BlocksRequest,
    consensus_common_grpc::BlockchainApiClient,
    consensus_peer::{
        ConsensusMsg as GrpcConsensusMsg, ConsensusMsgResponse,
        GetTxsRequest as GrpcFetchTxsRequest,
    },
    consensus_peer_grpc::ConsensusPeerApiClient,
    empty::Empty,
    ConversionError,
};
use mc_consensus_enclave_api::{ConsensusEnclave, TxContext, WellFormedEncryptedTx};
use mc_transaction_core::{tx::TxHash, Block, BlockID, BlockIndex};
use mc_util_grpc::ConnectionUriGrpcioChannel;
use mc_util_serial::{deserialize, serialize};
use mc_util_uri::{ConnectionUri, ConsensusPeerUri as PeerUri};
use protobuf::RepeatedField;
use std::{
    cmp::Ordering,
    convert::TryFrom,
    hash::{Hash, Hasher},
    ops::Range,
    result::Result as StdResult,
    sync::Arc,
};

/// This is a PeerConnection implementation which ensures transparent
/// attestation between the local and remote enclaves.
pub struct PeerConnection<Enclave: ConsensusEnclave + Clone + Send + Sync> {
    /// The local enclave, which the remote node will be peered with.
    enclave: Enclave,

    /// When communicating with the remote enclave, this is the handshake hash /
    /// session ID / channel ID.
    channel_id: Option<PeerSession>,

    /// The local node ID
    local_node_id: NodeID,

    /// The remote node ID
    remote_responder_id: ResponderId,

    /// The remote node's URI.
    uri: PeerUri,

    /// The logger instance we will be using.
    logger: Logger,

    /// The gRPC client used to access the remote attestation API.
    attested_api_client: AttestedApiClient,

    consensus_api_client: ConsensusPeerApiClient,
    blockchain_api_client: BlockchainApiClient,
}

impl<Enclave: ConsensusEnclave + Clone + Send + Sync> PeerConnection<Enclave> {
    /// Construct a new PeerConnection, optionally with TLS enabled.
    pub fn new(
        enclave: Enclave,
        local_node_id: NodeID,
        uri: PeerUri,
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
        let consensus_api_client = ConsensusPeerApiClient::new(ch.clone());
        let blockchain_api_client = BlockchainApiClient::new(ch);

        Self {
            enclave,
            local_node_id,
            remote_responder_id,
            uri,
            channel_id: None,
            logger,
            attested_api_client,
            consensus_api_client,
            blockchain_api_client,
        }
    }

    /// A helper method for performing an attested call and logging failures.
    fn log_attested_call<T>(
        &mut self,
        log_str: &str,
        func: impl FnOnce(&mut Self) -> StdResult<T, GrpcError>,
    ) -> StdResult<T, PeerAttestationError> {
        self.attested_call(func).map_err(|err| {
            log::debug!(
                self.logger,
                "{} failed: {:?} (is_attested={})",
                log_str,
                err,
                self.is_attested()
            );
            err
        })
    }
}

impl<Enclave: ConsensusEnclave + Clone + Send + Sync> Display for PeerConnection<Enclave> {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "{}", self.uri)
    }
}

impl<Enclave: ConsensusEnclave + Clone + Send + Sync> Eq for PeerConnection<Enclave> {}

impl<Enclave: ConsensusEnclave + Clone + Send + Sync> Hash for PeerConnection<Enclave> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.uri.addr().hash(state);
    }
}

impl<Enclave: ConsensusEnclave + Clone + Send + Sync> Ord for PeerConnection<Enclave> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.uri.addr().cmp(&other.uri.addr())
    }
}

impl<Enclave: ConsensusEnclave + Clone + Send + Sync> PartialEq for PeerConnection<Enclave> {
    fn eq(&self, other: &Self) -> bool {
        self.uri.addr() == other.uri.addr()
    }
}

impl<Enclave: ConsensusEnclave + Clone + Send + Sync> PartialOrd for PeerConnection<Enclave> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.uri.addr().partial_cmp(&other.uri.addr())
    }
}

impl<Enclave: ConsensusEnclave + Clone + Send + Sync> Connection for PeerConnection<Enclave> {
    type Uri = PeerUri;

    fn uri(&self) -> Self::Uri {
        self.uri.clone()
    }
}

impl<Enclave: ConsensusEnclave + Clone + Send + Sync> AttestedConnection
    for PeerConnection<Enclave>
{
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

// FIXME: refactor into a common impl shared with mc_connection::ThickClient
impl<Enclave: ConsensusEnclave + Clone + Send + Sync> BlockchainConnection
    for PeerConnection<Enclave>
{
    fn fetch_blocks(&mut self, range: Range<BlockIndex>) -> ConnectionResult<Vec<Block>> {
        trace_time!(self.logger, "PeerConnection::get_blocks");

        let mut request = BlocksRequest::new();
        request.set_offset(range.start);
        let limit =
            u32::try_from(range.end - range.start).or(Err(ConnectionError::RequestTooLarge))?;
        request.set_limit(limit);

        self.log_attested_call("fetch_blocks", |this| {
            this.blockchain_api_client.get_blocks(&request)
        })?
        .get_blocks()
        .iter()
        .map(|proto_block| Block::try_from(proto_block).map_err(ConnectionError::from))
        .collect::<ConnectionResult<Vec<Block>>>()
    }

    fn fetch_block_ids(&mut self, range: Range<BlockIndex>) -> ConnectionResult<Vec<BlockID>> {
        trace_time!(self.logger, "PeerConnection::get_blocks");

        let mut request = BlocksRequest::new();
        request.set_offset(range.start);
        let limit =
            u32::try_from(range.end - range.start).or(Err(ConnectionError::RequestTooLarge))?;
        request.set_limit(limit);

        self.attested_call(|this| this.blockchain_api_client.get_blocks(&request))?
            .get_blocks()
            .iter()
            .map(|proto_block| {
                BlockID::try_from(proto_block.get_id()).map_err(ConnectionError::from)
            })
            .collect::<ConnectionResult<Vec<BlockID>>>()
    }

    fn fetch_block_height(&mut self) -> ConnectionResult<BlockIndex> {
        trace_time!(self.logger, "PeerConnection::fetch_block_height");

        Ok(self
            .log_attested_call("fetch_block_height", |this| {
                this.blockchain_api_client
                    .get_last_block_info(&Empty::new())
            })?
            .index)
    }

    fn fetch_block_info(&mut self) -> ConnectionResult<BlockInfo> {
        trace_time!(self.logger, "PeerConnection::fetch_block_info");

        let block_info = self.log_attested_call("fetch_block_info", |this| {
            this.blockchain_api_client
                .get_last_block_info(&Empty::new())
        })?;
        Ok(block_info.into())
    }
}

impl<Enclave: ConsensusEnclave + Clone + Send + Sync> ConsensusConnection
    for PeerConnection<Enclave>
{
    fn remote_responder_id(&self) -> ResponderId {
        self.remote_responder_id.clone()
    }

    fn local_node_id(&self) -> NodeID {
        self.local_node_id.clone()
    }

    fn send_consensus_msg(&mut self, msg: &ConsensusMsg) -> Result<ConsensusMsgResponse> {
        let mut grpc_msg = GrpcConsensusMsg::default();
        grpc_msg.set_from_responder_id(self.local_node_id.responder_id.to_string());
        grpc_msg.set_payload(serialize(&msg)?);

        let response = self.log_attested_call("send_consensus_msg", |this| {
            this.consensus_api_client.send_consensus_msg(&grpc_msg)
        })?;
        Ok(response)
    }

    fn send_propose_tx(
        &mut self,
        encrypted_tx: &WellFormedEncryptedTx,
        origin_node: &NodeID,
    ) -> Result<()> {
        if !self.is_attested() {
            self.attest()?;
        }

        let aad = mc_util_serial::serialize(&TxProposeAAD {
            origin_node: origin_node.clone(),
            relayed_by: self.local_node_id().responder_id,
        })?;

        let request = self.enclave.txs_for_peer(
            &[encrypted_tx.clone()],
            &aad,
            self.channel_id.as_ref().unwrap(),
        )?;

        self.log_attested_call("txs_for_peer", |this| {
            this.consensus_api_client.peer_tx_propose(&request.into())
        })?;

        Ok(())
    }

    fn fetch_txs(&mut self, hashes: &[TxHash]) -> Result<Vec<TxContext>> {
        if !self.is_attested() {
            self.attest()?;
        }

        let mut request = GrpcFetchTxsRequest::new();
        request.set_channel_id(self.channel_id.as_ref().unwrap().as_ref().to_vec());
        request.set_tx_hashes(RepeatedField::from_vec(
            hashes.iter().map(|tx| tx.to_vec()).collect(),
        ));

        let mut response = self.log_attested_call("get_txs", |this| {
            this.consensus_api_client.get_txs(&request)
        })?;
        if response.has_tx_hashes_not_in_cache() {
            let tx_hashes = response
                .get_tx_hashes_not_in_cache()
                .get_tx_hashes()
                .iter()
                .map(|tx_hash_bytes| {
                    TxHash::try_from(&tx_hash_bytes[..])
                        .map_err(|_| Error::Conversion(ConversionError::ArrayCastError))
                })
                .collect::<StdResult<Vec<TxHash>, _>>()?;
            return Err(Error::TxHashesNotInCache(tx_hashes));
        }

        let tx_contexts = self
            .enclave
            .peer_tx_propose(response.take_success().into())?;

        Ok(tx_contexts)
    }

    fn fetch_latest_msg(&mut self) -> Result<Option<ConsensusMsg>> {
        let response = self.log_attested_call("gte_latest_msg", |this| {
            this.consensus_api_client.get_latest_msg(&Empty::new())
        })?;
        if response.get_payload().is_empty() {
            Ok(None)
        } else {
            let msg = deserialize::<ConsensusMsg>(response.get_payload())?;

            Ok(Some(msg))
        }
    }
}
