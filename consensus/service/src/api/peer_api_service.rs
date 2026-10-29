// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Serves node-to-node gRPC requests.

use crate::{
    api::peer_service_error::PeerServiceError,
    background_work_queue::BackgroundWorkQueueSenderFn,
    consensus_msg_verifier::{ConsensusMsgVerificationError, ConsensusMsgVerifier},
    consensus_service::{IncomingConsensusMsg, ProposeTxCallback},
    counters,
    tx_manager::{TxManager, TxManagerError},
    SVC_COUNTERS,
};
use grpcio::{RpcContext, RpcStatus, UnarySink};
use mc_attest_api::attest::Message;
use mc_attest_enclave_api::{EnclaveMessage, PeerSession};
use mc_common::{
    logger::{log, Logger},
    ResponderId,
};
use mc_consensus_api::{
    consensus_common::ProposeTxResponse,
    consensus_peer::{
        get_txs_response, ConsensusMsg as GrpcConsensusMsg, ConsensusMsgResponse,
        ConsensusMsgResult, ConsensusPeerApi, GetLatestMsgResponse, GetTxsRequest, GetTxsResponse,
        TxHashesNotInCache,
    },
};
use mc_consensus_enclave::{ConsensusEnclave, Error};
use mc_ledger_db::Ledger;
use mc_peers::{ConsensusValue, TxProposeAAD};
use mc_transaction_core::tx::TxHash;
use mc_util_grpc::{
    rpc_internal_error, rpc_invalid_arg_error, rpc_logger, rpc_permissions_error, send_result,
};
use mc_util_serial::deserialize;
use std::{str::FromStr, sync::Arc};

// Callback method for returning the latest SCP message issued by the local
// node, used to implement the `fetch_latest_msg` RPC call.
type FetchLatestMsgFn = Arc<dyn Fn() -> Option<mc_peers::ConsensusMsg> + Sync + Send>;

#[derive(Clone)]
pub struct PeerApiService {
    /// Enclave instance.
    consensus_enclave: Arc<dyn ConsensusEnclave + Send + Sync>,

    /// TxManager instance.
    tx_manager: Arc<dyn TxManager + Send + Sync>,

    /// Callback function for feeding consensus messages into ByzantineLedger.
    incoming_consensus_msgs_sender: BackgroundWorkQueueSenderFn<IncomingConsensusMsg>,

    /// Callback function for feeding transactions into ByzantineLedger.
    scp_client_value_sender: ProposeTxCallback,

    /// Ledger database.
    ledger: Arc<dyn Ledger + Send + Sync>,

    /// Callback function for getting the latest SCP statement the local node
    /// has issued.
    fetch_latest_msg_fn: FetchLatestMsgFn,

    /// List of recognized responder IDs to accept messages from.
    /// We only want to accept messages from peers we can initiate outgoing
    /// requests to. That is necessary for resolving TxHashes into Txs. If
    /// we received a consensus message from a peer not on this list, we
    /// won't be able to reach out to it to ask for the transaction contents.
    known_responder_ids: Vec<ResponderId>,

    /// Verifies message signatures and configured issuer keys,
    /// independently of which peer forwarded the message.
    consensus_msg_verifier: Arc<ConsensusMsgVerifier>,

    /// Logger.
    logger: Logger,
}

impl PeerApiService {
    /// Creates a PeerApiService.
    ///
    /// # Arguments:
    /// * `consensus_enclave` - The local node's consensus enclave.
    /// * `ledger` - The local node's ledger.
    /// * `tx_manager` - The local node's TxManager.
    /// * `incoming_consensus_msgs_sender` - Callback for a new consensus
    ///   message from a peer.
    /// * `scp_client_value_sender` - Callback for proposed transactions.
    /// * `fetch_latest_msg_fn` - Returns highest message emitted by this node.
    /// * `known_responder_ids` - Messages from peers not on this "whitelist"
    ///   are ignored.
    /// * `consensus_msg_verifier` - Enforces configured issuer key bindings.
    /// * `logger` - Logger.
    pub fn new(
        consensus_enclave: Arc<dyn ConsensusEnclave + Send + Sync>,
        ledger: Arc<dyn Ledger + Send + Sync>,
        tx_manager: Arc<dyn TxManager + Send + Sync>,
        incoming_consensus_msgs_sender: BackgroundWorkQueueSenderFn<IncomingConsensusMsg>,
        scp_client_value_sender: ProposeTxCallback,
        fetch_latest_msg_fn: FetchLatestMsgFn,
        known_responder_ids: Vec<ResponderId>,
        consensus_msg_verifier: Arc<ConsensusMsgVerifier>,
        logger: Logger,
    ) -> Self {
        Self {
            consensus_enclave,
            tx_manager,
            incoming_consensus_msgs_sender,
            scp_client_value_sender,
            ledger,
            fetch_latest_msg_fn,
            known_responder_ids,
            consensus_msg_verifier,
            logger,
        }
    }

    /// Handle transactions proposed by clients to a different node.
    ///
    /// # Arguments
    /// * `enclave_msg` - A message encrypted for this node's consensus enclave.
    /// * `logger` -
    ///
    /// # Returns
    /// The number of blocks in the local ledger when the tx_propose request was
    /// handled.
    fn handle_tx_propose(
        &mut self,
        enclave_msg: EnclaveMessage<PeerSession>,
        logger: &Logger,
    ) -> Result<u64, PeerServiceError> {
        let aad = enclave_msg.aad.clone();
        let tx_contexts = self
            .consensus_enclave
            .peer_tx_propose(enclave_msg)
            .map_err(PeerServiceError::Enclave)?;

        // The node the originally received the transaction from a client,
        // and the node that forwarded the transaction if not the origin_node.
        let (origin_node, relayed_by) = {
            mc_util_serial::deserialize::<TxProposeAAD>(&aad)
                .map(|aad| (Some(aad.origin_node), Some(aad.relayed_by)))
                .unwrap_or((None, None))
        };

        // The number of blocks in the local ledger when the tx_propose request was
        // handled.
        let num_blocks = self.ledger.num_blocks().map_err(|e| {
            log::warn!(logger, "{}", e);
            PeerServiceError::InternalError
        })?;

        // Handle each transaction.
        for tx_context in tx_contexts {
            let tx_hash = tx_context.tx_hash;

            match self.tx_manager.insert(tx_context) {
                Ok(tx_hash) => {
                    // Submit for consideration in next SCP slot.
                    (*self.scp_client_value_sender)(
                        ConsensusValue::TxHash(tx_hash),
                        origin_node.as_ref(),
                        relayed_by.as_ref(),
                    );
                }

                Err(TxManagerError::TransactionValidation(err)) => {
                    log::debug!(
                        logger,
                        "Error validating transaction {tx_hash}: {err}",
                        tx_hash = tx_hash.to_string(),
                        err = format!("{err:?}")
                    );
                    counters::TX_VALIDATION_ERROR_COUNTER.inc(&format!("{err:?}"));
                }

                Err(err) => {
                    log::info!(
                        logger,
                        "tx_propose failed for {tx_hash}: {err}",
                        tx_hash = tx_hash.to_string(),
                        err = format!("{err:?}")
                    );
                }
            };
        }

        Ok(num_blocks)
    }

    /// Handle a consensus message from another node.
    fn handle_consensus_msg(
        &mut self,
        consensus_msg: mc_peers::ConsensusMsg,
        from_responder_id: ResponderId,
    ) -> Result<(), PeerServiceError> {
        // Ignore a consensus message from an unknown peer.
        if !self.known_responder_ids.contains(&from_responder_id) {
            return Err(PeerServiceError::UnknownPeer(from_responder_id.to_string()));
        }

        // The forwarding peer may differ from the issuer. Check configured key
        // bindings while allowing transitive SCP participants.
        let verified_consensus_msg =
            self.consensus_msg_verifier
                .verify(consensus_msg)
                .map_err(|err| match err {
                    ConsensusMsgVerificationError::PublicKeyMismatch(issuer) => {
                        counters::CONSENSUS_MSG_ISSUER_KEY_MISMATCHES.inc();
                        log::warn!(
                            self.logger,
                            "Consensus message signing key mismatch for issuer {issuer} relayed by {from_responder_id}"
                        );
                        PeerServiceError::ConsensusMsgInvalidIssuer
                    }
                    ConsensusMsgVerificationError::InvalidSignature(_) => {
                        PeerServiceError::ConsensusMsgInvalidSignature
                    }
                })?;

        (self.incoming_consensus_msgs_sender)(IncomingConsensusMsg {
            from_responder_id,
            consensus_msg: verified_consensus_msg,
        })
        .map_err(|_| PeerServiceError::InternalError)
    }

    /// Returns the full, encrypted transactions corresponding to a list of
    /// transaction hashes.
    fn handle_get_txs(
        &mut self,
        tx_hashes: Vec<TxHash>,
        peer_session: PeerSession,
        logger: &Logger,
    ) -> Result<EnclaveMessage<PeerSession>, PeerServiceError> {
        self.tx_manager
            .encrypt_for_peer(&tx_hashes, &[], &peer_session)
            .map_err(|tx_manager_error| match tx_manager_error {
                TxManagerError::NotInCache(tx_hashes) => {
                    PeerServiceError::UnknownTransactions(tx_hashes)
                }
                err => {
                    log::warn!(logger, "{}", err);
                    PeerServiceError::InternalError
                }
            })
    }
}

impl ConsensusPeerApi for PeerApiService {
    /// Handle transactions proposed by clients to a different node.
    fn peer_tx_propose(
        &mut self,
        ctx: RpcContext,
        request: Message,
        sink: UnarySink<ProposeTxResponse>,
    ) {
        let _timer = SVC_COUNTERS.req(&ctx);

        let enclave_msg: EnclaveMessage<PeerSession> = request.into();

        mc_common::logger::scoped_global_logger(&rpc_logger(&ctx, &self.logger), |logger| {
            let result: Result<ProposeTxResponse, RpcStatus> =
                match self.handle_tx_propose(enclave_msg, logger) {
                    Ok(num_blocks) => Ok(ProposeTxResponse {
                        block_count: num_blocks,
                        ..Default::default()
                    }),

                    Err(err @ PeerServiceError::Enclave(Error::Attest(_))) => {
                        Err(rpc_permissions_error("peer_tx_propose", err, logger))
                    }
                    Err(err) => Err(rpc_internal_error("peer_tx_propose", err, logger)),
                };

            send_result(ctx, sink, result, logger)
        });
    }

    /// Handle a consensus message from another peer.
    fn send_consensus_msg(
        &mut self,
        ctx: RpcContext,
        request: GrpcConsensusMsg,
        sink: UnarySink<ConsensusMsgResponse>,
    ) {
        let _timer = SVC_COUNTERS.req(&ctx);
        mc_common::logger::scoped_global_logger(&rpc_logger(&ctx, &self.logger), |logger| {
            // The peer who delivered this message to us.
            let from_responder_id = match ResponderId::from_str(&request.from_responder_id) {
                Ok(responder_id) => responder_id,
                Err(_) => {
                    let result = Err(rpc_invalid_arg_error(
                        "send_consensus_msg",
                        "from_responder_id",
                        logger,
                    ));
                    send_result(ctx, sink, result, logger);
                    return;
                }
            };

            let consensus_msg: mc_peers::ConsensusMsg =
                match deserialize(request.payload.as_slice()) {
                    Ok(consensus_msg) => consensus_msg,
                    Err(_) => {
                        let result = Err(rpc_invalid_arg_error(
                            "send_consensus_msg",
                            "consensus_msg",
                            logger,
                        ));
                        send_result(ctx, sink, result, logger);
                        return;
                    }
                };

            let result: Result<ConsensusMsgResponse, RpcStatus> = match self
                .handle_consensus_msg(consensus_msg, from_responder_id)
            {
                Ok(()) => Ok(ConsensusMsgResponse {
                    result: ConsensusMsgResult::Ok.into(),
                }),
                Err(PeerServiceError::UnknownPeer(_)) => Ok(ConsensusMsgResponse {
                    result: ConsensusMsgResult::UnknownPeer.into(),
                }),
                Err(PeerServiceError::ConsensusMsgInvalidSignature) => Err(rpc_invalid_arg_error(
                    "send_consensus_msg",
                    "InvalidConsensusMsgSignature",
                    logger,
                )),
                Err(PeerServiceError::ConsensusMsgInvalidIssuer) => Err(rpc_invalid_arg_error(
                    "send_consensus_msg",
                    "InvalidConsensusMsgIssuer",
                    logger,
                )),
                Err(_) => Err(rpc_internal_error(
                    "send_consensus_msg",
                    "InternalError",
                    logger,
                )),
            };

            send_result(ctx, sink, result, logger);
        });
    }

    /// Returns the highest consensus message issued by this node.
    fn get_latest_msg(
        &mut self,
        ctx: RpcContext,
        _request: (),
        sink: UnarySink<GetLatestMsgResponse>,
    ) {
        let _timer = SVC_COUNTERS.req(&ctx);
        mc_common::logger::scoped_global_logger(&rpc_logger(&ctx, &self.logger), |logger| {
            let payload = if let Some(latest_msg) = (self.fetch_latest_msg_fn)() {
                mc_util_serial::serialize(&latest_msg).expect("Failed serializing consensus msg")
            } else {
                Vec::new()
            };
            let response = GetLatestMsgResponse { payload };
            send_result(ctx, sink, Ok(response), logger);
        });
    }

    /// Returns the full, encrypted transactions corresponding to a list of
    /// transaction hashes.
    fn get_txs(
        &mut self,
        ctx: RpcContext,
        request: GetTxsRequest,
        sink: UnarySink<GetTxsResponse>,
    ) {
        let _timer = SVC_COUNTERS.req(&ctx);
        mc_common::logger::scoped_global_logger(&rpc_logger(&ctx, &self.logger), |logger| {
            let mut tx_hashes: Vec<TxHash> = Vec::new();
            for tx_hash_bytes in request.tx_hashes.iter() {
                match TxHash::try_from(&tx_hash_bytes[..]) {
                    Ok(tx_hash) => tx_hashes.push(tx_hash),
                    Err(_) => {
                        let result = Err(rpc_invalid_arg_error("tx_hash", "", logger));
                        send_result(ctx, sink, result, logger);
                        return;
                    }
                }
            }

            let peer_session = PeerSession::from(request.channel_id);

            let result: Result<GetTxsResponse, RpcStatus> =
                match self.handle_get_txs(tx_hashes, peer_session, logger) {
                    Ok(enclave_message) => Ok(GetTxsResponse {
                        payload: Some(get_txs_response::Payload::Success(enclave_message.into())),
                    }),
                    Err(PeerServiceError::UnknownTransactions(tx_hashes)) => {
                        let tx_hashes_not_in_cache = TxHashesNotInCache {
                            tx_hashes: tx_hashes.iter().map(|tx_hash| tx_hash.to_vec()).collect(),
                        };
                        Ok(GetTxsResponse {
                            payload: Some(get_txs_response::Payload::TxHashesNotInCache(
                                tx_hashes_not_in_cache,
                            )),
                        })
                    }
                    // Unexpected errors:
                    Err(err) => Err(rpc_internal_error("get_txs", err, logger)),
                };

            send_result(ctx, sink, result, logger)
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{background_work_queue::BackgroundWorkQueueError, tx_manager::MockTxManager};
    use grpcio::{
        ChannelBuilder, Environment, Error::RpcFailure, RpcStatusCode, Server, ServerBuilder,
        ServerCredentials,
    };
    use mc_blockchain_types::Block;
    use mc_common::{logger::test_with_logger, NodeID};
    use mc_consensus_api::consensus_peer::{
        create_consensus_peer_api, ConsensusMsg, ConsensusPeerApiClient,
    };
    use mc_consensus_enclave_mock::MockConsensusEnclave;
    use mc_consensus_scp::{
        msg::{NominatePayload, Topic::Nominate},
        Msg, QuorumSet,
    };
    use mc_crypto_keys::{Ed25519Pair, Ed25519Private};
    use mc_ledger_db::MockLedger;
    use mc_util_from_random::FromRandom;
    use rand::{rngs::StdRng, SeedableRng};
    use std::sync::Mutex;

    fn get_consensus_msg_verifier(
        responder_id: ResponderId,
        signer: &Ed25519Pair,
    ) -> Arc<ConsensusMsgVerifier> {
        Arc::new(ConsensusMsgVerifier::new([NodeID {
            responder_id,
            public_key: signer.public_key(),
        }]))
    }

    // Get sensibly-initialized mocks.
    fn get_mocks() -> (MockConsensusEnclave, MockLedger, MockTxManager) {
        let consensus_enclave = MockConsensusEnclave::new();
        let ledger = MockLedger::new();
        let tx_manager = MockTxManager::new();

        (consensus_enclave, ledger, tx_manager)
    }

    /// Always returns OK.
    fn get_incoming_consensus_msgs_sender_ok(
    ) -> Arc<dyn Fn(IncomingConsensusMsg) -> Result<(), BackgroundWorkQueueError> + Sync + Send>
    {
        Arc::new(|_msg: IncomingConsensusMsg| {
            // TODO: store inputs for inspection.
            Ok(())
        })
    }

    // Does nothing.
    fn get_scp_client_value_sender(
    ) -> Arc<dyn Fn(ConsensusValue, Option<&NodeID>, Option<&ResponderId>) + Sync + Send> {
        Arc::new(
            |_value: ConsensusValue,
             _node_id: Option<&NodeID>,
             _responder_id: Option<&ResponderId>| {
                // Do nothing.
            },
        )
    }

    // Returns None.
    fn get_fetch_latest_msg_fn() -> Arc<dyn Fn() -> Option<mc_peers::ConsensusMsg> + Sync + Send> {
        Arc::new(|| None)
    }

    fn get_client_server(instance: PeerApiService) -> (ConsensusPeerApiClient, Server) {
        let service = create_consensus_peer_api(instance);
        let env = Arc::new(Environment::new(1));
        let mut server = ServerBuilder::new(env.clone())
            .register_service(service)
            .build()
            .expect("Could not create GRPC server");
        let port = server
            .add_listening_port("127.0.0.1:0", ServerCredentials::insecure())
            .expect("Could not create anonymous bind");
        server.start();
        let ch = ChannelBuilder::new(env).connect(&format!("127.0.0.1:{port}"));
        let client = ConsensusPeerApiClient::new(ch);
        (client, server)
    }

    #[test_with_logger]
    // Should ignore a message from an unknown peer.
    fn test_send_consensus_msg_ignore_unknown_peer(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([67u8; 32]);
        let (consensus_enclave, ledger, tx_manager) = get_mocks();

        // ResponderIds seem to be "host:port" strings.
        let known_responder_ids = vec![
            ResponderId("A:port".to_owned()),
            ResponderId("B:port".to_owned()),
        ];

        let instance = PeerApiService::new(
            Arc::new(consensus_enclave),
            Arc::new(ledger),
            Arc::new(tx_manager),
            get_incoming_consensus_msgs_sender_ok(),
            get_scp_client_value_sender(),
            get_fetch_latest_msg_fn(),
            known_responder_ids,
            Arc::new(ConsensusMsgVerifier::new([])),
            logger,
        );

        let (client, _server) = get_client_server(instance);

        // A message from an unknown peer.
        let from = ResponderId("X:port".to_owned());
        let node_x_signer_key = Ed25519Pair::from_random(&mut rng);
        let scp_msg = Msg {
            sender_id: NodeID {
                responder_id: from.clone(),
                public_key: node_x_signer_key.public_key(),
            },
            slot_index: 1,
            quorum_set: QuorumSet {
                threshold: 0,
                members: vec![],
            },
            topic: Nominate(NominatePayload {
                X: Default::default(),
                Y: Default::default(),
            }),
        };

        let payload = {
            // Node A's ledger.
            let mut ledger = MockLedger::new();
            ledger
                .expect_get_block()
                .return_const(Ok(Block::new_origin_block(&[])));
            mc_peers::ConsensusMsg::from_scp_msg(&ledger, scp_msg, &node_x_signer_key).unwrap()
        };

        let message = ConsensusMsg {
            from_responder_id: from.to_string(),
            payload: mc_util_serial::serialize(&payload).unwrap(),
        };

        match client.send_consensus_msg(&message) {
            Ok(consensus_msg_response) => {
                assert_eq!(
                    consensus_msg_response.result(),
                    ConsensusMsgResult::UnknownPeer
                );
            }
            Err(e) => panic!("Unexpected error: {e:?}"),
        }
    }

    #[test_with_logger]
    // Should accept a message from a known peer.
    fn test_send_consensus_msg_ok(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([77u8; 32]);
        let (consensus_enclave, ledger, tx_manager) = get_mocks();

        // Node A's private message signing keypair.
        let node_a_signer_key = {
            let private_key = Ed25519Private::from_random(&mut rng);
            Ed25519Pair::from(private_key)
        };

        // ResponderIds seem to be "host:port" strings.
        let known_responder_ids = vec![
            ResponderId("A:port".to_owned()),
            ResponderId("B:port".to_owned()),
        ];

        let instance = PeerApiService::new(
            Arc::new(consensus_enclave),
            Arc::new(ledger),
            Arc::new(tx_manager),
            get_incoming_consensus_msgs_sender_ok(),
            get_scp_client_value_sender(),
            get_fetch_latest_msg_fn(),
            known_responder_ids.clone(),
            get_consensus_msg_verifier(known_responder_ids[0].clone(), &node_a_signer_key),
            logger,
        );

        let (client, _server) = get_client_server(instance);

        // A message from a known peer.
        let from = known_responder_ids[0].clone();

        let scp_msg = Msg {
            sender_id: NodeID {
                responder_id: from.clone(),
                public_key: node_a_signer_key.public_key(),
            },
            slot_index: 1,
            quorum_set: QuorumSet {
                threshold: 0,
                members: vec![],
            },
            topic: Nominate(NominatePayload {
                X: Default::default(),
                Y: Default::default(),
            }),
        };

        let payload = {
            // Node A's ledger.
            let mut ledger = MockLedger::new();
            ledger
                .expect_get_block()
                .return_const(Ok(Block::new_origin_block(&[])));
            mc_peers::ConsensusMsg::from_scp_msg(&ledger, scp_msg, &node_a_signer_key).unwrap()
        };

        let message = ConsensusMsg {
            from_responder_id: from.to_string(),
            payload: mc_util_serial::serialize(&payload).unwrap(),
        };

        match client.send_consensus_msg(&message) {
            Ok(consensus_msg_response) => {
                assert_eq!(consensus_msg_response.result(), ConsensusMsgResult::Ok);
            }
            Err(e) => panic!("Unexpected error: {e:?}"),
        }

        // TODO: Should pass the message to incoming_consensus_msgs_sender
    }

    #[test_with_logger]
    // Should return an error if the message cannot be deserialized.
    fn test_send_consensus_msg_deserialize_error(logger: Logger) {
        let (consensus_enclave, ledger, tx_manager) = get_mocks();

        // ResponderIds seem to be "host:port" strings.
        let known_responder_ids = vec![
            ResponderId("A:port".to_owned()),
            ResponderId("B:port".to_owned()),
        ];

        let instance = PeerApiService::new(
            Arc::new(consensus_enclave),
            Arc::new(ledger),
            Arc::new(tx_manager),
            get_incoming_consensus_msgs_sender_ok(),
            get_scp_client_value_sender(),
            get_fetch_latest_msg_fn(),
            known_responder_ids.clone(),
            Arc::new(ConsensusMsgVerifier::new([])),
            logger,
        );

        let (client, _server) = get_client_server(instance);

        // A message from a known peer. The payload does not deserialize to a
        // ConsensusMsg.
        let from = known_responder_ids[0].clone();
        let message = ConsensusMsg {
            from_responder_id: from.to_string(),
            payload: vec![240, 159, 146, 150], // UTF-8 "sparkle heart".
        };

        match client.send_consensus_msg(&message) {
            Ok(response) => panic!("Unexpected response: {response:?}"),
            Err(RpcFailure(_rpc_status)) => {
                // This is expected.
                // TODO: check status code.
            }
            Err(e) => panic!("Unexpected error: {e:?}"),
        }
    }

    #[test_with_logger]
    // Should return an error if the message signature is wrong.
    fn test_send_consensus_msg_signature_error(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([77u8; 32]);
        let (consensus_enclave, ledger, tx_manager) = get_mocks();

        // Node A's private message signing keypair.
        let node_a_signer_key = {
            let private_key = Ed25519Private::from_random(&mut rng);
            Ed25519Pair::from(private_key)
        };

        // ResponderIds seem to be "host:port" strings.
        let known_responder_ids = vec![
            ResponderId("A:port".to_owned()),
            ResponderId("B:port".to_owned()),
        ];

        let instance = PeerApiService::new(
            Arc::new(consensus_enclave),
            Arc::new(ledger),
            Arc::new(tx_manager),
            get_incoming_consensus_msgs_sender_ok(),
            get_scp_client_value_sender(),
            get_fetch_latest_msg_fn(),
            known_responder_ids.clone(),
            get_consensus_msg_verifier(known_responder_ids[0].clone(), &node_a_signer_key),
            logger,
        );

        let (client, _server) = get_client_server(instance);

        // A message from a known peer.
        let from = known_responder_ids[0].clone();

        let scp_msg = Msg {
            sender_id: NodeID {
                responder_id: from.clone(),
                public_key: node_a_signer_key.public_key(),
            },
            slot_index: 1,
            quorum_set: QuorumSet {
                threshold: 0,
                members: vec![],
            },
            topic: Nominate(NominatePayload {
                X: Default::default(),
                Y: Default::default(),
            }),
        };

        let payload = {
            // Sign the message with a different signer key.
            let wrong_signer_key = {
                let private_key = Ed25519Private::from_random(&mut rng);
                Ed25519Pair::from(private_key)
            };
            let mut ledger = MockLedger::new();
            ledger
                .expect_get_block()
                .return_const(Ok(Block::new_origin_block(&[])));
            mc_peers::ConsensusMsg::from_scp_msg(&ledger, scp_msg, &wrong_signer_key).unwrap()
        };

        let message = ConsensusMsg {
            from_responder_id: from.to_string(),
            payload: mc_util_serial::serialize(&payload).unwrap(),
        };

        match client.send_consensus_msg(&message) {
            Ok(response) => panic!("Unexpected response: {response:?}"),
            Err(RpcFailure(_rpc_status)) => {
                // This is expected.
                // TODO: check status code.
            }
            Err(e) => panic!("Unexpected error: {e:?}"),
        }
    }

    #[test_with_logger]
    fn test_send_consensus_msg_authorizes_issuer_and_preserves_relay(logger: Logger) {
        use mc_peers_test_utils::{create_consensus_msg, test_node_id_and_signer};

        let (consensus_enclave, ledger, tx_manager) = get_mocks();
        let (issuer, issuer_signer) = test_node_id_and_signer(22);
        let (relay, relay_signer) = test_node_id_and_signer(33);
        let (attacker, attacker_signer) = test_node_id_and_signer(44);
        let verifier = Arc::new(ConsensusMsgVerifier::new([issuer.clone(), relay.clone()]));
        let received = Arc::new(Mutex::new(Vec::new()));
        let sender_received = received.clone();
        let instance = PeerApiService::new(
            Arc::new(consensus_enclave),
            Arc::new(ledger),
            Arc::new(tx_manager),
            Arc::new(move |msg| {
                sender_received.lock().unwrap().push(msg);
                Ok(())
            }),
            get_scp_client_value_sender(),
            get_fetch_latest_msg_fn(),
            // The issuer is configured but reachable through this relay only.
            vec![relay.responder_id.clone()],
            verifier,
            logger,
        );
        let (client, _server) = get_client_server(instance);
        let msg_ledger = mc_ledger_db::test_utils::get_mock_ledger(1);
        let make_message = |node_id, signer| {
            create_consensus_msg(&msg_ledger, node_id, QuorumSet::empty(), 1, "value", signer)
        };
        let request = |msg: &mc_peers::ConsensusMsg, from: &ResponderId| ConsensusMsg {
            from_responder_id: from.to_string(),
            payload: mc_util_serial::serialize(msg).unwrap(),
        };

        let mismatches_before = counters::CONSENSUS_MSG_ISSUER_KEY_MISMATCHES.get();
        // Neither an attacker key nor another configured node's key may sign as issuer.
        for signer in [&attacker_signer, &relay_signer] {
            let forged = make_message(
                NodeID {
                    responder_id: issuer.responder_id.clone(),
                    public_key: signer.public_key(),
                },
                signer,
            );
            forged.verify_signature().unwrap();
            match client.send_consensus_msg(&request(&forged, &relay.responder_id)) {
                Err(RpcFailure(status)) => {
                    assert_eq!(status.code(), RpcStatusCode::INVALID_ARGUMENT);
                    assert!(status.message().contains("InvalidConsensusMsgIssuer"));
                }
                result => panic!("Expected issuer validation failure, got {result:?}"),
            }
        }

        assert!(received.lock().unwrap().is_empty());
        assert!(counters::CONSENSUS_MSG_ISSUER_KEY_MISMATCHES.get() >= mismatches_before + 2);
        // Unconfigured participants remain admissible for transitive SCP quorums.
        let unknown = make_message(attacker.clone(), &attacker_signer);
        assert_eq!(
            client
                .send_consensus_msg(&request(&unknown, &relay.responder_id))
                .unwrap()
                .result(),
            ConsensusMsgResult::Ok
        );
        let valid = make_message(issuer.clone(), &issuer_signer);
        assert_eq!(
            client
                .send_consensus_msg(&request(&valid, &attacker.responder_id))
                .unwrap()
                .result(),
            ConsensusMsgResult::UnknownPeer
        );
        assert_eq!(received.lock().unwrap().len(), 1);

        assert_eq!(
            client
                .send_consensus_msg(&request(&valid, &relay.responder_id))
                .unwrap()
                .result(),
            ConsensusMsgResult::Ok
        );
        let received = received.lock().unwrap();
        assert_eq!(received.len(), 2);
        assert_eq!(received[0].consensus_msg.as_ref(), &unknown);
        assert_eq!(received[1].from_responder_id, relay.responder_id);
        assert_eq!(received[1].consensus_msg.as_ref(), &valid);
    }

    // TODO: fetch_latest_msg

    // TODO: fetch_txs

    // TODO: peer_tx_propose
}
