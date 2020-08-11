// Copyright (c) 2018-2020 MobileCoin Inc.

//! Serves node-to-node gRPC requests.

use crate::{
    background_work_queue::BackgroundWorkQueueSenderFn,
    consensus_service::{IncomingConsensusMsg, ProposeTxCallback},
    counters,
    grpc_error::ConsensusGrpcError,
    tx_manager::{TxManager, TxManagerError},
};
use grpcio::{RpcContext, UnarySink};
use mc_attest_api::attest::Message;
use mc_attest_enclave_api::{EnclaveMessage, PeerSession};
use mc_common::{
    logger::{log, Logger},
    ResponderId,
};
use mc_consensus_api::{
    consensus_common::ProposeTxResponse,
    consensus_peer::{
        ConsensusMsg as GrpcConsensusMsg, ConsensusMsgResponse, ConsensusMsgResult,
        FetchLatestMsgResponse, FetchTxsRequest,
    },
    consensus_peer_grpc::ConsensusPeerApi,
    empty::Empty,
};
use mc_consensus_enclave::ConsensusEnclaveProxy;
use mc_ledger_db::Ledger;
use mc_peers::TxProposeAAD;
use mc_transaction_core::tx::TxHash;
use mc_util_grpc::{rpc_invalid_arg_error, rpc_logger, send_result};
use mc_util_metrics::SVC_COUNTERS;
use mc_util_serial::deserialize;
use std::{
    convert::{TryFrom, TryInto},
    str::FromStr,
    sync::Arc,
};

// Callback method for returning the latest SCP message issued by the local node, used to
// implement the `fetch_latest_msg` RPC call.
type FetchLatestMsgFn = Arc<dyn Fn() -> Option<mc_peers::ConsensusMsg> + Sync + Send>;

#[derive(Clone)]
pub struct PeerApiService<E: ConsensusEnclaveProxy, L: Ledger> {
    /// Enclave instance.
    enclave: E,

    /// Callback function for feeding consensus messages into ByzantineLedger.
    incoming_consensus_msgs_sender: BackgroundWorkQueueSenderFn<IncomingConsensusMsg>,

    /// Callback function for feeding transactions into ByzantineLedger.
    scp_client_value_sender: ProposeTxCallback,

    /// Ledger database.
    ledger: L,

    /// Transactions Manager instance.
    tx_manager: TxManager<E, L>,

    /// Callback function for getting the latest SCP statement the local node has issued.
    fetch_latest_msg_fn: FetchLatestMsgFn,

    /// List of recognized responder IDs to accept messages from.
    /// We only want to accept messages from peers we can initiate outgoing requests to. That is
    /// necessary for resolving TxHashes into Txs. If we received a consensus message from a peer
    /// not on this list, we won't be able to reach out to it to ask for the transaction contents.
    known_responder_ids: Vec<ResponderId>,

    /// Logger.
    logger: Logger,
}

impl<E: ConsensusEnclaveProxy, L: Ledger> PeerApiService<E, L> {
    pub fn new(
        enclave: E,
        incoming_consensus_msgs_sender: BackgroundWorkQueueSenderFn<IncomingConsensusMsg>,
        scp_client_value_sender: ProposeTxCallback,
        ledger: L,
        tx_manager: TxManager<E, L>,
        fetch_latest_msg_fn: FetchLatestMsgFn,
        known_responder_ids: Vec<ResponderId>,
        logger: Logger,
    ) -> Self {
        Self {
            enclave,
            incoming_consensus_msgs_sender,
            scp_client_value_sender,
            ledger,
            tx_manager,
            fetch_latest_msg_fn,
            known_responder_ids,
            logger,
        }
    }

    fn real_peer_tx_propose(
        &mut self,
        request: Message,
        logger: &Logger,
    ) -> Result<ProposeTxResponse, ConsensusGrpcError> {
        // TODO: Use the prost message directly when available, take a reference
        let enclave_msg: EnclaveMessage<PeerSession> = request.into();
        let aad = enclave_msg.aad.clone();
        let tx_contexts = self.enclave.peer_tx_propose(enclave_msg)?;

        // We fail silently here since the only effect of not having
        // origin_node/relayed_by node IDs is less efficient broadcasting.
        let (origin_node, relayed_by) = mc_util_serial::deserialize::<TxProposeAAD>(&aad)
            .map(|aad| (Some(aad.origin_node), Some(aad.relayed_by)))
            .unwrap_or((None, None));

        // Feed to manager
        for tx_context in tx_contexts {
            let tx_hash = tx_context.tx_hash;

            match self.tx_manager.insert_proposed_tx(tx_context) {
                Ok(tx_context) => {
                    // Submit for consideration in next SCP slot.
                    (*self.scp_client_value_sender)(
                        *tx_context.tx_hash(),
                        origin_node.as_ref(),
                        relayed_by.as_ref(),
                    );
                }

                Err(TxManagerError::AlreadyInCache) => {}

                Err(TxManagerError::TransactionValidation(err)) => {
                    log::debug!(
                        logger,
                        "Error validating transaction {tx_hash}: {err}",
                        tx_hash = tx_hash.to_string(),
                        err = format!("{:?}", err)
                    );
                    counters::TX_VALIDATION_ERROR_COUNTER.inc(&format!("{:?}", err));
                }

                Err(err) => {
                    log::info!(
                        logger,
                        "tx_propose failed for {tx_hash}: {err}",
                        tx_hash = tx_hash.to_string(),
                        err = format!("{:?}", err)
                    );
                }
            };
        }

        Ok(ProposeTxResponse::new())
    }

    /// Get tx contents.
    fn real_fetch_txs(
        &mut self,
        request: FetchTxsRequest,
        logger: &Logger,
    ) -> Result<Message, ConsensusGrpcError> {
        let tx_hashes: Vec<TxHash> = request
            .get_tx_hashes()
            .iter()
            .map(|bytes| {
                TxHash::try_from(&bytes[..])
                    .map_err(|_| ConsensusGrpcError::InvalidArgument("invalid tx hash".to_string()))
            })
            .collect::<Result<Vec<TxHash>, ConsensusGrpcError>>()?;

        match self.tx_manager.txs_for_peer(
            &tx_hashes,
            &[],
            &PeerSession::from(request.get_channel_id()),
        ) {
            Ok(enclave_message) => Ok(enclave_message.into()),
            Err(err) => {
                log::warn!(
                    logger,
                    "txs_for_peer with hashes {:?} failed: {}",
                    tx_hashes,
                    err
                );
                Err(err.into())
            }
        }
    }
}

impl<E: ConsensusEnclaveProxy, L: Ledger> ConsensusPeerApi for PeerApiService<E, L> {
    fn peer_tx_propose(
        &mut self,
        ctx: RpcContext,
        request: Message,
        sink: UnarySink<ProposeTxResponse>,
    ) {
        let _timer = SVC_COUNTERS.req(&ctx);
        mc_common::logger::scoped_global_logger(&rpc_logger(&ctx, &self.logger), |logger| {
            send_result(
                ctx,
                sink,
                self.real_peer_tx_propose(request, &logger)
                    .or_else(ConsensusGrpcError::into)
                    .and_then(|mut resp| {
                        resp.set_num_blocks(
                            self.ledger.num_blocks().map_err(ConsensusGrpcError::from)?,
                        );
                        Ok(resp)
                    }),
                &logger,
            )
        });
    }

    fn send_consensus_msg(
        &mut self,
        ctx: RpcContext,
        request: GrpcConsensusMsg,
        sink: UnarySink<ConsensusMsgResponse>,
    ) {
        let _timer = SVC_COUNTERS.req(&ctx);
        mc_common::logger::scoped_global_logger(&rpc_logger(&ctx, &self.logger), |logger| {
            let unverified_consensus_msg: mc_peers::ConsensusMsg =
                match deserialize(request.get_payload()) {
                    Ok(val) => val,
                    Err(err) => {
                        send_result(
                            ctx,
                            sink,
                            Err(rpc_invalid_arg_error(
                                "send_consensus_msg",
                                format!("Message deserialize error: {}", err),
                                &logger,
                            )),
                            &logger,
                        );
                        return;
                    }
                };

            // Get the peer who delivered this message to us.
            let from_responder_id = match ResponderId::from_str(request.get_from_responder_id()) {
                Ok(val) => val,
                Err(err) => {
                    send_result(
                        ctx,
                        sink,
                        Err(rpc_invalid_arg_error(
                            "send_consensus_msg",
                            format!("From node ID deserialize error: {}", err),
                            &logger,
                        )),
                        &logger,
                    );
                    return;
                }
            };

            // See if we recognize this peer.
            if !self.known_responder_ids.contains(&from_responder_id) {
                let mut resp = ConsensusMsgResponse::new();
                resp.set_result(ConsensusMsgResult::UnknownPeer);
                send_result(ctx, sink, Ok(resp), &logger);
                log::warn!(
                    logger,
                    "Rejecting consensus message from unrecognized responder id {}",
                    from_responder_id
                );
                return;
            }

            // Validate message signature
            let consensus_msg: mc_peers::VerifiedConsensusMsg = match unverified_consensus_msg
                .clone()
                .try_into()
            {
                Ok(val) => val,
                Err(err) => {
                    log::error!(
                        logger,
                        "Signature verification failed for msg {:?} from node_id {:?}: {:?}, disregarding.",
                        unverified_consensus_msg,
                        from_responder_id,
                        err
                    );
                    send_result(
                        ctx,
                        sink,
                        Err(rpc_invalid_arg_error(
                            "send_consensus_msg",
                            format!("Signature verification failed: {}", err),
                            &logger,
                        )),
                        &logger,
                    );
                    return;
                }
            };

            log::trace!(
                logger,
                "received consensus message from {}: {:?}",
                from_responder_id,
                consensus_msg,
            );

            (self.incoming_consensus_msgs_sender)(IncomingConsensusMsg {
                from_responder_id,
                consensus_msg,
            })
            .expect("Could not send consensus input");
            let mut resp = ConsensusMsgResponse::new();
            resp.set_result(ConsensusMsgResult::Ok);
            send_result(ctx, sink, Ok(resp), &logger);
        });
    }

    fn fetch_latest_msg(
        &mut self,
        ctx: RpcContext,
        _request: Empty,
        sink: UnarySink<FetchLatestMsgResponse>,
    ) {
        let _timer = SVC_COUNTERS.req(&ctx);
        mc_common::logger::scoped_global_logger(&rpc_logger(&ctx, &self.logger), |logger| {
            let mut response = FetchLatestMsgResponse::new();
            if let Some(latest_msg) = (self.fetch_latest_msg_fn)() {
                let serialized_msg = mc_util_serial::serialize(&latest_msg)
                    .expect("failed serializizng consensus msg");
                response.set_payload(serialized_msg);
            }
            send_result(ctx, sink, Ok(response), &logger);
        });
    }

    fn fetch_txs(&mut self, ctx: RpcContext, request: FetchTxsRequest, sink: UnarySink<Message>) {
        let _timer = SVC_COUNTERS.req(&ctx);
        mc_common::logger::scoped_global_logger(&rpc_logger(&ctx, &self.logger), |logger| {
            send_result(
                ctx,
                sink,
                self.real_fetch_txs(request, &logger)
                    .map_err(ConsensusGrpcError::into),
                &logger,
            )
        });
    }
}
