// Copyright (c) 2018-2020 MobileCoin Inc.

//! Serves client-to-node gRPC requests.

use crate::{
    consensus_service::ProposeTxCallback,
    counters,
    grpc_error::ConsensusGrpcError,
    tx_manager::{TxManager, TxManagerError},
};
use grpcio::{RpcContext, UnarySink};
use mc_attest_api::attest::Message;
use mc_common::logger::Logger;
use mc_consensus_api::{
    consensus_client_grpc::ConsensusClientApi, consensus_common::ProposeTxResponse,
};
use mc_consensus_enclave::{ConsensusEnclave, TxContext};
use mc_ledger_db::Ledger;
use mc_transaction_core::validation::TransactionValidationError;
use mc_util_grpc::{rpc_logger, send_result};
use mc_util_metrics::{self, SVC_COUNTERS};
use std::sync::Arc;

/// Maximum number of pending values for consensus service before rejecting add_transaction requests.
const PENDING_LIMIT: i64 = 500;

#[derive(Clone)]
pub struct ClientApiService {
    enclave: Arc<dyn ConsensusEnclave + Send + Sync>,
    tx_manager: Arc<dyn TxManager + Send + Sync>,
    ledger: Arc<dyn Ledger + Send + Sync>,
    /// Passes proposed transactions to the consensus service.
    propose_tx_callback: ProposeTxCallback,
    /// Returns true if this node is able to process proposed transactions.
    is_serving_fn: Arc<(dyn Fn() -> bool + Sync + Send)>,
    logger: Logger,
}

impl ClientApiService {
    pub fn new(
        enclave: Arc<dyn ConsensusEnclave + Send + Sync>,
        scp_client_value_sender: ProposeTxCallback,
        ledger: Arc<dyn Ledger + Send + Sync>,
        tx_manager: Arc<dyn TxManager + Send + Sync>,
        is_serving_fn: Arc<(dyn Fn() -> bool + Sync + Send)>,
        logger: Logger,
    ) -> Self {
        Self {
            enclave,
            tx_manager,
            ledger,
            propose_tx_callback: scp_client_value_sender,
            is_serving_fn,
            logger,
        }
    }

    /// Handles a client's proposed transaction.
    ///
    /// # Arguments
    /// `msg` - An encrypted message from a client to the enclave.
    /// `logger` - Logger
    fn handle_proposed_tx(
        &mut self,
        msg: Message,
    ) -> Result<ProposeTxResponse, ConsensusGrpcError> {
        counters::ADD_TX_INITIATED.inc();

        if counters::CUR_NUM_PENDING_VALUES.get() > PENDING_LIMIT {
            // This node is over capacity, and is not accepting proposed transaction.
            self.enclave.client_discard_message(msg.into())?;
            return Err(ConsensusGrpcError::OverCapacity);
        }

        if !(self.is_serving_fn)() {
            // This node is unable to process transactions (e.g. is syncing its ledger).
            self.enclave.client_discard_message(msg.into())?;
            return Err(ConsensusGrpcError::NotServing);
        }

        let tx_context = self.enclave.client_tx_propose(msg.into())?;

        let num_blocks = self.ledger.num_blocks().map_err(ConsensusGrpcError::from)?;

        // Reject the proposed transaction if it contains any key images that have already been spent.
        // This is done here as a courtesy to give clients immediate feedback about their transaction.
        if self.contains_spent_key_image(&tx_context)? {
            return Err(ConsensusGrpcError::from(
                TransactionValidationError::ContainsSpentKeyImage,
            ));
        }

        self.tx_manager
            .insert(tx_context)
            .map(|tx_hash| {
                // Submit for consideration in next SCP slot.
                (*self.propose_tx_callback)(tx_hash, None, None);
                counters::ADD_TX.inc();
                let mut response = ProposeTxResponse::new();
                response.set_num_blocks(num_blocks);
                Ok(response)
            })
            .map_err(|err| {
                if let TxManagerError::TransactionValidation(cause) = &err {
                    counters::TX_VALIDATION_ERROR_COUNTER.inc(&format!("{:?}", cause));
                }
                err
            })?
    }

    /// Returns true if the transaction contains a spent key image.
    ///
    /// This is only a best-effort check, and may give inconsistent results if the ledger is
    /// concurrently modified.
    fn contains_spent_key_image(&self, tx_context: &TxContext) -> Result<bool, ConsensusGrpcError> {
        let mut contains_spent_key_image = false;
        for key_image in &tx_context.key_images {
            if self.ledger.contains_key_image(key_image)? {
                contains_spent_key_image = true;
                break;
            }
        }
        Ok(contains_spent_key_image)
    }
}

impl ConsensusClientApi for ClientApiService {
    fn client_tx_propose(
        &mut self,
        ctx: RpcContext,
        request: Message,
        sink: UnarySink<ProposeTxResponse>,
    ) {
        let _timer = SVC_COUNTERS.req(&ctx);

        let resp = self
            .handle_proposed_tx(request)
            .or_else(ConsensusGrpcError::into);

        mc_common::logger::scoped_global_logger(&rpc_logger(&ctx, &self.logger), |logger| {
            send_result(ctx, sink, resp, &logger)
        });
    }
}

#[cfg(test)]
mod tests {
    use crate::{client_api_service::ClientApiService, tx_manager::MockTxManager};
    use grpcio::{ChannelBuilder, Environment, Server, ServerBuilder};
    use mc_attest_api::attest::Message;
    use mc_common::{
        logger::{test_with_logger, Logger},
        NodeID, ResponderId,
    };
    use mc_consensus_api::{
        consensus_client_grpc, consensus_client_grpc::ConsensusClientApiClient,
        consensus_common::ProposeTxResult,
    };
    use mc_consensus_enclave::TxContext;
    use mc_consensus_enclave_mock::MockConsensusEnclave;
    use mc_ledger_db::MockLedger;
    use mc_transaction_core::{ring_signature::KeyImage, tx::TxHash};
    use std::sync::Arc;

    /// Starts the service on localhost and connects a client to it.
    fn get_client_server(instance: ClientApiService) -> (ConsensusClientApiClient, Server) {
        let service = consensus_client_grpc::create_consensus_client_api(instance);
        let env = Arc::new(Environment::new(1));
        let mut server = ServerBuilder::new(env.clone())
            .register_service(service)
            .bind("127.0.0.1", 0)
            .build()
            .unwrap();
        server.start();
        let (_, port) = server.bind_addrs().next().unwrap();

        let ch = ChannelBuilder::new(env).connect(&format!("127.0.0.1:{}", port));
        let client = ConsensusClientApiClient::new(ch);
        (client, server)
    }

    #[test_with_logger]
    fn test_client_tx_propose_ok(logger: Logger) {
        let mut consensus_enclave = MockConsensusEnclave::new();
        {
            // Return a TxContext that contains some KeyImages.
            let mut tx_context = TxContext::default();
            tx_context.key_images = vec![KeyImage::default(), KeyImage::default()];

            consensus_enclave
                .expect_client_tx_propose()
                .times(1)
                .return_const(Ok(tx_context));
        }

        // Arc<dyn Fn(TxHash, Option<&NodeID>, Option<&ResponderId>) + Sync + Send>
        let scp_client_value_sender = Arc::new(
            |_tx_hash: TxHash, _node_id: Option<&NodeID>, _responder_id: Option<&ResponderId>| {
                // TODO: store inputs for inspection.
            },
        );

        let num_blocks = 5;
        let mut ledger = MockLedger::new();
        // The service should request num_blocks.
        ledger
            .expect_num_blocks()
            .times(1)
            .return_const(Ok(num_blocks));

        // The service should check if each key image is already in the ledger.
        ledger
            .expect_contains_key_image()
            .times(2)
            .return_const(Ok(false));

        let mut tx_manager = MockTxManager::new();
        tx_manager
            .expect_insert()
            .times(1)
            .return_const(Ok(TxHash::default()));

        let is_serving_fn = Arc::new(|| -> bool { true });

        let instance = ClientApiService::new(
            Arc::new(consensus_enclave),
            scp_client_value_sender,
            Arc::new(ledger),
            Arc::new(tx_manager),
            is_serving_fn,
            logger,
        );

        // gRPC client and server.
        let (client, _server) = get_client_server(instance);

        let message = Message::default();
        match client.client_tx_propose(&message) {
            Ok(propose_tx_response) => {
                assert_eq!(propose_tx_response.get_result(), ProposeTxResult::Ok);
                assert_eq!(propose_tx_response.get_num_blocks(), num_blocks);
            }
            Err(e) => panic!("unexpected error: {:?}", e),
        }
    }
}
