// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Serves client-to-node gRPC requests.

use crate::{
    api::grpc_error::ConsensusGrpcError,
    consensus_service::ProposeTxCallback,
    counters,
    tx_manager::{TxManager, TxManagerError},
};
use grpcio::{RpcContext, RpcStatus, UnarySink};
use mc_attest_api::attest::Message;
use mc_common::logger::Logger;
use mc_consensus_api::{
    consensus_client_grpc::ConsensusClientApi,
    consensus_common::{ProposeTxResponse, ProposeTxResult},
};
use mc_consensus_enclave::ConsensusEnclave;
use mc_ledger_db::Ledger;
use mc_util_grpc::{rpc_logger, send_result, Authenticator};
use mc_util_metrics::{self, SVC_COUNTERS};
use std::sync::Arc;

/// Maximum number of pending values for consensus service before rejecting
/// add_transaction requests.
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
    authenticator: Arc<dyn Authenticator + Send + Sync>,
    logger: Logger,
}

impl ClientApiService {
    pub fn new(
        enclave: Arc<dyn ConsensusEnclave + Send + Sync>,
        scp_client_value_sender: ProposeTxCallback,
        ledger: Arc<dyn Ledger + Send + Sync>,
        tx_manager: Arc<dyn TxManager + Send + Sync>,
        is_serving_fn: Arc<(dyn Fn() -> bool + Sync + Send)>,
        authenticator: Arc<dyn Authenticator + Send + Sync>,
        logger: Logger,
    ) -> Self {
        Self {
            enclave,
            tx_manager,
            ledger,
            propose_tx_callback: scp_client_value_sender,
            is_serving_fn,
            authenticator,
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
        let tx_context = self.enclave.client_tx_propose(msg.into())?;
        let mut response = ProposeTxResponse::new();

        // Cache the transaction. This performs the well-formedness checks.
        let tx_hash = self.tx_manager.insert(tx_context).map_err(|err| {
            if let TxManagerError::TransactionValidation(cause) = &err {
                counters::TX_VALIDATION_ERROR_COUNTER.inc(&format!("{:?}", cause));
                let result = ProposeTxResult::from(cause.clone());
                response.set_result(result);
            }
            err
        })?;

        // Validate the transaction.
        // This is done here as a courtesy to give clients immediate feedback about the
        // transaction.
        self.tx_manager.validate(&tx_hash)?;

        // The transaction can be considered by the network.
        (*self.propose_tx_callback)(tx_hash, None, None);
        counters::ADD_TX.inc();
        Ok(response)
    }
}

impl ConsensusClientApi for ClientApiService {
    fn client_tx_propose(
        &mut self,
        ctx: RpcContext,
        msg: Message,
        sink: UnarySink<ProposeTxResponse>,
    ) {
        let _timer = SVC_COUNTERS.req(&ctx);

        if let Err(err) = self.authenticator.authenticate_rpc(&ctx) {
            return send_result(ctx, sink, err.into(), &self.logger);
        }

        let mut result: Result<ProposeTxResponse, RpcStatus> =
            if counters::CUR_NUM_PENDING_VALUES.get() >= PENDING_LIMIT {
                // This node is over capacity, and is not accepting proposed transaction.
                if let Err(e) = self.enclave.client_discard_message(msg.into()) {
                    ConsensusGrpcError::Enclave(e).into()
                } else {
                    ConsensusGrpcError::OverCapacity.into()
                }
            } else if !(self.is_serving_fn)() {
                // This node is unable to process transactions (e.g. is syncing its ledger).
                if let Err(e) = self.enclave.client_discard_message(msg.into()) {
                    ConsensusGrpcError::Enclave(e).into()
                } else {
                    ConsensusGrpcError::NotServing.into()
                }
            } else {
                self.handle_proposed_tx(msg)
                    .or_else(ConsensusGrpcError::into)
            };

        result = result.and_then(|mut response| {
            let num_blocks = self.ledger.num_blocks().map_err(ConsensusGrpcError::from)?;
            response.set_block_count(num_blocks);
            Ok(response)
        });

        mc_common::logger::scoped_global_logger(&rpc_logger(&ctx, &self.logger), |logger| {
            send_result(ctx, sink, result, &logger)
        });
    }
}

#[cfg(test)]
mod client_api_tests {
    use crate::{
        api::client_api_service::{ClientApiService, PENDING_LIMIT},
        counters,
        tx_manager::{MockTxManager, TxManagerError},
    };
    use grpcio::{
        ChannelBuilder, Environment, Error as GrpcError, RpcStatusCode, Server, ServerBuilder,
    };
    use mc_attest_api::attest::Message;
    use mc_common::{
        logger::{test_with_logger, Logger},
        time::SystemTimeProvider,
        NodeID, ResponderId,
    };
    use mc_consensus_api::{
        consensus_client_grpc, consensus_client_grpc::ConsensusClientApiClient,
        consensus_common::ProposeTxResult,
    };
    use mc_consensus_enclave::TxContext;
    use mc_consensus_enclave_mock::MockConsensusEnclave;
    use mc_ledger_db::MockLedger;
    use mc_transaction_core::{
        ring_signature::KeyImage, tx::TxHash, validation::TransactionValidationError,
    };
    use mc_util_grpc::{AnonymousAuthenticator, TokenAuthenticator};
    use serial_test_derive::serial;
    use std::{sync::Arc, time::Duration};

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
    #[serial(counters)]
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

        let mut tx_manager = MockTxManager::new();
        tx_manager
            .expect_insert()
            .times(1)
            .return_const(Ok(TxHash::default()));
        tx_manager.expect_validate().times(1).return_const(Ok(()));

        let is_serving_fn = Arc::new(|| -> bool { true });

        let authenticator = AnonymousAuthenticator::default();

        let instance = ClientApiService::new(
            Arc::new(consensus_enclave),
            scp_client_value_sender,
            Arc::new(ledger),
            Arc::new(tx_manager),
            is_serving_fn,
            Arc::new(authenticator),
            logger,
        );

        // gRPC client and server.
        let (client, _server) = get_client_server(instance);
        let message = Message::default();
        match client.client_tx_propose(&message) {
            Ok(propose_tx_response) => {
                assert_eq!(propose_tx_response.get_result(), ProposeTxResult::Ok);
                assert_eq!(propose_tx_response.get_block_count(), num_blocks);
            }
            Err(e) => panic!("Unexpected error: {:?}", e),
        }
    }

    #[test_with_logger]
    #[serial(counters)]
    // Should return ProposeTxResult::ContainsSpentKeyImage if the tx contains a
    // spent key image.
    fn test_client_tx_propose_spent_key_image(logger: Logger) {
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

        let scp_client_value_sender = Arc::new(
            |_tx_hash: TxHash, _node_id: Option<&NodeID>, _responder_id: Option<&ResponderId>| {},
        );

        let mut ledger = MockLedger::new();
        // The service should request num_blocks.
        let num_blocks = 5;
        ledger
            .expect_num_blocks()
            .times(1)
            .return_const(Ok(num_blocks));

        // The service should return without calling tx_manager.
        let mut tx_manager = MockTxManager::new();
        tx_manager
            .expect_insert()
            .times(1)
            .return_const(Ok(TxHash::default()));

        tx_manager.expect_validate().times(1).return_const(Err(
            TxManagerError::TransactionValidation(
                TransactionValidationError::ContainsSpentKeyImage,
            ),
        ));

        let is_serving_fn = Arc::new(|| -> bool { true });

        let authenticator = AnonymousAuthenticator::default();

        let instance = ClientApiService::new(
            Arc::new(consensus_enclave),
            scp_client_value_sender,
            Arc::new(ledger),
            Arc::new(tx_manager),
            is_serving_fn,
            Arc::new(authenticator),
            logger,
        );

        // gRPC client and server.
        let (client, _server) = get_client_server(instance);

        let message = Message::default();
        match client.client_tx_propose(&message) {
            Ok(propose_tx_response) => {
                assert_eq!(
                    propose_tx_response.get_result(),
                    ProposeTxResult::ContainsSpentKeyImage
                );
                assert_eq!(propose_tx_response.get_block_count(), num_blocks);
            }
            Err(e) => panic!("Unexpected error: {:?}", e),
        }
    }

    #[test_with_logger]
    #[serial(counters)]
    // Should return ProposeTxResult::<SomeError> if the tx is not well-formed.
    fn test_client_tx_propose_tx_not_well_formed(logger: Logger) {
        let mut consensus_enclave = MockConsensusEnclave::new();

        // Return a TxContext that contains some KeyImages.
        let mut tx_context = TxContext::default();
        tx_context.key_images = vec![KeyImage::default(), KeyImage::default()];

        consensus_enclave
            .expect_client_tx_propose()
            .times(1)
            .return_const(Ok(tx_context));

        let scp_client_value_sender = Arc::new(
            |_tx_hash: TxHash, _node_id: Option<&NodeID>, _responder_id: Option<&ResponderId>| {},
        );

        let num_blocks = 5;
        let mut ledger = MockLedger::new();
        // The service should request num_blocks.
        ledger
            .expect_num_blocks()
            .times(1)
            .return_const(Ok(num_blocks));

        let mut tx_manager = MockTxManager::new();
        tx_manager.expect_insert().times(1).return_const(Err(
            TxManagerError::TransactionValidation(TransactionValidationError::InvalidRangeProof),
        ));

        let is_serving_fn = Arc::new(|| -> bool { true });

        let authenticator = AnonymousAuthenticator::default();

        let instance = ClientApiService::new(
            Arc::new(consensus_enclave),
            scp_client_value_sender,
            Arc::new(ledger),
            Arc::new(tx_manager),
            is_serving_fn,
            Arc::new(authenticator),
            logger,
        );

        // gRPC client and server.
        let (client, _server) = get_client_server(instance);

        let message = Message::default();
        match client.client_tx_propose(&message) {
            Ok(propose_tx_response) => {
                assert_eq!(
                    propose_tx_response.get_result(),
                    ProposeTxResult::InvalidRangeProof
                );
                assert_eq!(propose_tx_response.get_block_count(), num_blocks);
            }
            Err(e) => panic!("Unexpected error: {:?}", e),
        }
    }

    #[test_with_logger]
    #[serial(counters)]
    // Should return RpcStatus Unavailable if the node is not serving.
    fn test_client_tx_propose_tx_is_not_serving(logger: Logger) {
        let mut enclave = MockConsensusEnclave::new();
        enclave
            .expect_client_discard_message()
            .times(1)
            .return_const(Ok(()));

        let is_serving_fn = Arc::new(|| -> bool { false }); // Not serving

        let scp_client_value_sender = Arc::new(
            |_tx_hash: TxHash, _node_id: Option<&NodeID>, _responder_id: Option<&ResponderId>| {},
        );

        let authenticator = AnonymousAuthenticator::default();

        let instance = ClientApiService::new(
            Arc::new(enclave),
            scp_client_value_sender,
            Arc::new(MockLedger::new()),
            Arc::new(MockTxManager::new()),
            is_serving_fn,
            Arc::new(authenticator),
            logger,
        );

        // gRPC client and server.
        let (client, _server) = get_client_server(instance);

        let message = Message::default();
        match client.client_tx_propose(&message) {
            Ok(propose_tx_response) => {
                panic!("Unexpected response {:?}", propose_tx_response);
            }
            Err(_) => {
                // Should be RpcFailure(RpcStatus { status: 14-UNAVAILABLE,
                // details: Some("Temporarily not serving requests")
            }
        }
    }

    #[test_with_logger]
    #[serial(counters)]
    // Should return RpcStatus Unavailable if the node is over capacity.
    // This test modifies a the global variable `counters::CUR_NUM_PENDING_VALUES`,
    // which means it cannot run in parallel with other tests that depend on
    // that value (e.g. all tests in this module).
    fn test_client_tx_propose_tx_over_capacity(logger: Logger) {
        let mut enclave = MockConsensusEnclave::new();
        enclave
            .expect_client_discard_message()
            .times(1)
            .return_const(Ok(()));

        let is_serving_fn = Arc::new(|| -> bool { true });

        let scp_client_value_sender = Arc::new(
            |_tx_hash: TxHash, _node_id: Option<&NodeID>, _responder_id: Option<&ResponderId>| {},
        );

        let authenticator = AnonymousAuthenticator::default();

        let instance = ClientApiService::new(
            Arc::new(enclave),
            scp_client_value_sender,
            Arc::new(MockLedger::new()),
            Arc::new(MockTxManager::new()),
            is_serving_fn,
            Arc::new(authenticator),
            logger,
        );

        // gRPC client and server.
        let (client, _server) = get_client_server(instance);

        // Set the number of pending values to be above the PENDING_LIMIT
        // This is a global variable, and so affects other unit tests. It must be reset
        // afterwards :(
        counters::CUR_NUM_PENDING_VALUES.set(PENDING_LIMIT);

        let message = Message::default();
        match client.client_tx_propose(&message) {
            Ok(propose_tx_response) => {
                panic!("Unexpected response {:?}", propose_tx_response);
            }
            Err(_) => {
                // Should be RpcFailure(RpcStatus { status: 14-UNAVAILABLE,
                // details: Some("Temporarily not serving requests")
            }
        }

        // This is a global variable. It affects other unit tests, so must be reset :(
        counters::CUR_NUM_PENDING_VALUES.set(0);
    }

    #[test_with_logger]
    #[serial(counters)]
    fn test_client_tx_propose_rejects_unauthenticated(logger: Logger) {
        let enclave = MockConsensusEnclave::new();

        let is_serving_fn = Arc::new(|| -> bool { true }); // Not serving

        let scp_client_value_sender = Arc::new(
            |_tx_hash: TxHash, _node_id: Option<&NodeID>, _responder_id: Option<&ResponderId>| {},
        );

        let authenticator = TokenAuthenticator::new(
            [1; 32],
            Duration::from_secs(60),
            SystemTimeProvider::default(),
        );

        let instance = ClientApiService::new(
            Arc::new(enclave),
            scp_client_value_sender,
            Arc::new(MockLedger::new()),
            Arc::new(MockTxManager::new()),
            is_serving_fn,
            Arc::new(authenticator),
            logger,
        );

        // gRPC client and server.
        let (client, _server) = get_client_server(instance);

        let message = Message::default();
        match client.client_tx_propose(&message) {
            Ok(response) => {
                panic!("Unexpected response {:?}", response);
            }
            Err(GrpcError::RpcFailure(rpc_status)) => {
                assert_eq!(rpc_status.code(), RpcStatusCode::UNAUTHENTICATED);
            }
            Err(err @ _) => {
                panic!("Unexpected error {:?}", err);
            }
        };
    }
}
