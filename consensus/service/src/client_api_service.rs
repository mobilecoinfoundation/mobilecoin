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
use mc_common::logger::{log, Logger};
use mc_consensus_api::{
    consensus_client_grpc::ConsensusClientApi, consensus_common::ProposeTxResponse,
};
use mc_consensus_enclave::ConsensusEnclave;
use mc_ledger_db::Ledger;
use mc_transaction_core::validation::TransactionValidationError;
use mc_util_grpc::{rpc_logger, send_result};
use mc_util_metrics::{self, SVC_COUNTERS};
use std::sync::Arc;

/// Maximum number of pending values for consensus service before rejecting add_transaction requests.
const PENDING_LIMIT: i64 = 500;

#[derive(Clone)]
pub struct ClientApiService<L: Ledger + Clone> {
    enclave: Arc<dyn ConsensusEnclave + Send + Sync>,
    scp_client_value_sender: ProposeTxCallback,
    ledger: L,
    tx_manager: Arc<dyn TxManager + Send + Sync>,
    is_serving_fn: Arc<(dyn Fn() -> bool + Sync + Send)>,
    logger: Logger,
}

impl<L: Ledger + Clone> ClientApiService<L> {
    pub fn new(
        enclave: Arc<dyn ConsensusEnclave + Send + Sync>,
        scp_client_value_sender: ProposeTxCallback,
        ledger: L,
        tx_manager: Arc<dyn TxManager + Send + Sync>,
        is_serving_fn: Arc<(dyn Fn() -> bool + Sync + Send)>,
        logger: Logger,
    ) -> Self {
        Self {
            enclave,
            scp_client_value_sender,
            tx_manager,
            ledger,
            is_serving_fn,
            logger,
        }
    }

    fn real_client_tx_propose(
        &mut self,
        request: Message,
        logger: &Logger,
    ) -> Result<ProposeTxResponse, ConsensusGrpcError> {
        counters::ADD_TX_INITIATED.inc();

        if counters::CUR_NUM_PENDING_VALUES.get() > PENDING_LIMIT {
            self.enclave.client_discard_message(request.into())?;

            log::trace!(
                logger,
                "Ignoring add transaction call, node is over capacity."
            );
            return Err(ConsensusGrpcError::OverCapacity);
        }

        // Check if node is accepting requests.
        if !(self.is_serving_fn)() {
            self.enclave.client_discard_message(request.into())?;

            log::info!(
                logger,
                "Ignoring add transaction call, not currently serving requests."
            );
            return Err(ConsensusGrpcError::NotServing);
        }

        let tx_context = self.enclave.client_tx_propose(request.into())?;
        let tx_hash = tx_context.tx_hash;

        match self.tx_manager.insert(tx_context) {
            Ok(tx_hash) => {
                // Submit for consideration in next SCP slot.
                (*self.scp_client_value_sender)(tx_hash, None, None);

                counters::ADD_TX.inc();

                // Return success.
                Ok(ProposeTxResponse::new())
            }

            Err(TxManagerError::TransactionValidation(err)) => {
                // These errors are common, so only trace them
                if err == TransactionValidationError::TombstoneBlockExceeded
                    || err == TransactionValidationError::ContainsSpentKeyImage
                    || err == TransactionValidationError::ContainsExistingOutputPublicKey
                {
                    log::trace!(
                        logger,
                        "Error validating transaction {tx_hash}: {err}",
                        tx_hash = tx_hash.to_string(),
                        err = format!("{:?}", err)
                    );
                } else {
                    log::debug!(
                        logger,
                        "Error validating transaction {tx_hash}: {err}",
                        tx_hash = tx_hash.to_string(),
                        err = format!("{:?}", err)
                    );
                }
                counters::TX_VALIDATION_ERROR_COUNTER.inc(&format!("{:?}", err));
                Err(err.into())
            }

            Err(err) => {
                log::info!(
                    logger,
                    "tx_propose failed for {tx_hash}: {err}",
                    tx_hash = tx_hash.to_string(),
                    err = format!("{:?}", err)
                );
                Err(err.into())
            }
        }
    }
}

impl<L: Ledger + Clone> ConsensusClientApi for ClientApiService<L> {
    fn client_tx_propose(
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
                self.real_client_tx_propose(request, &logger)
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
}

#[cfg(test)]
mod tests {
    use crate::{client_api_service::ClientApiService, tx_manager::MockTxManager};
    use grpcio::{ChannelBuilder, Environment, ServerBuilder};
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
    use mc_transaction_core::tx::TxHash;
    use mc_transaction_core_test_utils::{create_ledger, initialize_ledger, AccountKey};
    use rand::{rngs::StdRng, SeedableRng};
    use std::sync::Arc;

    #[test_with_logger]
    fn test_client_tx_propose_ok(logger: Logger) {
        let mut consensus_enclave = MockConsensusEnclave::new();
        consensus_enclave
            .expect_client_tx_propose()
            .times(1)
            .return_const(Ok(TxContext::default()));

        // Arc<dyn Fn(TxHash, Option<&NodeID>, Option<&ResponderId>) + Sync + Send>
        let scp_client_value_sender = Arc::new(
            |_tx_hash: TxHash, _node_id: Option<&NodeID>, _responder_id: Option<&ResponderId>| {
                // TODO: store inputs for inspection.
            },
        );

        // Local ledger
        // TODO: mock this, because it's only used to get num_blocks.
        let mut ledger = create_ledger();
        let mut rng: StdRng = SeedableRng::from_seed([62u8; 32]);
        let sender = AccountKey::random(&mut rng);
        let num_blocks = 5;
        initialize_ledger(&mut ledger, num_blocks, &sender, &mut rng);

        let mut tx_manager = MockTxManager::new();
        tx_manager
            .expect_insert()
            .times(1)
            .return_const(Ok(TxHash::default()));

        let is_serving_fn = Arc::new(|| -> bool { true });

        let client_api_service = ClientApiService::new(
            Arc::new(consensus_enclave),
            scp_client_value_sender,
            ledger,
            Arc::new(tx_manager),
            is_serving_fn,
            logger,
        );

        let service = consensus_client_grpc::create_consensus_client_api(client_api_service);

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

        let message = Message::default();
        match client.client_tx_propose(&message) {
            Ok(propose_tx_response) => {
                assert_eq!(propose_tx_response.get_result(), ProposeTxResult::Ok);
                assert_eq!(propose_tx_response.get_num_blocks(), num_blocks);
            }
            Err(e) => panic!("unexpected error: {:?}", e),
        }

        // let mut req = HealthCheckRequest::default();
        // req.set_service("not-exist".to_owned());
        // let err = client.check(&req).unwrap_err();
        // match err {
        //     Error::RpcFailure(s) => assert_eq!(s.status, RpcStatusCode::NOT_FOUND),
        //     e => panic!("unexpected error: {:?}", e),
        // }
    }
}
