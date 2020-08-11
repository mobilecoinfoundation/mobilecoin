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
use mc_consensus_enclave::ConsensusEnclaveProxy;
use mc_ledger_db::Ledger;
use mc_transaction_core::validation::TransactionValidationError;
use mc_util_grpc::{rpc_logger, send_result};
use mc_util_metrics::{self, SVC_COUNTERS};
use std::sync::Arc;

/// Maximum number of pending values for consensus service before rejecting add_transaction requests.
const PENDING_LIMIT: i64 = 500;

#[derive(Clone)]
pub struct ClientApiService<E: ConsensusEnclaveProxy, L: Ledger + Clone> {
    enclave: E,
    scp_client_value_sender: ProposeTxCallback,
    ledger: L,
    tx_manager: TxManager<E, L>,
    is_serving_fn: Arc<(dyn Fn() -> bool + Sync + Send)>,
    logger: Logger,
}

impl<E: ConsensusEnclaveProxy, L: Ledger + Clone> ClientApiService<E, L> {
    pub fn new(
        enclave: E,
        scp_client_value_sender: ProposeTxCallback,
        ledger: L,
        tx_manager: TxManager<E, L>,
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

        match self.tx_manager.insert_proposed_tx(tx_context) {
            Ok(tx_context) => {
                // Submit for consideration in next SCP slot.
                (*self.scp_client_value_sender)(*tx_context.tx_hash(), None, None);

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

impl<E: ConsensusEnclaveProxy, L: Ledger + Clone> ConsensusClientApi for ClientApiService<E, L> {
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
