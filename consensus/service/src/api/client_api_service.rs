// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Serves client-to-node gRPC requests.

use crate::{
    api::grpc_error::ConsensusGrpcError,
    consensus_service::ProposeTxCallback,
    counters,
    mint_tx_manager::MintTxManager,
    tx_manager::{TxManager, TxManagerError},
    SVC_COUNTERS,
};
use grpcio::{RpcContext, RpcStatus, RpcStatusCode, UnarySink};
use mc_attest_api::attest::Message;
use mc_attest_enclave_api::ClientSession;
use mc_common::{
    logger::{log, Logger},
    LruCache,
};
use mc_consensus_api::{
    consensus_client::{ProposeMintConfigTxResponse, ProposeMintTxResponse},
    consensus_client_grpc::ConsensusClientApi,
    consensus_common::ProposeTxResponse,
    consensus_config::{ConsensusNodeConfig, TokenConfig},
    empty::Empty,
};
use mc_consensus_enclave::ConsensusEnclave;
use mc_consensus_service_config::Config;
use mc_ledger_db::Ledger;
use mc_peers::ConsensusValue;
use mc_transaction_core::mint::{MintConfigTx, MintTx};
use mc_util_grpc::{check_request_chain_id, rpc_logger, send_result, Authenticator};
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

/// Maximum number of pending values for consensus service before rejecting
/// add_transaction requests.
const PENDING_LIMIT: i64 = 500;

/// Data retained on a session with a client.
#[derive(Clone, Debug)]
pub struct ClientSessionTracking {
    // This needs to be a VecDeque because popping elements oldest-first (i.e.
    // in a FIFO fashion) needs to be efficient, since we'll be culling the
    // oldest tx failure timestamps constantly - if the server is configured to
    // drop clients with over 100 failed tx proposals in the last 30 seconds,
    // we don't care about timestamps from over 30 seconds ago, for example.
    tx_proposal_failures: VecDeque<Instant>,
}

impl ClientSessionTracking {
    pub fn new() -> Self {
        Self {
            tx_proposal_failures: VecDeque::default(),
        }
    }

    pub fn get_proposetx_failures(&self) -> usize {
        self.tx_proposal_failures.len()
    }

    /// Remove any transaction proposal failure record that is older than our
    /// tracking window.
    fn clear_stale_records(&mut self, now: &Instant, tracking_window: &Duration) {
        self.tx_proposal_failures.retain(|past_failure| {
            now.saturating_duration_since(*past_failure) <= *tracking_window
        });
    }

    /// Push a new failed tx proposal record, clear out samples older than
    /// our tracking window, and return the number of tx failures remaining
    /// on the list - as-in, tells you "there have been x number of failures
    /// within the past `tracking_window` seconds".
    ///
    /// # Arguments
    ///
    /// * `now` - Used as both the instant to record as a new tx proposal
    /// failure, and as the "present" time to check for stale records.
    /// * `tracking_window` - How long of a period of time should we keep track
    /// of an individual tx proposal failure incident for? Any records which
    /// have existed for longer than this value will be dropped when this
    /// method is called.
    pub fn fail_tx_proposal(&mut self, now: &Instant, tracking_window: &Duration) -> usize {
        self.clear_stale_records(now, tracking_window);
        self.tx_proposal_failures.push_back(*now);
        self.tx_proposal_failures.len()
    }
}

#[derive(Clone)]
pub struct ClientApiService {
    config: Config,
    enclave: Arc<dyn ConsensusEnclave + Send + Sync>,
    tx_manager: Arc<dyn TxManager + Send + Sync>,
    mint_tx_manager: Arc<dyn MintTxManager + Send + Sync>,
    ledger: Arc<dyn Ledger + Send + Sync>,
    /// Passes proposed transactions to the consensus service.
    propose_tx_callback: ProposeTxCallback,
    /// Returns true if this node is able to process proposed transactions.
    is_serving_fn: Arc<(dyn Fn() -> bool + Sync + Send)>,
    authenticator: Arc<dyn Authenticator + Send + Sync>,
    logger: Logger,
    /// Information kept regarding sessions between clients and consensus
    /// so that we can drop bad sessions.
    tracked_sessions: Arc<Mutex<LruCache<ClientSession, ClientSessionTracking>>>,
}

impl ClientApiService {
    pub fn new(
        config: Config,
        enclave: Arc<dyn ConsensusEnclave + Send + Sync>,
        scp_client_value_sender: ProposeTxCallback,
        ledger: Arc<dyn Ledger + Send + Sync>,
        tx_manager: Arc<dyn TxManager + Send + Sync>,
        mint_tx_manager: Arc<dyn MintTxManager + Send + Sync>,
        is_serving_fn: Arc<(dyn Fn() -> bool + Sync + Send)>,
        authenticator: Arc<dyn Authenticator + Send + Sync>,
        logger: Logger,
        tracked_sessions: Arc<Mutex<LruCache<ClientSession, ClientSessionTracking>>>,
    ) -> Self {
        Self {
            config,
            enclave,
            tx_manager,
            mint_tx_manager,
            ledger,
            propose_tx_callback: scp_client_value_sender,
            is_serving_fn,
            authenticator,
            logger,
            tracked_sessions,
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

        // Cache the transaction. This performs the well-formedness checks.
        let tx_hash = self.tx_manager.insert(tx_context).map_err(|err| {
            if let TxManagerError::TransactionValidation(cause) = &err {
                counters::TX_VALIDATION_ERROR_COUNTER.inc(&format!("{cause:?}"));
            }
            err
        })?;

        // Validate the transaction.
        // This is done here as a courtesy to give clients immediate feedback about the
        // transaction.
        self.tx_manager.validate(&tx_hash)?;

        // The transaction can be considered by the network.
        (*self.propose_tx_callback)(ConsensusValue::TxHash(tx_hash), None, None);
        counters::ADD_TX.inc();

        let response = ProposeTxResponse::new();
        Ok(response)
    }

    /// Handles a client's proposal for a MintConfigTx to be included in the
    /// ledger.
    ///
    /// # Arguments
    /// `grpc_tx` - The protobuf MintConfigTx being proposed.
    fn handle_propose_mint_config_tx(
        &mut self,
        grpc_tx: mc_consensus_api::external::MintConfigTx,
    ) -> Result<ProposeMintConfigTxResponse, ConsensusGrpcError> {
        counters::PROPOSE_MINT_CONFIG_TX_INITIATED.inc();
        let mint_config_tx = MintConfigTx::try_from(&grpc_tx)
            .map_err(|err| ConsensusGrpcError::InvalidArgument(format!("{err:?}")))?;
        let response = ProposeMintConfigTxResponse::new();

        // Validate the transaction.
        // This is done here as a courtesy to give clients immediate feedback about the
        // transaction.
        self.mint_tx_manager
            .validate_mint_config_tx(&mint_config_tx)?;

        // The transaction can be considered by the network.
        (*self.propose_tx_callback)(ConsensusValue::MintConfigTx(mint_config_tx), None, None);
        counters::PROPOSE_MINT_CONFIG_TX.inc();
        Ok(response)
    }

    /// Handles a client's proposal for a MintTx to be included in the
    /// ledger.
    ///
    /// # Arguments
    /// `grpc_tx` - The protobuf MintTx being proposed.
    fn handle_propose_mint_tx(
        &mut self,
        grpc_tx: mc_consensus_api::external::MintTx,
    ) -> Result<ProposeMintTxResponse, ConsensusGrpcError> {
        counters::PROPOSE_MINT_TX_INITIATED.inc();
        let mint_tx = MintTx::try_from(&grpc_tx)
            .map_err(|err| ConsensusGrpcError::InvalidArgument(format!("{err:?}")))?;
        let response = ProposeMintTxResponse::new();

        // Validate the transaction.
        // This is done here as a courtesy to give clients immediate feedback about the
        // transaction.
        self.mint_tx_manager.validate_mint_tx(&mint_tx)?;

        // The transaction can be considered by the network.
        (*self.propose_tx_callback)(ConsensusValue::MintTx(mint_tx), None, None);
        counters::PROPOSE_MINT_TX.inc();
        Ok(response)
    }

    /// Get the node's configuration.
    fn get_node_config_impl(&self) -> Result<ConsensusNodeConfig, ConsensusGrpcError> {
        let tokens_config = self.config.tokens();

        let token_config_map = tokens_config
            .tokens()
            .iter()
            .map(|token_config| {
                let mut grpc_token_config = TokenConfig::new();
                grpc_token_config.set_token_id(*token_config.token_id());
                grpc_token_config
                    .set_minimum_fee(token_config.minimum_fee_or_default().unwrap_or(0));
                if let Some(governors) = token_config.governors()? {
                    grpc_token_config.set_governors((&governors).into());
                }

                let active_mint_configs = self
                    .ledger
                    .get_active_mint_configs(token_config.token_id())?;
                if let Some(active_mint_configs) = active_mint_configs.as_ref() {
                    grpc_token_config.set_active_mint_configs(active_mint_configs.into());
                }

                Ok((*token_config.token_id(), grpc_token_config))
            })
            .collect::<Result<_, ConsensusGrpcError>>()?;

        let mut response = ConsensusNodeConfig::new();
        response.set_minting_trust_root((&self.enclave.get_minting_trust_root()?).into());
        response.set_token_config_map(token_config_map);
        if let Some(governors_signature) = tokens_config.governors_signature.as_ref() {
            response.set_governors_signature(governors_signature.into());
        }
        response.set_peer_responder_id(self.config.peer_responder_id.to_string());
        response.set_client_responder_id(self.config.client_responder_id.to_string());
        response.set_block_signing_key((&self.enclave.get_signer()?).into());
        response.set_block_version(*self.config.block_version);
        response.set_scp_message_signing_key((&self.config.msg_signer_key.public_key()).into());

        response.set_client_tracking_capacity(self.config.client_tracking_capacity as u64);
        response.set_tx_failure_window_seconds(self.config.tx_failure_window.as_secs());
        response.set_tx_failure_limit(self.config.tx_failure_limit);

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

        let session_id = ClientSession::from(msg.channel_id.clone());

        {
            let mut tracker = self.tracked_sessions.lock().expect("Mutex poisoned");
            // Calling get() on the LRU bumps the entry to show up as more
            // recently-used.
            if tracker.get(&session_id).is_none() {
                tracker.put(session_id.clone(), ClientSessionTracking::new());
            }

            let session_info = tracker
                .get(&session_id)
                .expect("Session should be present after insert");
            let recent_failures = session_info.get_proposetx_failures() as u32;
            if recent_failures >= self.config.tx_failure_limit {
                log::debug!(
                    self.logger,
                    "Client has {} recent failed tx proposals within the \
                    last {} seconds - dropping connection.",
                    recent_failures,
                    self.config.tx_failure_window.as_secs_f32()
                );
                // Rate-limiting is performed at the auth endpoint, so
                // merely dropping the connection will be enough.
                let close_result = self.enclave.client_close(session_id.clone());
                // At the time of writing (30th March, 2023), it should
                // only be possible for client_close() to error if a
                // mutex is poisoned. However, because the
                // implementation of this method might change, it
                // seems wise to handle any error this might throw.
                if let Err(e) = close_result {
                    log::error!(
                        self.logger,
                        "Failed to drop session {:?} due to: {:?}",
                        &session_id,
                        e
                    );
                } else {
                    let _ = tracker.pop(&session_id);
                }

                // Send an error indicating the rate-limiting.
                let rpc_code = RpcStatusCode::RESOURCE_EXHAUSTED;
                let rpc_error = ConsensusGrpcError::RpcStatus(RpcStatus::new(rpc_code));
                let result: Result<_, RpcStatus> = rpc_error.into();

                // Send the error and return early.
                return send_result(ctx, sink, result, &self.logger);
            }
        }

        if let Err(err) = check_request_chain_id(&self.config.chain_id, &ctx) {
            return send_result(ctx, sink, Err(err), &self.logger);
        }

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
                let result = self.handle_proposed_tx(msg);
                // The block present below rate-limits suspicious behavior.
                if let Err(_err) = &result {
                    let mut tracker = self.tracked_sessions.lock().expect("Mutex poisoned");
                    let record = if let Some(record) = tracker.get_mut(&session_id) {
                        record
                    } else {
                        tracker.put(session_id.clone(), ClientSessionTracking::new());
                        tracker
                            .get_mut(&session_id)
                            .expect("Adding session-tracking record should be atomic.")
                    };
                    record.fail_tx_proposal(&Instant::now(), &self.config.tx_failure_window);
                }
                result.or_else(ConsensusGrpcError::into)
            };

        result = result.and_then(|mut response| {
            let num_blocks = self.ledger.num_blocks().map_err(ConsensusGrpcError::from)?;
            response.set_block_count(num_blocks);
            response.set_block_version(*self.config.block_version);
            Ok(response)
        });

        mc_common::logger::scoped_global_logger(&rpc_logger(&ctx, &self.logger), |logger| {
            send_result(ctx, sink, result, logger)
        });
    }

    fn propose_mint_config_tx(
        &mut self,
        ctx: RpcContext,
        grpc_tx: mc_consensus_api::external::MintConfigTx,
        sink: UnarySink<ProposeMintConfigTxResponse>,
    ) {
        let _timer = SVC_COUNTERS.req(&ctx);

        if let Err(err) = check_request_chain_id(&self.config.chain_id, &ctx) {
            return send_result(ctx, sink, Err(err), &self.logger);
        }

        if let Err(err) = self.authenticator.authenticate_rpc(&ctx) {
            return send_result(ctx, sink, err.into(), &self.logger);
        }

        let mut result: Result<ProposeMintConfigTxResponse, RpcStatus> =
            if counters::CUR_NUM_PENDING_VALUES.get() >= PENDING_LIMIT {
                ConsensusGrpcError::OverCapacity.into()
            } else if !(self.is_serving_fn)() {
                ConsensusGrpcError::NotServing.into()
            } else {
                self.handle_propose_mint_config_tx(grpc_tx)
                    .or_else(ConsensusGrpcError::into)
            };

        result = result.and_then(|mut response| {
            let num_blocks = self.ledger.num_blocks().map_err(ConsensusGrpcError::from)?;
            response.set_block_count(num_blocks);
            response.set_block_version(*self.config.block_version);
            Ok(response)
        });

        mc_common::logger::scoped_global_logger(&rpc_logger(&ctx, &self.logger), |logger| {
            send_result(ctx, sink, result, logger)
        });
    }

    fn propose_mint_tx(
        &mut self,
        ctx: RpcContext,
        grpc_tx: mc_consensus_api::external::MintTx,
        sink: UnarySink<ProposeMintTxResponse>,
    ) {
        let _timer = SVC_COUNTERS.req(&ctx);

        if let Err(err) = check_request_chain_id(&self.config.chain_id, &ctx) {
            return send_result(ctx, sink, Err(err), &self.logger);
        }

        if let Err(err) = self.authenticator.authenticate_rpc(&ctx) {
            return send_result(ctx, sink, err.into(), &self.logger);
        }

        let mut result: Result<ProposeMintTxResponse, RpcStatus> =
            if counters::CUR_NUM_PENDING_VALUES.get() >= PENDING_LIMIT {
                ConsensusGrpcError::OverCapacity.into()
            } else if !(self.is_serving_fn)() {
                ConsensusGrpcError::NotServing.into()
            } else {
                self.handle_propose_mint_tx(grpc_tx)
                    .or_else(ConsensusGrpcError::into)
            };

        result = result.and_then(|mut response| {
            let num_blocks = self.ledger.num_blocks().map_err(ConsensusGrpcError::from)?;
            response.set_block_count(num_blocks);
            response.set_block_version(*self.config.block_version);
            Ok(response)
        });

        mc_common::logger::scoped_global_logger(&rpc_logger(&ctx, &self.logger), |logger| {
            send_result(ctx, sink, result, logger)
        });
    }

    fn get_node_config(
        &mut self,
        ctx: RpcContext,
        _empty: Empty,
        sink: UnarySink<ConsensusNodeConfig>,
    ) {
        let result = self.get_node_config_impl().map_err(RpcStatus::from);

        mc_common::logger::scoped_global_logger(&rpc_logger(&ctx, &self.logger), |logger| {
            send_result(ctx, sink, result, logger)
        });
    }
}

#[cfg(test)]
mod client_api_tests {
    use crate::{
        api::client_api_service::{ClientApiService, PENDING_LIMIT},
        counters,
        mint_tx_manager::{MintTxManagerError, MockMintTxManager},
        tx_manager::{MockTxManager, TxManagerError},
    };
    use clap::Parser;
    use grpcio::{
        CallOption, ChannelBuilder, Environment, Error as GrpcError, MetadataBuilder,
        RpcStatusCode, Server, ServerBuilder, ServerCredentials,
    };
    use mc_attest_api::attest::Message;
    use mc_common::{
        logger::{test_with_logger, Logger},
        time::SystemTimeProvider,
        LruCache, NodeID, ResponderId,
    };
    use mc_consensus_api::{
        consensus_client::MintValidationResultCode, consensus_client_grpc,
        consensus_client_grpc::ConsensusClientApiClient, consensus_common::ProposeTxResult,
    };
    use mc_consensus_enclave::{Error as EnclaveError, TxContext};
    use mc_consensus_enclave_mock::MockConsensusEnclave;
    use mc_consensus_service_config::Config;
    use mc_crypto_keys::Ed25519Pair;
    use mc_ledger_db::MockLedger;
    use mc_peers::ConsensusValue;
    use mc_transaction_core::{
        mint::MintValidationError, ring_signature::KeyImage, tx::TxHash,
        validation::TransactionValidationError, TokenId,
    };
    use mc_transaction_core_test_utils::{create_mint_config_tx, create_mint_tx};
    use mc_util_from_random::FromRandom;
    use mc_util_grpc::{
        AnonymousAuthenticator, TokenAuthenticator, CHAIN_ID_GRPC_HEADER, CHAIN_ID_MISMATCH_ERR_MSG,
    };
    use rand_core::SeedableRng;
    use rand_hc::Hc128Rng;
    use serial_test::serial;
    use std::{
        sync::{Arc, Mutex},
        time::Duration,
    };

    /// Starts the service on localhost and connects a client to it.
    fn get_client_server(instance: ClientApiService) -> (ConsensusClientApiClient, Server) {
        let service = consensus_client_grpc::create_consensus_client_api(instance);
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
        let client = ConsensusClientApiClient::new(ch);
        (client, server)
    }

    /// Get a dummy config object
    fn get_config() -> Config {
        Config::try_parse_from([
            "foo",
            "--chain-id=local",
            "--peer-responder-id=localhost:8081",
            "--client-responder-id=localhost:3223",
            "--msg-signer-key=MC4CAQAwBQYDK2VwBCIEIC50QXQll2Y9qxztvmsUgcBBIxkmk7EQjxzQTa926bKo",
            "--network=network.toml",
            "--peer-listen-uri=insecure-mcp://0.0.0.0:8081/",
            "--client-listen-uri=insecure-mc://0.0.0.0:3223/",
            "--admin-listen-uri=insecure-mca://0.0.0.0:9090/",
            "--sealed-block-signing-key=/tmp/key",
            "--ledger-path=/tmp/ledger",
            "--ias-spid=22222222222222222222222222222222",
            "--ias-api-key=asdf",
        ])
        .unwrap()
    }

    // Make a "call option" object which includes appropriate grpc headers
    fn call_option(chain_id: &str) -> CallOption {
        let mut metadata_builder = MetadataBuilder::new();

        // Add the chain id header if we have a chain id specified
        if !chain_id.is_empty() {
            metadata_builder
                .add_str(CHAIN_ID_GRPC_HEADER, chain_id)
                .expect("Could not add chain-id header");
        }

        CallOption::default().headers(metadata_builder.build())
    }

    // A note about `#[serial(counters)]`: some of the tests here rely on
    // manipulating and observing the value of the global prometheus counters.
    // Since the client API calls that are being tested also manipulate them, the
    // tests have to be serialized so that they do not interfere with eachother.

    #[test_with_logger]
    #[serial(counters)]
    fn test_client_tx_propose_ok(logger: Logger) {
        let mut consensus_enclave = MockConsensusEnclave::new();
        {
            // Return a TxContext that contains some KeyImages.
            let tx_context = TxContext {
                key_images: vec![KeyImage::default(), KeyImage::default()],
                ..Default::default()
            };

            consensus_enclave
                .expect_client_tx_propose()
                .times(1)
                .return_const(Ok(tx_context));
        }

        // Arc<dyn Fn(TxHash, Option<&NodeID>, Option<&ResponderId>) + Sync + Send>
        let scp_client_value_sender = Arc::new(
            |_value: ConsensusValue,
             _node_id: Option<&NodeID>,
             _responder_id: Option<&ResponderId>| {
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

        let tracked_sessions = Arc::new(Mutex::new(LruCache::new(4096)));

        let instance = ClientApiService::new(
            get_config(),
            Arc::new(consensus_enclave),
            scp_client_value_sender,
            Arc::new(ledger),
            Arc::new(tx_manager),
            Arc::new(MockMintTxManager::new()),
            is_serving_fn,
            Arc::new(authenticator),
            logger,
            tracked_sessions,
        );

        // gRPC client and server.
        let (client, _server) = get_client_server(instance);
        let message = Message::default();
        match client.client_tx_propose(&message) {
            Ok(propose_tx_response) => {
                assert_eq!(propose_tx_response.get_result(), ProposeTxResult::Ok);
                assert_eq!(propose_tx_response.get_block_count(), num_blocks);
            }
            Err(e) => panic!("Unexpected error: {e:?}"),
        }
    }

    #[test_with_logger]
    #[serial(counters)]
    fn test_client_tx_propose_ok_with_chain_id(logger: Logger) {
        let mut consensus_enclave = MockConsensusEnclave::new();
        {
            // Return a TxContext that contains some KeyImages.
            let tx_context = TxContext {
                key_images: vec![KeyImage::default(), KeyImage::default()],
                ..Default::default()
            };

            consensus_enclave
                .expect_client_tx_propose()
                .times(1)
                .return_const(Ok(tx_context));
        }

        // Arc<dyn Fn(TxHash, Option<&NodeID>, Option<&ResponderId>) + Sync + Send>
        let scp_client_value_sender = Arc::new(
            |_value: ConsensusValue,
             _node_id: Option<&NodeID>,
             _responder_id: Option<&ResponderId>| {
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

        let tracked_sessions = Arc::new(Mutex::new(LruCache::new(4096)));

        let instance = ClientApiService::new(
            get_config(),
            Arc::new(consensus_enclave),
            scp_client_value_sender,
            Arc::new(ledger),
            Arc::new(tx_manager),
            Arc::new(MockMintTxManager::new()),
            is_serving_fn,
            Arc::new(authenticator),
            logger,
            tracked_sessions,
        );

        // gRPC client and server.
        let (client, _server) = get_client_server(instance);
        let message = Message::default();

        // Try with chain id header
        match client.client_tx_propose_opt(&message, call_option("local")) {
            Ok(propose_tx_response) => {
                assert_eq!(propose_tx_response.get_result(), ProposeTxResult::Ok);
                assert_eq!(propose_tx_response.get_block_count(), num_blocks);
            }
            Err(e) => panic!("Unexpected error: {e:?}"),
        }
    }

    #[test_with_logger]
    #[serial(counters)]
    fn test_client_tx_propose_ok_wrong_chain_id(logger: Logger) {
        let consensus_enclave = MockConsensusEnclave::new();

        // Arc<dyn Fn(TxHash, Option<&NodeID>, Option<&ResponderId>) + Sync + Send>
        let scp_client_value_sender = Arc::new(
            |_value: ConsensusValue,
             _node_id: Option<&NodeID>,
             _responder_id: Option<&ResponderId>| {
                // TODO: store inputs for inspection.
            },
        );

        let ledger = MockLedger::new();

        let tx_manager = MockTxManager::new();

        let is_serving_fn = Arc::new(|| -> bool { true });

        let authenticator = AnonymousAuthenticator::default();

        let tracked_sessions = Arc::new(Mutex::new(LruCache::new(4096)));

        let instance = ClientApiService::new(
            get_config(),
            Arc::new(consensus_enclave),
            scp_client_value_sender,
            Arc::new(ledger),
            Arc::new(tx_manager),
            Arc::new(MockMintTxManager::new()),
            is_serving_fn,
            Arc::new(authenticator),
            logger,
            tracked_sessions,
        );

        // gRPC client and server.
        let (client, _server) = get_client_server(instance);
        let message = Message::default();

        // Try with wrong chain id header
        match client.client_tx_propose_opt(&message, call_option("wrong")) {
            Err(grpcio::Error::RpcFailure(status)) => {
                let expected = format!("{} '{}'", CHAIN_ID_MISMATCH_ERR_MSG, "local");
                assert_eq!(status.message(), expected);
            }
            Ok(_) => {
                panic!("Got success, but failure was expected");
            }
            Err(e) => panic!("Unexpected error: {e:?}"),
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
            let tx_context = TxContext {
                key_images: vec![KeyImage::default(), KeyImage::default()],
                ..Default::default()
            };

            consensus_enclave
                .expect_client_tx_propose()
                .times(1)
                .return_const(Ok(tx_context));
        }

        let scp_client_value_sender = Arc::new(
            |_value: ConsensusValue,
             _node_id: Option<&NodeID>,
             _responder_id: Option<&ResponderId>| {},
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

        let tracked_sessions = Arc::new(Mutex::new(LruCache::new(4096)));

        let instance = ClientApiService::new(
            get_config(),
            Arc::new(consensus_enclave),
            scp_client_value_sender,
            Arc::new(ledger),
            Arc::new(tx_manager),
            Arc::new(MockMintTxManager::new()),
            is_serving_fn,
            Arc::new(authenticator),
            logger,
            tracked_sessions,
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
            Err(e) => panic!("Unexpected error: {e:?}"),
        }
    }

    #[test_with_logger]
    #[serial(counters)]
    // Should return ProposeTxResult::FeeMapDigestMismatch if the tx is not
    // well-formed.
    fn test_client_tx_propose_fee_map_mismatched(logger: Logger) {
        let mut consensus_enclave = MockConsensusEnclave::new();

        consensus_enclave
            .expect_client_tx_propose()
            .times(1)
            .return_const(Err(EnclaveError::FeeMapDigestMismatch));

        let scp_client_value_sender = Arc::new(
            |_value: ConsensusValue,
             _node_id: Option<&NodeID>,
             _responder_id: Option<&ResponderId>| {},
        );

        let num_blocks = 5;
        let mut ledger = MockLedger::new();
        // The service should request num_blocks.
        ledger
            .expect_num_blocks()
            .times(1)
            .return_const(Ok(num_blocks));

        let tx_manager = MockTxManager::new();

        let is_serving_fn = Arc::new(|| -> bool { true });

        let authenticator = AnonymousAuthenticator::default();

        let tracked_sessions = Arc::new(Mutex::new(LruCache::new(4096)));

        let instance = ClientApiService::new(
            get_config(),
            Arc::new(consensus_enclave),
            scp_client_value_sender,
            Arc::new(ledger),
            Arc::new(tx_manager),
            Arc::new(MockMintTxManager::new()),
            is_serving_fn,
            Arc::new(authenticator),
            logger,
            tracked_sessions,
        );

        // gRPC client and server.
        let (client, _server) = get_client_server(instance);

        let message = Message::default();
        match client.client_tx_propose(&message) {
            Ok(propose_tx_response) => {
                assert_eq!(
                    propose_tx_response.get_result(),
                    ProposeTxResult::FeeMapDigestMismatch
                );
                assert_eq!(propose_tx_response.get_block_count(), num_blocks);
            }
            Err(e) => panic!("Unexpected error: {e:?}"),
        }
    }

    #[test_with_logger]
    #[serial(counters)]
    // Should return ProposeTxResult::<SomeError> if the tx is not well-formed.
    fn test_client_tx_propose_tx_not_well_formed(logger: Logger) {
        let mut consensus_enclave = MockConsensusEnclave::new();

        // Return a TxContext that contains some KeyImages.
        let tx_context = TxContext {
            key_images: vec![KeyImage::default(), KeyImage::default()],
            ..Default::default()
        };

        consensus_enclave
            .expect_client_tx_propose()
            .times(1)
            .return_const(Ok(tx_context));

        let scp_client_value_sender = Arc::new(
            |_value: ConsensusValue,
             _node_id: Option<&NodeID>,
             _responder_id: Option<&ResponderId>| {},
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

        let tracked_sessions = Arc::new(Mutex::new(LruCache::new(4096)));

        let instance = ClientApiService::new(
            get_config(),
            Arc::new(consensus_enclave),
            scp_client_value_sender,
            Arc::new(ledger),
            Arc::new(tx_manager),
            Arc::new(MockMintTxManager::new()),
            is_serving_fn,
            Arc::new(authenticator),
            logger,
            tracked_sessions,
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
            Err(e) => panic!("Unexpected error: {e:?}"),
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
            |_value: ConsensusValue,
             _node_id: Option<&NodeID>,
             _responder_id: Option<&ResponderId>| {},
        );

        let authenticator = AnonymousAuthenticator::default();

        let tracked_sessions = Arc::new(Mutex::new(LruCache::new(4096)));

        let instance = ClientApiService::new(
            get_config(),
            Arc::new(enclave),
            scp_client_value_sender,
            Arc::new(MockLedger::new()),
            Arc::new(MockTxManager::new()),
            Arc::new(MockMintTxManager::new()),
            is_serving_fn,
            Arc::new(authenticator),
            logger,
            tracked_sessions,
        );

        // gRPC client and server.
        let (client, _server) = get_client_server(instance);

        let message = Message::default();
        match client.client_tx_propose(&message) {
            Ok(propose_tx_response) => {
                panic!("Unexpected response {propose_tx_response:?}");
            }
            Err(GrpcError::RpcFailure(rpc_status)) => {
                assert_eq!(rpc_status.code(), RpcStatusCode::UNAVAILABLE);
            }
            Err(e) => panic!("Unexpected error: {e:?}"),
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
            |_value: ConsensusValue,
             _node_id: Option<&NodeID>,
             _responder_id: Option<&ResponderId>| {},
        );

        let authenticator = AnonymousAuthenticator::default();

        let tracked_sessions = Arc::new(Mutex::new(LruCache::new(4096)));

        let instance = ClientApiService::new(
            get_config(),
            Arc::new(enclave),
            scp_client_value_sender,
            Arc::new(MockLedger::new()),
            Arc::new(MockTxManager::new()),
            Arc::new(MockMintTxManager::new()),
            is_serving_fn,
            Arc::new(authenticator),
            logger,
            tracked_sessions,
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
                panic!("Unexpected response {propose_tx_response:?}");
            }
            Err(GrpcError::RpcFailure(rpc_status)) => {
                assert_eq!(rpc_status.code(), RpcStatusCode::UNAVAILABLE);
            }
            Err(e) => panic!("Unexpected error: {e:?}"),
        }

        // This is a global variable. It affects other unit tests, so must be reset :(
        counters::CUR_NUM_PENDING_VALUES.set(0);
    }

    #[test_with_logger]
    #[serial(counters)]
    fn test_client_tx_propose_rejects_unauthenticated(logger: Logger) {
        let enclave = MockConsensusEnclave::new();

        let is_serving_fn = Arc::new(|| -> bool { true });

        let scp_client_value_sender = Arc::new(
            |_value: ConsensusValue,
             _node_id: Option<&NodeID>,
             _responder_id: Option<&ResponderId>| {},
        );

        let authenticator = TokenAuthenticator::new(
            [1; 32],
            Duration::from_secs(60),
            SystemTimeProvider::default(),
        );

        let tracked_sessions = Arc::new(Mutex::new(LruCache::new(4096)));

        let instance = ClientApiService::new(
            get_config(),
            Arc::new(enclave),
            scp_client_value_sender,
            Arc::new(MockLedger::new()),
            Arc::new(MockTxManager::new()),
            Arc::new(MockMintTxManager::new()),
            is_serving_fn,
            Arc::new(authenticator),
            logger,
            tracked_sessions,
        );

        // gRPC client and server.
        let (client, _server) = get_client_server(instance);

        let message = Message::default();
        match client.client_tx_propose(&message) {
            Ok(response) => {
                panic!("Unexpected response {response:?}");
            }
            Err(GrpcError::RpcFailure(rpc_status)) => {
                assert_eq!(rpc_status.code(), RpcStatusCode::UNAUTHENTICATED);
            }
            Err(err) => {
                panic!("Unexpected error {err:?}");
            }
        };
    }

    #[test_with_logger]
    #[serial(counters)]
    fn test_propose_mint_config_tx_ok(logger: Logger) {
        let mut rng = Hc128Rng::from_seed([1u8; 32]);
        let consensus_enclave = MockConsensusEnclave::new();
        let submitted_values = Arc::new(Mutex::new(Vec::new()));

        let submitted_values2 = submitted_values.clone();
        let scp_client_value_sender = Arc::new(
            move |value: ConsensusValue,
                  _node_id: Option<&NodeID>,
                  _responder_id: Option<&ResponderId>| {
                submitted_values2.lock().unwrap().push(value);
            },
        );

        let num_blocks = 5;
        let mut ledger = MockLedger::new();
        // The service should request num_blocks.
        ledger
            .expect_num_blocks()
            .times(1)
            .return_const(Ok(num_blocks));

        let mut mint_tx_manager = MockMintTxManager::new();
        mint_tx_manager
            .expect_validate_mint_config_tx()
            .times(1)
            .return_const(Ok(()));

        let is_serving_fn = Arc::new(|| -> bool { true });
        let authenticator = AnonymousAuthenticator::default();

        let tracked_sessions = Arc::new(Mutex::new(LruCache::new(4096)));

        let instance = ClientApiService::new(
            get_config(),
            Arc::new(consensus_enclave),
            scp_client_value_sender,
            Arc::new(ledger),
            Arc::new(MockTxManager::new()),
            Arc::new(mint_tx_manager),
            is_serving_fn,
            Arc::new(authenticator),
            logger,
            tracked_sessions,
        );

        // gRPC client and server.
        let (client, _server) = get_client_server(instance);
        let tx = create_mint_config_tx(TokenId::from(5), &mut rng);
        match client.propose_mint_config_tx(&(&tx).into()) {
            Ok(propose_tx_response) => {
                assert_eq!(
                    propose_tx_response.get_result().get_code(),
                    MintValidationResultCode::Ok
                );
                assert_eq!(propose_tx_response.get_block_count(), num_blocks);
            }
            Err(e) => panic!("Unexpected error: {e:?}"),
        }

        assert_eq!(
            *submitted_values.lock().unwrap(),
            vec![ConsensusValue::MintConfigTx(tx)]
        );
    }

    #[test_with_logger]
    #[serial(counters)]
    // Should return NonceAlreadyUsed if the tx contains a nonce that is already
    // used.
    fn test_propose_mint_config_tx_duplicate_nonce(logger: Logger) {
        let mut rng = Hc128Rng::from_seed([1u8; 32]);
        let tx = create_mint_config_tx(TokenId::from(5), &mut rng);
        let consensus_enclave = MockConsensusEnclave::new();
        let submitted_values = Arc::new(Mutex::new(Vec::new()));

        let submitted_values2 = submitted_values.clone();
        let scp_client_value_sender = Arc::new(
            move |value: ConsensusValue,
                  _node_id: Option<&NodeID>,
                  _responder_id: Option<&ResponderId>| {
                submitted_values2.lock().unwrap().push(value);
            },
        );

        let num_blocks = 5;
        let mut ledger = MockLedger::new();
        // The service should request num_blocks.
        ledger
            .expect_num_blocks()
            .times(1)
            .return_const(Ok(num_blocks));

        let mut mint_tx_manager = MockMintTxManager::new();
        mint_tx_manager
            .expect_validate_mint_config_tx()
            .times(1)
            .return_const(Err(MintTxManagerError::MintValidation(
                MintValidationError::NonceAlreadyUsed,
            )));

        let is_serving_fn = Arc::new(|| -> bool { true });
        let authenticator = AnonymousAuthenticator::default();

        let tracked_sessions = Arc::new(Mutex::new(LruCache::new(4096)));

        let instance = ClientApiService::new(
            get_config(),
            Arc::new(consensus_enclave),
            scp_client_value_sender,
            Arc::new(ledger),
            Arc::new(MockTxManager::new()),
            Arc::new(mint_tx_manager),
            is_serving_fn,
            Arc::new(authenticator),
            logger,
            tracked_sessions,
        );

        // gRPC client and server.
        let (client, _server) = get_client_server(instance);
        match client.propose_mint_config_tx(&(&tx).into()) {
            Ok(propose_tx_response) => {
                assert_eq!(
                    propose_tx_response.get_result().get_code(),
                    MintValidationResultCode::NonceAlreadyUsed
                );
                assert_eq!(propose_tx_response.get_block_count(), num_blocks);
            }
            Err(e) => panic!("Unexpected error: {e:?}"),
        }

        assert!(submitted_values.lock().unwrap().is_empty());
    }

    #[test_with_logger]
    #[serial(counters)]
    // Should return RpcStatus Unavailable if the node is not serving.
    fn test_propose_mint_config_tx_not_serving(logger: Logger) {
        let mut rng = Hc128Rng::from_seed([1u8; 32]);
        let tx = create_mint_config_tx(TokenId::from(5), &mut rng);
        let consensus_enclave = MockConsensusEnclave::new();
        let submitted_values = Arc::new(Mutex::new(Vec::new()));

        let submitted_values2 = submitted_values.clone();
        let scp_client_value_sender = Arc::new(
            move |value: ConsensusValue,
                  _node_id: Option<&NodeID>,
                  _responder_id: Option<&ResponderId>| {
                submitted_values2.lock().unwrap().push(value);
            },
        );

        let ledger = MockLedger::new();
        let mint_tx_manager = MockMintTxManager::new();
        let is_serving_fn = Arc::new(|| -> bool { false });
        let authenticator = AnonymousAuthenticator::default();

        let tracked_sessions = Arc::new(Mutex::new(LruCache::new(4096)));

        let instance = ClientApiService::new(
            get_config(),
            Arc::new(consensus_enclave),
            scp_client_value_sender,
            Arc::new(ledger),
            Arc::new(MockTxManager::new()),
            Arc::new(mint_tx_manager),
            is_serving_fn,
            Arc::new(authenticator),
            logger,
            tracked_sessions,
        );

        // gRPC client and server.
        let (client, _server) = get_client_server(instance);
        match client.propose_mint_config_tx(&(&tx).into()) {
            Ok(propose_tx_response) => {
                panic!("Unexpected response {propose_tx_response:?}");
            }
            Err(GrpcError::RpcFailure(rpc_status)) => {
                assert_eq!(rpc_status.code(), RpcStatusCode::UNAVAILABLE);
            }
            Err(e) => panic!("Unexpected error: {e:?}"),
        }

        assert!(submitted_values.lock().unwrap().is_empty());
    }

    #[test_with_logger]
    #[serial(counters)]
    // Should return RpcStatus Unavailable if the node is over capacity.
    // This test modifies a the global variable `counters::CUR_NUM_PENDING_VALUES`,
    // which means it cannot run in parallel with other tests that depend on
    // that value (e.g. all tests in this module).
    fn test_propose_mint_config_tx_over_capacity(logger: Logger) {
        let mut rng = Hc128Rng::from_seed([1u8; 32]);
        let tx = create_mint_config_tx(TokenId::from(5), &mut rng);
        let consensus_enclave = MockConsensusEnclave::new();
        let submitted_values = Arc::new(Mutex::new(Vec::new()));

        let submitted_values2 = submitted_values.clone();
        let scp_client_value_sender = Arc::new(
            move |value: ConsensusValue,
                  _node_id: Option<&NodeID>,
                  _responder_id: Option<&ResponderId>| {
                submitted_values2.lock().unwrap().push(value);
            },
        );

        let ledger = MockLedger::new();
        let mint_tx_manager = MockMintTxManager::new();
        let is_serving_fn = Arc::new(|| -> bool { true });
        let authenticator = AnonymousAuthenticator::default();

        let tracked_sessions = Arc::new(Mutex::new(LruCache::new(4096)));

        let instance = ClientApiService::new(
            get_config(),
            Arc::new(consensus_enclave),
            scp_client_value_sender,
            Arc::new(ledger),
            Arc::new(MockTxManager::new()),
            Arc::new(mint_tx_manager),
            is_serving_fn,
            Arc::new(authenticator),
            logger,
            tracked_sessions,
        );

        // Set the number of pending values to be above the PENDING_LIMIT
        // This is a global variable, and so affects other unit tests. It must be reset
        // afterwards :(
        counters::CUR_NUM_PENDING_VALUES.set(PENDING_LIMIT);

        // gRPC client and server.
        let (client, _server) = get_client_server(instance);
        match client.propose_mint_config_tx(&(&tx).into()) {
            Ok(propose_tx_response) => {
                panic!("Unexpected response {propose_tx_response:?}");
            }
            Err(GrpcError::RpcFailure(rpc_status)) => {
                assert_eq!(rpc_status.code(), RpcStatusCode::UNAVAILABLE);
            }
            Err(e) => panic!("Unexpected error: {e:?}"),
        }

        assert!(submitted_values.lock().unwrap().is_empty());

        // This is a global variable. It affects other unit tests, so must be reset :(
        counters::CUR_NUM_PENDING_VALUES.set(0);
    }

    #[test_with_logger]
    #[serial(counters)]
    fn test_propose_mint_config_tx_unauthenticated(logger: Logger) {
        let mut rng = Hc128Rng::from_seed([1u8; 32]);
        let tx = create_mint_config_tx(TokenId::from(5), &mut rng);
        let consensus_enclave = MockConsensusEnclave::new();
        let submitted_values = Arc::new(Mutex::new(Vec::new()));

        let submitted_values2 = submitted_values.clone();
        let scp_client_value_sender = Arc::new(
            move |value: ConsensusValue,
                  _node_id: Option<&NodeID>,
                  _responder_id: Option<&ResponderId>| {
                submitted_values2.lock().unwrap().push(value);
            },
        );

        let ledger = MockLedger::new();
        let mint_tx_manager = MockMintTxManager::new();
        let is_serving_fn = Arc::new(|| -> bool { true });

        let authenticator = TokenAuthenticator::new(
            [1; 32],
            Duration::from_secs(60),
            SystemTimeProvider::default(),
        );

        let tracked_sessions = Arc::new(Mutex::new(LruCache::new(4096)));

        let instance = ClientApiService::new(
            get_config(),
            Arc::new(consensus_enclave),
            scp_client_value_sender,
            Arc::new(ledger),
            Arc::new(MockTxManager::new()),
            Arc::new(mint_tx_manager),
            is_serving_fn,
            Arc::new(authenticator),
            logger,
            tracked_sessions,
        );

        // gRPC client and server.
        let (client, _server) = get_client_server(instance);
        match client.propose_mint_config_tx(&(&tx).into()) {
            Ok(propose_tx_response) => {
                panic!("Unexpected response {propose_tx_response:?}");
            }
            Err(GrpcError::RpcFailure(rpc_status)) => {
                assert_eq!(rpc_status.code(), RpcStatusCode::UNAUTHENTICATED);
            }
            Err(e) => panic!("Unexpected error: {e:?}"),
        }

        assert!(submitted_values.lock().unwrap().is_empty());
    }

    #[test_with_logger]
    #[serial(counters)]
    fn test_propose_mint_tx_ok(logger: Logger) {
        let mut rng = Hc128Rng::from_seed([1u8; 32]);
        let consensus_enclave = MockConsensusEnclave::new();
        let submitted_values = Arc::new(Mutex::new(Vec::new()));

        let submitted_values2 = submitted_values.clone();
        let scp_client_value_sender = Arc::new(
            move |value: ConsensusValue,
                  _node_id: Option<&NodeID>,
                  _responder_id: Option<&ResponderId>| {
                submitted_values2.lock().unwrap().push(value);
            },
        );

        let num_blocks = 5;
        let mut ledger = MockLedger::new();
        // The service should request num_blocks.
        ledger
            .expect_num_blocks()
            .times(1)
            .return_const(Ok(num_blocks));

        let mut mint_tx_manager = MockMintTxManager::new();
        mint_tx_manager
            .expect_validate_mint_tx()
            .times(1)
            .return_const(Ok(()));

        let is_serving_fn = Arc::new(|| -> bool { true });
        let authenticator = AnonymousAuthenticator::default();

        let tracked_sessions = Arc::new(Mutex::new(LruCache::new(4096)));

        let instance = ClientApiService::new(
            get_config(),
            Arc::new(consensus_enclave),
            scp_client_value_sender,
            Arc::new(ledger),
            Arc::new(MockTxManager::new()),
            Arc::new(mint_tx_manager),
            is_serving_fn,
            Arc::new(authenticator),
            logger,
            tracked_sessions,
        );

        // gRPC client and server.
        let (client, _server) = get_client_server(instance);
        let tx = create_mint_tx(
            TokenId::from(5),
            &[Ed25519Pair::from_random(&mut rng)],
            100,
            &mut rng,
        );
        match client.propose_mint_tx(&(&tx).into()) {
            Ok(propose_tx_response) => {
                assert_eq!(
                    propose_tx_response.get_result().get_code(),
                    MintValidationResultCode::Ok
                );
                assert_eq!(propose_tx_response.get_block_count(), num_blocks);
            }
            Err(e) => panic!("Unexpected error: {e:?}"),
        }

        assert_eq!(
            *submitted_values.lock().unwrap(),
            vec![ConsensusValue::MintTx(tx)]
        );
    }

    #[test_with_logger]
    #[serial(counters)]
    // Should return NonceAlreadyUsed if the tx contains a nonce that is already
    // used.
    fn test_propose_mint_tx_duplicate_nonce(logger: Logger) {
        let mut rng = Hc128Rng::from_seed([1u8; 32]);
        let tx = create_mint_tx(
            TokenId::from(5),
            &[Ed25519Pair::from_random(&mut rng)],
            100,
            &mut rng,
        );
        let consensus_enclave = MockConsensusEnclave::new();
        let submitted_values = Arc::new(Mutex::new(Vec::new()));

        let submitted_values2 = submitted_values.clone();
        let scp_client_value_sender = Arc::new(
            move |value: ConsensusValue,
                  _node_id: Option<&NodeID>,
                  _responder_id: Option<&ResponderId>| {
                submitted_values2.lock().unwrap().push(value);
            },
        );

        let num_blocks = 5;
        let mut ledger = MockLedger::new();
        // The service should request num_blocks.
        ledger
            .expect_num_blocks()
            .times(1)
            .return_const(Ok(num_blocks));

        let mut mint_tx_manager = MockMintTxManager::new();
        mint_tx_manager
            .expect_validate_mint_tx()
            .times(1)
            .return_const(Err(MintTxManagerError::MintValidation(
                MintValidationError::NonceAlreadyUsed,
            )));

        let is_serving_fn = Arc::new(|| -> bool { true });
        let authenticator = AnonymousAuthenticator::default();

        let tracked_sessions = Arc::new(Mutex::new(LruCache::new(4096)));

        let instance = ClientApiService::new(
            get_config(),
            Arc::new(consensus_enclave),
            scp_client_value_sender,
            Arc::new(ledger),
            Arc::new(MockTxManager::new()),
            Arc::new(mint_tx_manager),
            is_serving_fn,
            Arc::new(authenticator),
            logger,
            tracked_sessions,
        );

        // gRPC client and server.
        let (client, _server) = get_client_server(instance);
        match client.propose_mint_tx(&(&tx).into()) {
            Ok(propose_tx_response) => {
                assert_eq!(
                    propose_tx_response.get_result().get_code(),
                    MintValidationResultCode::NonceAlreadyUsed
                );
                assert_eq!(propose_tx_response.get_block_count(), num_blocks);
            }
            Err(e) => panic!("Unexpected error: {e:?}"),
        }

        assert!(submitted_values.lock().unwrap().is_empty());
    }

    #[test_with_logger]
    #[serial(counters)]
    // Should return RpcStatus Unavailable if the node is not serving.
    fn test_propose_mint_tx_not_serving(logger: Logger) {
        let mut rng = Hc128Rng::from_seed([1u8; 32]);
        let tx = create_mint_tx(
            TokenId::from(5),
            &[Ed25519Pair::from_random(&mut rng)],
            100,
            &mut rng,
        );
        let consensus_enclave = MockConsensusEnclave::new();
        let submitted_values = Arc::new(Mutex::new(Vec::new()));

        let submitted_values2 = submitted_values.clone();
        let scp_client_value_sender = Arc::new(
            move |value: ConsensusValue,
                  _node_id: Option<&NodeID>,
                  _responder_id: Option<&ResponderId>| {
                submitted_values2.lock().unwrap().push(value);
            },
        );

        let ledger = MockLedger::new();
        let mint_tx_manager = MockMintTxManager::new();
        let is_serving_fn = Arc::new(|| -> bool { false });
        let authenticator = AnonymousAuthenticator::default();

        let tracked_sessions = Arc::new(Mutex::new(LruCache::new(4096)));

        let instance = ClientApiService::new(
            get_config(),
            Arc::new(consensus_enclave),
            scp_client_value_sender,
            Arc::new(ledger),
            Arc::new(MockTxManager::new()),
            Arc::new(mint_tx_manager),
            is_serving_fn,
            Arc::new(authenticator),
            logger,
            tracked_sessions,
        );

        // gRPC client and server.
        let (client, _server) = get_client_server(instance);
        match client.propose_mint_tx(&(&tx).into()) {
            Ok(propose_tx_response) => {
                panic!("Unexpected response {propose_tx_response:?}");
            }
            Err(GrpcError::RpcFailure(rpc_status)) => {
                assert_eq!(rpc_status.code(), RpcStatusCode::UNAVAILABLE);
            }
            Err(e) => panic!("Unexpected error: {e:?}"),
        }

        assert!(submitted_values.lock().unwrap().is_empty());
    }

    #[test_with_logger]
    #[serial(counters)]
    // Should return RpcStatus Unavailable if the node is over capacity.
    // This test modifies a the global variable `counters::CUR_NUM_PENDING_VALUES`,
    // which means it cannot run in parallel with other tests that depend on
    // that value (e.g. all tests in this module).
    fn test_propose_mint_tx_over_capacity(logger: Logger) {
        let mut rng = Hc128Rng::from_seed([1u8; 32]);
        let tx = create_mint_tx(
            TokenId::from(5),
            &[Ed25519Pair::from_random(&mut rng)],
            100,
            &mut rng,
        );
        let consensus_enclave = MockConsensusEnclave::new();
        let submitted_values = Arc::new(Mutex::new(Vec::new()));

        let submitted_values2 = submitted_values.clone();
        let scp_client_value_sender = Arc::new(
            move |value: ConsensusValue,
                  _node_id: Option<&NodeID>,
                  _responder_id: Option<&ResponderId>| {
                submitted_values2.lock().unwrap().push(value);
            },
        );

        let ledger = MockLedger::new();
        let mint_tx_manager = MockMintTxManager::new();
        let is_serving_fn = Arc::new(|| -> bool { true });
        let authenticator = AnonymousAuthenticator::default();

        let tracked_sessions = Arc::new(Mutex::new(LruCache::new(4096)));

        let instance = ClientApiService::new(
            get_config(),
            Arc::new(consensus_enclave),
            scp_client_value_sender,
            Arc::new(ledger),
            Arc::new(MockTxManager::new()),
            Arc::new(mint_tx_manager),
            is_serving_fn,
            Arc::new(authenticator),
            logger,
            tracked_sessions,
        );

        // Set the number of pending values to be above the PENDING_LIMIT
        // This is a global variable, and so affects other unit tests. It must be reset
        // afterwards :(
        counters::CUR_NUM_PENDING_VALUES.set(PENDING_LIMIT);

        // gRPC client and server.
        let (client, _server) = get_client_server(instance);
        match client.propose_mint_tx(&(&tx).into()) {
            Ok(propose_tx_response) => {
                panic!("Unexpected response {propose_tx_response:?}");
            }
            Err(GrpcError::RpcFailure(rpc_status)) => {
                assert_eq!(rpc_status.code(), RpcStatusCode::UNAVAILABLE);
            }
            Err(e) => panic!("Unexpected error: {e:?}"),
        }

        assert!(submitted_values.lock().unwrap().is_empty());

        // This is a global variable. It affects other unit tests, so must be reset :(
        counters::CUR_NUM_PENDING_VALUES.set(0);
    }

    #[test_with_logger]
    #[serial(counters)]
    fn test_propose_mint_tx_unauthenticated(logger: Logger) {
        let mut rng = Hc128Rng::from_seed([1u8; 32]);
        let tx = create_mint_tx(
            TokenId::from(5),
            &[Ed25519Pair::from_random(&mut rng)],
            100,
            &mut rng,
        );
        let consensus_enclave = MockConsensusEnclave::new();
        let submitted_values = Arc::new(Mutex::new(Vec::new()));

        let submitted_values2 = submitted_values.clone();
        let scp_client_value_sender = Arc::new(
            move |value: ConsensusValue,
                  _node_id: Option<&NodeID>,
                  _responder_id: Option<&ResponderId>| {
                submitted_values2.lock().unwrap().push(value);
            },
        );

        let ledger = MockLedger::new();
        let mint_tx_manager = MockMintTxManager::new();
        let is_serving_fn = Arc::new(|| -> bool { true });

        let authenticator = TokenAuthenticator::new(
            [1; 32],
            Duration::from_secs(60),
            SystemTimeProvider::default(),
        );

        let tracked_sessions = Arc::new(Mutex::new(LruCache::new(4096)));

        let instance = ClientApiService::new(
            get_config(),
            Arc::new(consensus_enclave),
            scp_client_value_sender,
            Arc::new(ledger),
            Arc::new(MockTxManager::new()),
            Arc::new(mint_tx_manager),
            is_serving_fn,
            Arc::new(authenticator),
            logger,
            tracked_sessions,
        );

        // gRPC client and server.
        let (client, _server) = get_client_server(instance);
        match client.propose_mint_tx(&(&tx).into()) {
            Ok(propose_tx_response) => {
                panic!("Unexpected response {propose_tx_response:?}");
            }
            Err(GrpcError::RpcFailure(rpc_status)) => {
                assert_eq!(rpc_status.code(), RpcStatusCode::UNAUTHENTICATED);
            }
            Err(e) => panic!("Unexpected error: {e:?}"),
        }

        assert!(submitted_values.lock().unwrap().is_empty());
    }

    // Very simple test of the session-tracking feature
    #[test_with_logger]
    #[serial(counters)]
    fn test_session_tracking_gets_populated(logger: Logger) {
        let mut consensus_enclave = MockConsensusEnclave::new();
        {
            // Return a TxContext that contains some KeyImages.
            let tx_context = TxContext {
                key_images: vec![KeyImage::default(), KeyImage::default()],
                ..Default::default()
            };

            consensus_enclave
                .expect_client_tx_propose()
                .times(1)
                .return_const(Ok(tx_context));
        }

        let scp_client_value_sender = Arc::new(
            |_value: ConsensusValue,
             _node_id: Option<&NodeID>,
             _responder_id: Option<&ResponderId>| {
                // TODO: store inputs for inspection.
            },
        );

        const NUM_BLOCKS: u64 = 5;
        let mut ledger = MockLedger::new();
        ledger
            .expect_num_blocks()
            .times(1)
            .return_const(Ok(NUM_BLOCKS));

        let mut tx_manager = MockTxManager::new();
        tx_manager
            .expect_insert()
            .times(1)
            .return_const(Ok(TxHash::default()));
        tx_manager.expect_validate().times(1).return_const(Ok(()));

        let is_serving_fn = Arc::new(|| -> bool { true });

        let authenticator = AnonymousAuthenticator::default();

        const LRU_CAPACITY: usize = 4096;
        let tracked_sessions = Arc::new(Mutex::new(LruCache::new(LRU_CAPACITY)));

        let instance = ClientApiService::new(
            get_config(),
            Arc::new(consensus_enclave),
            scp_client_value_sender,
            Arc::new(ledger),
            Arc::new(tx_manager),
            Arc::new(MockMintTxManager::new()),
            is_serving_fn,
            Arc::new(authenticator),
            logger,
            // Clone this, maintaining our own Arc reference into the tracked
            // sessions structure so that we can inspect it later.
            tracked_sessions.clone(),
        );

        // gRPC client and server.
        let (client, _server) = get_client_server(instance);
        let message = Message::default();
        {
            // Make sure there are no tracked sessions right up until we
            // actually propose a tx.
            let tracker = tracked_sessions
                .lock()
                .expect("Attempt to lock session-tracking mutex failed.");
            assert!(tracker.is_empty());
        }

        let propose_tx_response = client
            .client_tx_propose(&message)
            .expect("Client tx propose error");
        assert_eq!(propose_tx_response.get_result(), ProposeTxResult::Ok);
        assert_eq!(propose_tx_response.get_block_count(), NUM_BLOCKS);

        let tracker = tracked_sessions
            .lock()
            .expect("Attempt to lock session-tracking mutex failed.");
        assert_eq!(tracker.len(), 1);
    }

    #[test_with_logger]
    #[serial(counters)]
    fn test_get_kicked_failure_limit(logger: Logger) {
        let limit = 3;

        let mut consensus_enclave = MockConsensusEnclave::new();

        let scp_client_value_sender = Arc::new(
            |_value: ConsensusValue,
             _node_id: Option<&NodeID>,
             _responder_id: Option<&ResponderId>| {
                // TODO: store inputs for inspection.
            },
        );

        const NUM_BLOCKS: u64 = 5;
        let mut ledger = MockLedger::new();
        ledger
            .expect_num_blocks()
            .times(limit as usize)
            .return_const(Ok(NUM_BLOCKS));

        let tx_manager = MockTxManager::new();
        let is_serving_fn = Arc::new(|| -> bool { true });
        let authenticator = AnonymousAuthenticator::default();

        const LRU_CAPACITY: usize = 4096;
        let tracked_sessions = Arc::new(Mutex::new(LruCache::new(LRU_CAPACITY)));

        let mut config = get_config();
        // Permit only 3 failed transactions
        config.tx_failure_limit = limit;

        // Cause the mock enclave to consistently fail each request.
        consensus_enclave
            .expect_client_tx_propose()
            .times(limit as usize)
            .return_const(Err(EnclaveError::MalformedTx(
                TransactionValidationError::ContainsSpentKeyImage,
            )));
        // Expect a close, since this will be exceeding our limit
        consensus_enclave
            .expect_client_close()
            .times(1)
            .return_const(Ok(()));

        let instance = ClientApiService::new(
            config,
            Arc::new(consensus_enclave),
            scp_client_value_sender,
            Arc::new(ledger),
            Arc::new(tx_manager),
            Arc::new(MockMintTxManager::new()),
            is_serving_fn,
            Arc::new(authenticator),
            logger,
            // Clone this, maintaining our own Arc reference into the tracked
            // sessions structure so that we can inspect it later.
            tracked_sessions.clone(),
        );

        // gRPC client and server.
        let (client, _server) = get_client_server(instance);
        let message = Message::default();

        for _ in 0..limit {
            let propose_tx_response = client
                .client_tx_propose(&message)
                .expect("Client tx propose error");
            assert_eq!(
                propose_tx_response.get_result(),
                ProposeTxResult::ContainsSpentKeyImage
            );
        }
        // No failed transaction proposals over the limit yet, so the session
        // shouldn't have been dropped
        {
            let tracker = tracked_sessions
                .lock()
                .expect("Attempt to lock session-tracking mutex failed.");
            assert_eq!(tracker.len(), 1);
            let (_session_id, tracking_data) = tracker.iter().next().unwrap();
            assert_eq!(tracking_data.tx_proposal_failures.len(), limit as usize);
        }

        let propose_tx_response = client.client_tx_propose(&message);
        assert!(propose_tx_response.is_err());

        match propose_tx_response {
            Err(grpcio::Error::RpcFailure(rpc_status)) => {
                assert_eq!(rpc_status.code(), RpcStatusCode::RESOURCE_EXHAUSTED);
            }
            _ => panic!(
                "Unexpected response upon continuing to use\
                        a rate-limited session: {propose_tx_response:?}"
            ),
        }

        let tracker = tracked_sessions
            .lock()
            .expect("Attempt to lock session-tracking mutex failed.");
        // This session should have been dropped at this point.
        assert_eq!(tracker.len(), 0);

        // Because of the behavior of Mockall, if this returns without calling
        // client_close() exactly once, it will panic and the test will fail.
    }
}
