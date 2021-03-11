// Copyright (c) 2018-2021 The MobileCoin Foundation

//! The MobileCoin consensus service.

use crate::{
    api::{AttestedApiService, BlockchainApiService, ClientApiService, PeerApiService},
    background_work_queue::BackgroundWorkQueue,
    byzantine_ledger::ByzantineLedger,
    config::{Config, NetworkConfig},
    counters,
    peer_keepalive::PeerKeepalive,
    tx_manager::TxManager,
};
use base64::{encode_config, URL_SAFE};
use displaydoc::Display;
use futures::executor::block_on;
use grpcio::{EnvBuilder, Environment, RpcStatus, RpcStatusCode, Server, ServerBuilder};
use mc_attest_api::attest_grpc::create_attested_api;
use mc_attest_enclave_api::{ClientSession, PeerSession};
use mc_attest_net::RaClient;
use mc_common::{
    logger::{log, Logger},
    time::TimeProvider,
    NodeID, ResponderId,
};
use mc_connection::{Connection, ConnectionManager};
use mc_consensus_api::{consensus_client_grpc, consensus_common_grpc, consensus_peer_grpc};
use mc_consensus_enclave::ConsensusEnclave;
use mc_crypto_keys::DistinguishedEncoding;
use mc_ledger_db::{Error as LedgerDbError, Ledger, LedgerDB};
use mc_peers::{PeerConnection, ThreadedBroadcaster, VerifiedConsensusMsg};
use mc_sgx_report_cache_untrusted::{Error as ReportCacheError, ReportCacheThread};
use mc_transaction_core::{tx::TxHash, Block, BlockSignature};
use mc_util_grpc::{
    AdminServer, AnonymousAuthenticator, Authenticator, BuildInfoService,
    ConnectionUriGrpcioServer, GetConfigJsonFn, HealthCheckStatus, HealthService,
    TokenAuthenticator,
};
use mc_util_uri::{ConnectionUri, ConsensusPeerUriApi};
use once_cell::sync::OnceCell;
use serde_json::json;
use std::{
    env,
    sync::{Arc, Mutex, Weak},
    time::Instant,
};

/// Crate version, used for admin info endpoint
const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Display)]
pub enum ConsensusServiceError {
    /// Failed to join thread: `{0}`
    ThreadJoin(String),
    /// RPC shutdown failure: `{0}`
    RpcShutdown(String),
    /// Failed to start background work queue: `{0}`
    BackgroundWorkQueueStart(String),
    /// Failed to stop background work queue: `{0}`
    BackgroundWorkQueueStop(String),
    /// Report cache error: `{0}`
    ReportCache(ReportCacheError),
}
impl From<ReportCacheError> for ConsensusServiceError {
    fn from(src: ReportCacheError) -> Self {
        ConsensusServiceError::ReportCache(src)
    }
}

/// A consensus message relayed by the broadcast layer. In addition to the consensus message
/// itself, it includes the node ID the message was received from. Note that this could be
/// different from the node ID that initiated the message due to relaying.
pub struct IncomingConsensusMsg {
    /// The broadcast-layer sender.
    pub from_responder_id: ResponderId,

    /// The message we received from the network.
    pub consensus_msg: VerifiedConsensusMsg,
}

/// A callback for broadcasting a new transaction to peers and feeding it into ByztantineLedger.
/// It receives 3 arguments:
/// - TxHash of the the TX that was received
/// - The NodeID the transaction was originally submitted to
///   (will be None for values submitted by clients and not relayed by other nodes)
/// - The NodeID that notified us about this transaction.
///   (will be None for values submitted by clients and not relayed by other nodes)
pub type ProposeTxCallback =
    Arc<dyn Fn(TxHash, Option<&NodeID>, Option<&ResponderId>) + Sync + Send>;

pub struct ConsensusService<
    E: ConsensusEnclave + Clone + Send + Sync + 'static,
    R: RaClient + Send + Sync + 'static,
    TXM: TxManager + Clone + Send + Sync + 'static,
> {
    config: Config,
    local_node_id: NodeID,
    enclave: E,
    ledger_db: LedgerDB,
    env: Arc<Environment>,
    ra_client: R,
    logger: Logger,

    report_cache_thread: Option<ReportCacheThread>,

    consensus_msgs_from_network: BackgroundWorkQueue<IncomingConsensusMsg>,

    peer_manager: ConnectionManager<PeerConnection<E>>,
    // This mutex is required because ThreadedBroadcaster API cannot be used concurrently,
    // the LRU cache requires exclusive access, among other reasons.
    // The contention for this is (at time of writing), (one) ByzantineLedger worker thread,
    // and the client and peer api services, via the ProposeTxCallback
    broadcaster: Arc<Mutex<ThreadedBroadcaster>>,
    tx_manager: Arc<TXM>,
    // Option is only here because we need a way to drop the PeerKeepalive without mutex,
    // if we want to implement Stop as currently concieved
    peer_keepalive: Option<Arc<PeerKeepalive>>,
    // GRPC client requests authenticator
    client_authenticator: Arc<dyn Authenticator + Send + Sync>,

    admin_rpc_server: Option<AdminServer>,
    consensus_rpc_server: Option<Server>,
    user_rpc_server: Option<Server>,
    // Option is only here because we need a way to drop the ByzantineLedger without mutex,
    // if we want to implement Stop as currently conceived.
    byzantine_ledger: Option<Arc<OnceCell<ByzantineLedger>>>,
}

impl<
        E: ConsensusEnclave + Clone + Send + Sync + 'static,
        R: RaClient + Send + Sync + 'static,
        TXM: TxManager + Clone + Send + Sync + 'static,
    > ConsensusService<E, R, TXM>
{
    /// Creates a new ConsensusService.
    ///
    /// # Arguments
    /// * `config` - Service configurations.
    /// * `enclave` - Consensus enclave.
    /// * `ledger_db` - Ledger.
    /// * `ra_client` - Remote attestation client.
    /// * `tx_manager` - TransactionManager.
    /// * `time_provider` - TimeProvider for client Authenticator.
    /// * `logger`
    pub fn new<TP: TimeProvider + 'static>(
        config: Config,
        enclave: E,
        ledger_db: LedgerDB,
        ra_client: R,
        tx_manager: Arc<TXM>,
        time_provider: Arc<TP>,
        logger: Logger,
    ) -> Self {
        // gRPC environment.
        let env = Arc::new(
            EnvBuilder::new()
                .name_prefix("Main-RPC".to_string())
                .build(),
        );

        // Consensus messages from network
        let consensus_msgs_from_network =
            BackgroundWorkQueue::new(&counters::CONSENSUS_MSGS_FROM_NETWORK_QUEUE_SIZE);

        let local_node_id = config.node_id();

        // Peers
        let peers: Vec<PeerConnection<E>> = config
            .network()
            .broadcast_peers()
            .into_iter()
            .map(|peer_uri| {
                PeerConnection::new(
                    enclave.clone(),
                    local_node_id.clone(),
                    peer_uri,
                    env.clone(),
                    logger.clone(),
                )
            })
            .collect();

        let peer_manager = ConnectionManager::new(peers, logger.clone());

        // Broadcaster
        let broadcaster = Arc::new(Mutex::new(ThreadedBroadcaster::new(
            &peer_manager,
            &mc_peers::ThreadedBroadcasterFibonacciRetryPolicy::default(),
            logger.clone(),
        )));

        // Peer Keepalive
        let peer_keepalive = Some(Arc::new(PeerKeepalive::start(
            peer_manager.clone(),
            consensus_msgs_from_network.get_sender_fn(),
            logger.clone(),
        )));

        // Authenticator
        let client_authenticator: Arc<dyn Authenticator + Sync + Send> =
            if let Some(shared_secret) = config.client_auth_token_secret.as_ref() {
                Arc::new(TokenAuthenticator::new(
                    *shared_secret,
                    config.client_auth_token_max_lifetime,
                    time_provider,
                ))
            } else {
                Arc::new(AnonymousAuthenticator::default())
            };

        // Return
        Self {
            config,
            local_node_id,
            enclave,
            ledger_db,
            env,
            ra_client,
            logger,

            report_cache_thread: None,

            consensus_msgs_from_network,

            peer_manager,
            broadcaster,
            tx_manager,
            peer_keepalive,
            client_authenticator,

            admin_rpc_server: None,
            consensus_rpc_server: None,
            user_rpc_server: None,
            byzantine_ledger: Some(Arc::new(Default::default())),
        }
    }

    pub fn config(&self) -> Config {
        self.config.clone()
    }

    pub fn start(&mut self) -> Result<(), ConsensusServiceError> {
        let ret = {
            self.report_cache_thread = Some(ReportCacheThread::start(
                self.enclave.clone(),
                self.ra_client.clone(),
                self.config.ias_spid,
                &counters::ENCLAVE_REPORT_TIMESTAMP,
                self.logger.clone(),
            )?);
            self.start_admin_rpc_server()?;
            self.start_consensus_rpc_server()?;
            self.start_user_rpc_server()?;
            self.start_byzantine_ledger_service()?;

            // Success.
            Ok(())
        };
        if ret.is_err() {
            let _ = self.stop();
        }
        ret
    }

    pub fn stop(&mut self) -> Result<(), ConsensusServiceError> {
        log::debug!(self.logger, "Attempting to stop node...");

        // This will join the peer_keepalive in drop if we are the last thread holding it
        self.peer_keepalive = None;

        if let Some(ref mut server) = self.user_rpc_server.take() {
            block_on(server.shutdown())
                .map_err(|_| ConsensusServiceError::RpcShutdown("user_rpc_server".to_string()))?
        }

        if let Some(ref mut server) = self.consensus_rpc_server.take() {
            block_on(server.shutdown()).map_err(|_| {
                ConsensusServiceError::RpcShutdown("consensus_rpc_server".to_string())
            })?
        }

        if let Some(ref mut server) = self.admin_rpc_server.take() {
            block_on(server.shutdown())
                .map_err(|_| ConsensusServiceError::RpcShutdown("admin_rpc_server".to_string()))?
        }

        self.consensus_msgs_from_network.stop().map_err(|e| {
            ConsensusServiceError::BackgroundWorkQueueStop(format!(
                "consensus_msgs_from_network: {:?}",
                e
            ))
        })?;

        // This will join the byzantine ledger in drop if we are the last thread holding it
        self.byzantine_ledger = None;

        if let Some(ref mut report_cache_thread) = self.report_cache_thread.take() {
            report_cache_thread.stop()?;
        }

        Ok(())
    }

    #[allow(dead_code)]
    pub fn wait_for_all_threads(&mut self) -> Result<(), ConsensusServiceError> {
        log::debug!(
            self.logger,
            "Waiting for consensus_msgs_from_network_receiver_thread..."
        );
        self.consensus_msgs_from_network.join().map_err(|_| {
            ConsensusServiceError::ThreadJoin("consensus_msgs_from_network".to_string())
        })?;
        Ok(())
    }

    fn start_user_rpc_server(&mut self) -> Result<(), ConsensusServiceError> {
        log::info!(
            self.logger,
            "Starting user rpc server on {}...",
            self.config.client_listen_uri.addr(),
        );

        // Setup GRPC services.
        let enclave = Arc::new(self.enclave.clone());

        let client_service =
            consensus_client_grpc::create_consensus_client_api(ClientApiService::new(
                enclave.clone(),
                self.create_scp_client_value_sender_fn(),
                Arc::new(self.ledger_db.clone()),
                self.tx_manager.clone(),
                self.create_is_serving_user_requests_fn(),
                self.client_authenticator.clone(),
                self.logger.clone(),
            ));

        let attested_service = create_attested_api(AttestedApiService::<ClientSession>::new(
            enclave,
            self.client_authenticator.clone(),
            self.logger.clone(),
        ));

        let blockchain_service =
            consensus_common_grpc::create_blockchain_api(BlockchainApiService::new(
                self.ledger_db.clone(),
                self.client_authenticator.clone(),
                self.logger.clone(),
            ));

        let is_serving_user_requests = self.create_is_serving_user_requests_fn();
        let health_check_callback: Arc<dyn Fn(&str) -> HealthCheckStatus + Sync + Send> =
            Arc::new(move |_| {
                if is_serving_user_requests() {
                    HealthCheckStatus::SERVING
                } else {
                    HealthCheckStatus::NOT_SERVING
                }
            });
        let health_service =
            HealthService::new(Some(health_check_callback), self.logger.clone()).into_service();
        let build_info_service = BuildInfoService::new(self.logger.clone()).into_service();

        // Start GRPC server.
        let env = Arc::new(
            EnvBuilder::new()
                .cq_count(1)
                .name_prefix("User-RPC".to_string())
                .build(),
        );

        let server_builder = ServerBuilder::new(env)
            .register_service(client_service)
            .register_service(blockchain_service)
            .register_service(health_service)
            .register_service(attested_service)
            .register_service(build_info_service)
            .bind_using_uri(&self.config.client_listen_uri, self.logger.clone());

        let mut server = server_builder.build().unwrap();
        server.start();

        for (host, port) in server.bind_addrs() {
            log::info!(self.logger, "Peer GRPC API listening on {}:{}", host, port);
        }

        self.user_rpc_server = Some(server);

        // Success.
        Ok(())
    }

    fn start_admin_rpc_server(&mut self) -> Result<(), ConsensusServiceError> {
        if let Some(admin_listen_uri) = self.config.admin_listen_uri.as_ref() {
            self.admin_rpc_server = Some(
                AdminServer::start(
                    Some(self.env.clone()),
                    admin_listen_uri,
                    "Consensus Service".to_owned(),
                    self.config.peer_responder_id.to_string(),
                    Some(self.create_get_config_json_fn()),
                    self.logger.clone(),
                )
                .expect("Failed starting admin grpc server"),
            );
        }

        Ok(())
    }

    fn start_consensus_rpc_server(&mut self) -> Result<(), ConsensusServiceError> {
        log::info!(
            self.logger,
            "Starting consensus rpc server on {}...",
            self.config.peer_listen_uri.addr(),
        );

        // Peers currently do not support request authentication.
        let peer_authenticator = Arc::new(AnonymousAuthenticator::default());

        // Initialize services.
        let enclave = Arc::new(self.enclave.clone());

        let byzantine_ledger = Arc::downgrade(
            self.byzantine_ledger
                .as_ref()
                .expect("Server was not initialized"),
        );
        let get_highest_scp_message_fn = Arc::new(move || {
            byzantine_ledger.upgrade().and_then(|ledger| {
                ledger
                    .get()
                    .and_then(|ledger| ledger.get_highest_issued_message())
            })
        });

        let blockchain_service =
            consensus_common_grpc::create_blockchain_api(BlockchainApiService::new(
                self.ledger_db.clone(),
                peer_authenticator.clone(),
                self.logger.clone(),
            ));

        let peer_service = consensus_peer_grpc::create_consensus_peer_api(PeerApiService::new(
            Arc::new(self.enclave.clone()),
            Arc::new(self.ledger_db.clone()),
            self.tx_manager.clone(),
            self.consensus_msgs_from_network.get_sender_fn(),
            self.create_scp_client_value_sender_fn(),
            get_highest_scp_message_fn,
            self.peer_manager.responder_ids(),
            self.logger.clone(),
        ));

        let attested_service = create_attested_api(AttestedApiService::<PeerSession>::new(
            enclave,
            peer_authenticator,
            self.logger.clone(),
        ));

        let health_service = HealthService::new(None, self.logger.clone()).into_service();
        let build_info_service = BuildInfoService::new(self.logger.clone()).into_service();

        // Start GRPC server.
        let server_builder = ServerBuilder::new(self.env.clone())
            .register_service(blockchain_service)
            .register_service(peer_service)
            .register_service(health_service)
            .register_service(attested_service)
            .register_service(build_info_service)
            .bind_using_uri(&self.config.peer_listen_uri, self.logger.clone());

        let mut server = server_builder.build().unwrap();
        server.start();

        for (host, port) in server.bind_addrs() {
            log::info!(self.logger, "Peer GRPC API listening on {}:{}", host, port);
        }

        self.consensus_rpc_server = Some(server);

        Ok(())
    }

    fn start_byzantine_ledger_service(&mut self) -> Result<(), ConsensusServiceError> {
        log::info!(self.logger, "Starting ByzantineLedger service.");

        let byzantine_ledger_arc = self
            .byzantine_ledger
            .as_mut()
            .expect("Server not initialized");
        if byzantine_ledger_arc
            .set(ByzantineLedger::new(
                self.local_node_id.clone(),
                self.config.network().quorum_set(),
                self.peer_manager.clone(),
                self.ledger_db.clone(),
                self.tx_manager.clone(),
                self.broadcaster.clone(),
                self.config.msg_signer_key.clone(),
                self.config.network().tx_source_urls,
                self.config.scp_debug_dump.clone(),
                self.logger.clone(),
            ))
            .is_err()
        {
            panic!("ByzantineLedger was doubly initialized")
        }

        // Handling of incoming SCP messages.
        let byzantine_ledger_weak = Arc::downgrade(byzantine_ledger_arc);
        let peer_keepalive_weak = Arc::downgrade(
            self.peer_keepalive
                .as_ref()
                .expect("Server not initialized"),
        );
        self.consensus_msgs_from_network
            .start(
                "MsgsFromNetRecv".to_string(),
                move |consensus_msg_from_network| {
                    let (consensus_msg, from_responder_id) = (
                        consensus_msg_from_network.consensus_msg,
                        consensus_msg_from_network.from_responder_id,
                    );

                    // Keep track that we heard from the sender of this message.
                    if let Some(peer_keepalive) = peer_keepalive_weak.upgrade() {
                        peer_keepalive.heard_from_peer(from_responder_id.clone());
                    }

                    byzantine_ledger_weak.upgrade().and_then(|ledger| {
                        ledger.get().map(|ledger| {
                            ledger.handle_consensus_msg(consensus_msg, from_responder_id)
                        })
                    });
                },
            )
            .map_err(|_| {
                ConsensusServiceError::BackgroundWorkQueueStart(
                    "consensus_msgs_from_network".to_string(),
                )
            })?;

        Ok(())
    }

    /// Creates a function that returns true if the node is currently serving user requests.
    fn create_is_serving_user_requests_fn(&self) -> Arc<dyn Fn() -> bool + Sync + Send> {
        let byzantine_ledger = self
            .byzantine_ledger
            .as_ref()
            .map(Arc::downgrade)
            .expect("Server was not initialized");

        Arc::new(move || {
            byzantine_ledger
                .upgrade()
                .and_then(|ledger| ledger.get().map(|ledger| !ledger.is_behind()))
                .unwrap_or(false)
        })
    }

    /// Creates a function that feeds client values into ByzantineLedger and broadcasts it to our
    /// peers.
    fn create_scp_client_value_sender_fn(&self) -> ProposeTxCallback {
        let byzantine_ledger = self
            .byzantine_ledger
            .as_ref()
            .map(Arc::downgrade)
            .expect("Server was not initialized");
        let tx_manager = self.tx_manager.clone();
        let local_node_id = self.local_node_id.clone();
        let broadcaster = self.broadcaster.clone();

        // Figure out which node IDs we are going to be relaying received transactions from.
        // See comment below ("Broadcast to peers") for more details.
        let relay_from_nodes: Vec<ResponderId> = self
            .peer_manager
            .conns()
            .iter()
            .filter_map(|conn| {
                let uri = conn.uri();
                if uri.consensus_relay_incoming_txs() {
                    match uri.responder_id() {
                        Ok(responder_id) => Some(responder_id),
                        Err(_e) => {
                            log::warn!(
                                self.logger,
                                "Could not get responder_id from {:?}",
                                uri.to_string()
                            );
                            None
                        }
                    }
                } else {
                    None
                }
            })
            .collect();

        Arc::new(move |tx_hash, origin_node, relayed_from| {
            let origin_node = origin_node.unwrap_or(&local_node_id);

            // Broadcast to peers.
            //
            // Nodes always relay transactions sent to them by clients to all their peers. As such, in
            // mesh network configurations there is no need to relay transactions received from other
            // peers since the originating node will already take care of sending the transaction to all
            // of it's peers.
            // However, in non-mesh configurations, network operators might want to selectively have
            // incoming transactions from certain peers be relayed to other peers in order to improve
            // consensus time.
            if origin_node == &local_node_id || relay_from_nodes.contains(&origin_node.responder_id)
            {
                if let Some(encrypted_tx) = tx_manager.get_encrypted_tx(&tx_hash) {
                    broadcaster
                        .lock()
                        .expect("lock poisoned")
                        .broadcast_propose_tx_msg(
                            &tx_hash,
                            encrypted_tx,
                            origin_node,
                            relayed_from.unwrap_or(&local_node_id.responder_id),
                        );
                } else {
                    // If a value was submitted to `scp_client_value_sender` that means it
                    // should've found it's way into the cache. Suddenly not having it there
                    // indicates something is broken, so for the time being we will panic.
                    panic!("tx hash {} expected to be in cache but wasn't", tx_hash);
                }
            }

            // Feed into ByzantineLedger.
            let timestamp = if origin_node == &local_node_id {
                Some(Instant::now())
            } else {
                None
            };
            byzantine_ledger.upgrade().and_then(|ledger| {
                ledger
                    .get()
                    .map(|ledger| ledger.push_values(vec![tx_hash], timestamp))
            });
        })
    }

    /// Helper method for creating the get config json function needed by the GRPC admin service.
    fn create_get_config_json_fn(&self) -> GetConfigJsonFn {
        let ledger_db = self.ledger_db.clone();

        let byzantine_ledger: Weak<OnceCell<ByzantineLedger>> = self
            .byzantine_ledger
            .as_ref()
            .map(Arc::downgrade)
            .expect("Server was not initialized");

        let config = self.config.clone();
        let logger = self.logger.clone();
        Arc::new(move || {
            // The highest block in the local ledger, and its BlockSignature if available.
            let (highest_block, highest_block_signature): (Block, Option<BlockSignature>) = {
                // Number of blocks in the local ledger.
                let num_blocks: u64 = ledger_db.num_blocks().map_err(|e| {
                    log::error!(logger, "{:?}", e);
                    RpcStatus::new(
                        RpcStatusCode::UNAVAILABLE,
                        Some("LedgerDB error".to_string()),
                    )
                })?;

                // The local ledger must at least contain the origin block.
                assert_ne!(num_blocks, 0, "The local ledger must not be empty");
                let highest_block_index = num_blocks - 1;

                // The highest block in the local ledger.
                let highest_block: Block =
                    ledger_db.get_block(highest_block_index).map_err(|e| {
                        log::error!(
                            logger,
                            "Error getting block {} {:?}",
                            highest_block_index,
                            e
                        );
                        RpcStatus::new(
                            RpcStatusCode::UNAVAILABLE,
                            Some("LedgerDB error".to_string()),
                        )
                    })?;

                // Enclave signature for highest_block, if any.
                let highest_block_signature: Option<BlockSignature> =
                    match ledger_db.get_block_signature(highest_block_index) {
                        Ok(block_signature) => Ok(Some(block_signature)),
                        // A block signature will be missing if the corresponding block was not
                        // processed by an enclave participating in consensus. For example, unsigned
                        // blocks can be created by a node that falls behind its peers and
                        // enters into catchup.
                        Err(LedgerDbError::NotFound) => {
                            log::trace!(
                                logger,
                                "BlockSignature not found for block {}",
                                highest_block_index
                            );
                            Ok(None)
                        }
                        Err(e) => {
                            log::error!(
                                logger,
                                "Error getting BlockSignature for block {} {:?}",
                                highest_block_index,
                                e
                            );
                            Err(RpcStatus::new(
                                RpcStatusCode::UNAVAILABLE,
                                Some("LedgerDB error".to_string()),
                            ))
                        }
                    }?;

                (highest_block, highest_block_signature)
            };

            let (is_behind, highest_peer_block_index): (bool, u64) = {
                let byzantine_ledger_arc_once_cell: Arc<OnceCell<ByzantineLedger>> =
                    match byzantine_ledger.upgrade() {
                        Some(instance) => Ok(instance),
                        None => {
                            log::error!(logger, "ByzantineLedger has been dropped.");
                            Err(RpcStatus::new(
                                RpcStatusCode::UNAVAILABLE,
                                Some("ByzantineLedger has been dropped".to_string()),
                            ))
                        }
                    }?;

                let byzantine_ledger_instance = match byzantine_ledger_arc_once_cell.get() {
                    Some(instance) => Ok(instance),
                    None => {
                        log::error!(logger, "ByzantineLedger has not been initialized.");
                        Err(RpcStatus::new(
                            RpcStatusCode::UNAVAILABLE,
                            Some("ByzantineLedger has not been initialized".to_string()),
                        ))
                    }
                }?;

                let is_behind: bool = byzantine_ledger_instance.is_behind();
                let highest_peer_block_index: u64 = byzantine_ledger_instance.highest_peer_block();
                (is_behind, highest_peer_block_index)
            };

            let network_config = config.network();

            let json: String = config_and_status_as_json(
                &config,
                &network_config,
                &highest_block,
                highest_block_signature.as_ref(),
                is_behind,
                highest_peer_block_index,
            );

            Ok(json)
        })
    }
}

impl<
        E: ConsensusEnclave + Clone + Send + Sync + 'static,
        R: RaClient + Send + Sync + 'static,
        TXM: TxManager + Clone + Send + Sync + 'static,
    > Drop for ConsensusService<E, R, TXM>
{
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

/// Format the service's configuration and ledger status as JSON.
///
/// # Arguments
/// * `config` - ConsensusService configurations.
/// * `network_config` - Network configuration.
/// * `highest_block` - Highest block in the local ledger.
/// * `highest_block_signature` - Signature, if any, for the highest block in the local ledger.
/// * `is_behind` - True if the local ledger is behind the peers' ledgers.
/// * `highest_peer_block_index` -  Highest block index agreed upon by peers.
fn config_and_status_as_json(
    config: &Config,
    network_config: &NetworkConfig,
    highest_block: &Block,
    highest_block_signature: Option<&BlockSignature>,
    is_behind: bool,
    highest_peer_block_index: u64,
) -> String {
    // The approximate time in which the block was signed, represented at seconds
    //  of UTC time since Unix epoch 1970-01-01T00:00:00Z.
    let highest_block_signed_at: Option<u64> =
        highest_block_signature.map(|signature| signature.signed_at());

    let sync_status = if is_behind { "catchup" } else { "synced" };

    // Number of blocks that the local node is behind, or zero if the local node is not behind.
    // (It's funky that this is both an Option and a saturating value. It would probably be simpler to
    // return the local node's block index and the highest peers' block index.)
    let blocks_behind = Some(highest_peer_block_index.saturating_sub(highest_block.index));

    json!({
                "config": {
                    "public_key": config.node_id().public_key,
                    "peer_responder_id": config.peer_responder_id,
                    "client_responder_id": config.client_responder_id,
                    "message_pubkey": encode_config(&config.msg_signer_key.public_key().to_der(), URL_SAFE),
                    "network": config.network_path,
                    "peer_listen_uri": config.peer_listen_uri,
                    "client_listen_uri": config.client_listen_uri,
                    "admin_listen_uri": config.admin_listen_uri,
                    "ledger_path": config.ledger_path,
                    "scp_debug_dump": config.scp_debug_dump,
                    "client_auth_token_enabled": config.client_auth_token_secret.map(|_| true).unwrap_or(false),
                    "client_auth_token_max_lifetime": config.client_auth_token_max_lifetime.as_secs(),
                },
                "network": network_config,
                "status": {
                    "block_height": highest_block.index + 1,
                    "version": VERSION,
                    "broadcast_peer_count": network_config.broadcast_peers.len(),
                    "known_peer_count": network_config.known_peers.as_ref().map_or(0, |x| x.len()),
                    "sync_status": sync_status,
                    "blocks_behind": blocks_behind,
                    "latest_block_hash": hex::encode(&highest_block.id.0),
                    "latest_block_timestamp": highest_block_signed_at.map_or("".to_string(), |u| u.to_string()),
                },
            })
        .to_string()
}

#[cfg(test)]
mod tests {
    use crate::{
        config::{keypair_from_base64, Config, NetworkConfig},
        consensus_service::config_and_status_as_json,
    };
    use mc_attest_core::ProviderId;
    use mc_common::ResponderId;
    use mc_transaction_core::Block;
    use mc_util_uri::{AdminUri, ConsensusClientUri, ConsensusPeerUri};
    use serde_json::Value;
    use std::{path::PathBuf, str::FromStr, time::Duration};

    // Sample ConsensusService configurations.
    fn get_config() -> Config {
        Config {
            peer_responder_id: ResponderId::from_str("localhost:8081").unwrap(),
            client_responder_id: ResponderId::from_str("localhost:3223").unwrap(),
            msg_signer_key: keypair_from_base64(
                "MC4CAQAwBQYDK2VwBCIEIC50QXQll2Y9qxztvmsUgcBBIxkmk7EQjxzQTa926bKo",
            )
            .unwrap(),
            network_path: PathBuf::from("network.toml"),
            ias_api_key: "".to_string(),
            ias_spid: ProviderId::from_str("22222222222222222222222222222222").unwrap(),
            peer_listen_uri: ConsensusPeerUri::from_str("insecure-mcp://0.0.0.0:8081/").unwrap(),
            client_listen_uri: ConsensusClientUri::from_str("insecure-mc://0.0.0.0:3223/").unwrap(),
            admin_listen_uri: Some(AdminUri::from_str("insecure-mca://0.0.0.0:9090/").unwrap()),
            ledger_path: Default::default(),
            scp_debug_dump: None,
            origin_block_path: None,
            sealed_block_signing_key: Default::default(),
            client_auth_token_secret: None,
            client_auth_token_max_lifetime: Duration::from_secs(60),
        }
    }

    // network_config is constructed here instead of using config.network() because
    // config.network() has the side effect of reading a toml file.
    fn get_network_config() -> NetworkConfig {
        let input_toml: &str = r#"
                broadcast_peers = []
                tx_source_urls = []
                quorum_set = { threshold = 2, members = [] }
            "#;
        toml::from_str(input_toml).unwrap()
    }

    #[test]
    /// Should return parsable JSON.
    fn test_config_and_status_as_json() {
        let config = get_config();
        let network_config = get_network_config();
        let highest_block = Block::new_origin_block(&vec![]);
        let highest_block_signature = None;
        let is_behind = true;
        let highest_peer_block_index = 13;

        let json: String = config_and_status_as_json(
            &config,
            &network_config,
            &highest_block,
            highest_block_signature.as_ref(),
            is_behind,
            highest_peer_block_index,
        );

        // Spot-check some of the fields.
        let v: Value = serde_json::from_str(&json).expect("Could not parse JSON");

        assert_eq!(v["status"]["block_height"], highest_block.index + 1);
        assert_eq!(v["status"]["sync_status"], "catchup");
        assert_eq!(v["status"]["blocks_behind"], 13);
    }
}
