// Copyright (c) 2018-2020 MobileCoin Inc.

//! The MobileCoin consensus service.

use crate::{
    attested_api_service::AttestedApiService, background_work_queue::BackgroundWorkQueue,
    blockchain_api_service, byzantine_ledger::ByzantineLedger, client_api_service, config::Config,
    counters, peer_api_service, peer_keepalive::PeerKeepalive, tx_manager::TxManager,
    validators::DefaultTxManagerUntrustedInterfaces,
};
use failure::Fail;
use futures::executor::block_on;
use grpcio::{EnvBuilder, Environment, Server, ServerBuilder};
use mc_attest_api::attest_grpc::create_attested_api;
use mc_attest_enclave_api::{ClientSession, PeerSession};
use mc_attest_net::RaClient;
use mc_common::{
    logger::{log, Logger},
    NodeID, ResponderId,
};
use mc_connection::{Connection, ConnectionManager};
use mc_consensus_api::{consensus_client_grpc, consensus_common_grpc, consensus_peer_grpc};
use mc_consensus_enclave::ConsensusEnclaveProxy;
use mc_ledger_db::{Ledger, LedgerDB};
use mc_peers::{PeerConnection, ThreadedBroadcaster, VerifiedConsensusMsg};
use mc_sgx_report_cache_untrusted::{Error as ReportCacheError, ReportCacheThread};
use mc_transaction_core::tx::TxHash;
use mc_util_grpc::{
    AdminServer, BuildInfoService, ConnectionUriGrpcioServer, GetConfigJsonFn, HealthCheckStatus,
    HealthService,
};
use mc_util_uri::{ConnectionUri, ConsensusPeerUriApi};
use serde_json::json;
use std::{
    env,
    sync::{Arc, Mutex},
    time::Instant,
};

/// Crate version, used for admin info endpoint
const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Fail)]
pub enum ConsensusServiceError {
    #[fail(display = "Failed to join thread: {}", _0)]
    ThreadJoin(String),
    #[fail(display = "RPC shutdown failure: {}", _0)]
    RpcShutdown(String),
    #[fail(display = "Failed to start background work queue: {}", _0)]
    BackgroundWorkQueueStart(String),
    #[fail(display = "Failed to stop background work queue: {}", _0)]
    BackgroundWorkQueueStop(String),
    #[fail(display = "Report cache error: {}", _0)]
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

pub struct ConsensusService<E: ConsensusEnclaveProxy, R: RaClient + Send + Sync + 'static> {
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
    broadcaster: Arc<Mutex<ThreadedBroadcaster>>,
    tx_manager: TxManager<E, LedgerDB>,
    peer_keepalive: Arc<Mutex<PeerKeepalive>>,

    admin_rpc_server: Option<AdminServer>,
    consensus_rpc_server: Option<Server>,
    user_rpc_server: Option<Server>,
    byzantine_ledger: Arc<Mutex<Option<ByzantineLedger>>>,
}

impl<E: ConsensusEnclaveProxy, R: RaClient + Send + Sync + 'static> ConsensusService<E, R> {
    pub fn new(
        config: Config,
        enclave: E,
        ledger_db: LedgerDB,
        ra_client: R,
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

        // Tx Manager
        let tx_manager = TxManager::new(
            enclave.clone(),
            ledger_db.clone(),
            DefaultTxManagerUntrustedInterfaces::new(ledger_db.clone()),
            logger.clone(),
        );

        // Peer Keepalive
        let peer_keepalive = Arc::new(Mutex::new(PeerKeepalive::start(
            peer_manager.clone(),
            consensus_msgs_from_network.get_sender_fn(),
            logger.clone(),
        )));

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

            admin_rpc_server: None,
            consensus_rpc_server: None,
            user_rpc_server: None,
            byzantine_ledger: Arc::new(Mutex::new(None)),
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

        self.peer_keepalive.lock().expect("mutex poisoned").stop();

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

        let mut byzantine_ledger = self.byzantine_ledger.lock().expect("lock poisoned");
        if let Some(ref mut byzantine_ledger) = byzantine_ledger.take() {
            byzantine_ledger.stop();
        }

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

        let mut byzantine_ledger = self.byzantine_ledger.lock().expect("lock poisoned");
        if let Some(mut byzantine_ledger) = byzantine_ledger.take() {
            log::debug!(self.logger, "Waiting for byzantine_ledger...");
            byzantine_ledger.join();
        }

        Ok(())
    }

    fn start_user_rpc_server(&mut self) -> Result<(), ConsensusServiceError> {
        log::info!(
            self.logger,
            "Starting user rpc server on {}...",
            self.config.client_listen_uri.addr(),
        );

        // Setup GRPC services.
        let client_service = consensus_client_grpc::create_consensus_client_api(
            client_api_service::ClientApiService::new(
                self.enclave.clone(),
                self.create_scp_client_value_sender_fn(),
                self.ledger_db.clone(),
                self.tx_manager.clone(),
                self.create_is_serving_user_requests_fn(),
                self.logger.clone(),
            ),
        );

        let attested_service = create_attested_api(AttestedApiService::<E, ClientSession>::new(
            self.enclave.clone(),
            self.logger.clone(),
        ));

        let blockchain_service = consensus_common_grpc::create_blockchain_api(
            blockchain_api_service::BlockchainApiService::new(
                self.ledger_db.clone(),
                self.logger.clone(),
            ),
        );

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
            .bind_using_uri(&self.config.client_listen_uri);

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

        // Initialize services.
        let byzantine_ledger = self.byzantine_ledger.clone();
        let get_highest_scp_message_fn = Arc::new(move || {
            let byzantine_ledger = byzantine_ledger.lock().expect("mutex poisoned");
            byzantine_ledger
                .as_ref()
                .and_then(|byzantine_ledger| byzantine_ledger.get_highest_scp_message())
        });

        let blockchain_service = consensus_common_grpc::create_blockchain_api(
            blockchain_api_service::BlockchainApiService::new(
                self.ledger_db.clone(),
                self.logger.clone(),
            ),
        );

        let peer_service =
            consensus_peer_grpc::create_consensus_peer_api(peer_api_service::PeerApiService::new(
                self.enclave.clone(),
                self.consensus_msgs_from_network.get_sender_fn(),
                self.create_scp_client_value_sender_fn(),
                self.ledger_db.clone(),
                self.tx_manager.clone(),
                get_highest_scp_message_fn,
                self.peer_manager.responder_ids(),
                self.logger.clone(),
            ));

        let attested_service = create_attested_api(AttestedApiService::<E, PeerSession>::new(
            self.enclave.clone(),
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
            .bind_using_uri(&self.config.peer_listen_uri);

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

        let mut byzantine_ledger = self.byzantine_ledger.lock().expect("lock poisoned");
        byzantine_ledger.replace(ByzantineLedger::new(
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
        ));

        // Handling of incoming SCP messages.
        let byzantine_ledger_1 = self.byzantine_ledger.clone();
        let peer_keepalive = self.peer_keepalive.clone();
        self.consensus_msgs_from_network
            .start(
                "MsgsFromNetRecv".to_string(),
                move |consensus_msg_from_network| {
                    let (consensus_msg, from_responder_id) = (
                        consensus_msg_from_network.consensus_msg,
                        consensus_msg_from_network.from_responder_id,
                    );

                    // Keep track that we heard from the sender of this message.
                    {
                        let peer_keepalive = peer_keepalive.lock().expect("mutex poisoned");
                        peer_keepalive.heard_from_peer(from_responder_id.clone());
                    }

                    // Feed into ByzantineLedger.
                    if let Some(ref byzantine_ledger) = *(byzantine_ledger_1.lock().unwrap()) {
                        byzantine_ledger.handle_consensus_msg(consensus_msg, from_responder_id);
                    }
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
        let byzantine_ledger = self.byzantine_ledger.clone();

        Arc::new(move || {
            let byzantine_ledger = byzantine_ledger.lock().expect("lock poisoned");
            byzantine_ledger
                .as_ref()
                .map(|byzantine_ledger| !byzantine_ledger.is_behind())
                .unwrap_or(false)
        })
    }

    /// Creates a function that feeds client values into ByzantineLedger and broadcasts it to our
    /// peers.
    fn create_scp_client_value_sender_fn(&self) -> ProposeTxCallback {
        let byzantine_ledger = self.byzantine_ledger.clone();
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
                if let Some(encrypted_tx) = tx_manager.get_encrypted_tx_by_hash(&tx_hash) {
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
            let byzantine_ledger = byzantine_ledger.lock().expect("lock poisoned");
            let timestamp = if origin_node == &local_node_id {
                Some(Instant::now())
            } else {
                None
            };
            if let Some(byzantine_ledger) = &*byzantine_ledger {
                byzantine_ledger.push_values(vec![tx_hash], timestamp);
            }
        })
    }

    /// Helper method for creating the get config json function needed by the GRPC admin service.
    fn create_get_config_json_fn(&self) -> GetConfigJsonFn {
        let ledger_db = self.ledger_db.clone();
        let byzantine_ledger = self.byzantine_ledger.clone();
        let config = self.config.clone();
        let logger = self.logger.clone();
        Arc::new(move || {
            let mut sync_status = "synced";
            let mut peer_block_height: u64 = 0;
            let byzantine_ledger = byzantine_ledger
                .lock()
                .expect("Could not get byzantine ledger.");
            if let Some(byzantine_ledger) = &*byzantine_ledger {
                if byzantine_ledger.is_behind() {
                    sync_status = "catchup";
                };
                peer_block_height = byzantine_ledger.highest_peer_block();
            }
            let block_height;
            let latest_block_hash;
            let latest_block_timestamp;
            let blocks_behind;
            // If we do not get a num_blocks, several status points will be null
            match ledger_db.num_blocks() {
                Ok(b) => {
                    block_height = Some(b);
                    latest_block_hash = ledger_db
                        .get_block(b - 1)
                        .map(|x| format!("{:X}", x.id.0))
                        .map_err(|e| log::error!(logger, "Error getting block {} {:?}", b - 1, e))
                        .ok();
                    latest_block_timestamp = ledger_db
                        .get_block_signature(b - 1)
                        .map(|x| x.signed_at())
                        .map_err(|e| {
                            log::error!(
                                logger,
                                "Error getting block signature for block {} {:?}",
                                b - 1,
                                e
                            )
                        })
                        .ok();
                    blocks_behind = Some(std::cmp::min(peer_block_height - b, 0));
                }
                Err(e) => {
                    log::error!(logger, "Error getting block height {:?}", e);
                    block_height = None;
                    latest_block_hash = None;
                    latest_block_timestamp = None;
                    blocks_behind = None;
                }
            };
            Ok(json!({
                "config": {
                    "public_key": config.node_id().public_key,
                    "peer_responder_id": config.peer_responder_id,
                    "client_responder_id": config.client_responder_id,
                    "message_pubkey": config.msg_signer_key.public_key(),
                    "network": config.network_path,
                    "peer_listen_uri": config.peer_listen_uri,
                    "client_listen_uri": config.client_listen_uri,
                    "admin_listen_uri": config.admin_listen_uri,
                    "ledger_path": config.ledger_path,
                    "scp_debug_dump": config.scp_debug_dump,
                },
                "network": config.network(),
                "status": {
                    "block_height": block_height,
                    "version": VERSION,
                    "broadcast_peer_count": config.network().broadcast_peers.len(),
                    "known_peer_count": config.network().known_peers.map_or(0, |x| x.len()),
                    "sync_status": sync_status,
                    "blocks_behind": blocks_behind,
                    "latest_block_hash": latest_block_hash,
                    "latest_block_timestamp": latest_block_timestamp,
                },
            })
            .to_string())
        })
    }
}

impl<E: ConsensusEnclaveProxy, R: RaClient + Send + Sync + 'static> Drop
    for ConsensusService<E, R>
{
    fn drop(&mut self) {
        let _ = self.stop();
    }
}
