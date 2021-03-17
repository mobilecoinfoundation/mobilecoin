// Copyright (c) 2018-2021 The MobileCoin Foundation

//! PeerKeepalive is used to start a thread that periodically pings nodes we
//! have not received an SCP statement from in a while. This allows nodes who
//! have temporarily lost connectivity and came back online to re-sync with
//! their peers.

use crate::{
    background_work_queue::BackgroundWorkQueueSenderFn, consensus_service::IncomingConsensusMsg,
};
use mc_common::{
    logger::{log, Logger},
    HashMap, ResponderId,
};
use mc_connection::ConnectionManager;
use mc_peers::{ConsensusConnection, RetryableConsensusConnection};
use retry::Error as RetryError;
use std::{
    convert::TryInto,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};

/// How much time needs to pass since we last hear from a node before we try
/// pinging it?
const START_KEEPALIVE_CHECKS_AFTER: Duration = Duration::from_secs(30);

/// Time between keepalive checks for silent nodes.
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);

pub struct PeerKeepalive {
    join_handle: Option<thread::JoinHandle<()>>,
    stop_requested: Arc<AtomicBool>,
    responder_id_to_last_heard: Arc<Mutex<HashMap<ResponderId, Instant>>>,
}

impl PeerKeepalive {
    pub fn start<CC: ConsensusConnection + 'static>(
        conn_manager: ConnectionManager<CC>,
        incoming_consensus_msgs_sender: BackgroundWorkQueueSenderFn<IncomingConsensusMsg>,
        logger: Logger,
    ) -> Self {
        // Start by asssuming we heard from all of our peers.
        let now = Instant::now();
        let responder_id_to_last_heard = Arc::new(Mutex::new(
            conn_manager
                .responder_ids()
                .iter()
                .map(|node_id| (node_id.clone(), now))
                .collect(),
        ));

        let stop_requested = Arc::new(AtomicBool::new(false));
        let thread_stop_requested = stop_requested.clone();
        let thread_responder_id_to_last_heard = responder_id_to_last_heard.clone();
        let join_handle = Some(
            thread::Builder::new()
                .name("PeerKeepAlive".into())
                .spawn(move || {
                    Self::thread_entrypoint(
                        conn_manager,
                        thread_stop_requested,
                        incoming_consensus_msgs_sender,
                        thread_responder_id_to_last_heard,
                        logger,
                    )
                })
                .expect("Failed spawning PeerKeepAlive thread"),
        );

        Self {
            join_handle,
            stop_requested,
            responder_id_to_last_heard,
        }
    }

    pub fn stop(&mut self) {
        self.stop_requested.store(true, Ordering::SeqCst);
        if let Some(thread) = self.join_handle.take() {
            thread.join().expect("PeerKeepAlive thread join failed");
        }
    }

    pub fn heard_from_peer(&self, responder_id: ResponderId) {
        let mut responder_id_to_last_heard = self
            .responder_id_to_last_heard
            .lock()
            .expect("mutex poisoned");
        responder_id_to_last_heard.insert(responder_id, Instant::now());
    }

    fn thread_entrypoint<CC: ConsensusConnection>(
        conn_manager: ConnectionManager<CC>,
        stop_requested: Arc<AtomicBool>,
        incoming_consensus_msgs_sender: BackgroundWorkQueueSenderFn<IncomingConsensusMsg>,
        responder_id_to_last_heard: Arc<Mutex<HashMap<ResponderId, Instant>>>,
        logger: Logger,
    ) {
        log::debug!(logger, "PeerKeepAlive thread has started.");

        // When did we last try and contact a given node?
        let mut last_attempt_at = HashMap::<ResponderId, Instant>::default();

        loop {
            if stop_requested.load(Ordering::SeqCst) {
                log::debug!(logger, "PeerKeepAlive stop requested.");
                break;
            }

            // Get a list of nodes we haven't heard from recently
            let silent_nodes: Vec<ResponderId> = {
                let responder_id_to_last_heard =
                    responder_id_to_last_heard.lock().expect("mutex poisoned");
                let now = Instant::now();
                responder_id_to_last_heard
                    .iter()
                    .filter(|(_node_id, last_heard)| {
                        now.saturating_duration_since(**last_heard) > START_KEEPALIVE_CHECKS_AFTER
                    })
                    .map(|(node_id, _last_heard)| node_id.clone())
                    .collect()
            };

            if !silent_nodes.is_empty() {
                log::trace!(logger, "silent nodes: {:?}", silent_nodes);
                let now = Instant::now();
                // Attempt to ping each of our silent nodes.
                for responder_id in silent_nodes {
                    // See if it's time to ping this node, and if not skip it.
                    if let Some(last_attempt_at) = last_attempt_at.get(&responder_id) {
                        if now.saturating_duration_since(*last_attempt_at) < KEEPALIVE_INTERVAL {
                            continue;
                        }
                    }

                    last_attempt_at.insert(responder_id.clone(), now);

                    match conn_manager
                        .conn(&responder_id)
                        .ok_or_else(|| RetryError::Internal(format!("{} not found", responder_id)))
                        .and_then(|conn| conn.fetch_latest_msg(std::iter::empty()))
                    {
                        Ok(None) => {
                            let mut responder_id_to_last_heard =
                                responder_id_to_last_heard.lock().expect("mutex poisoned");
                            responder_id_to_last_heard.insert(responder_id.clone(), Instant::now());

                            log::trace!(
                                logger,
                                "heard back from silent node {} with no consensus message",
                                responder_id
                            );
                        }
                        Ok(Some(unverified_consensus_msg)) => {
                            // Validate message signature
                            // FIXME: Additional verification for quorum set members that public key
                            // matches expected
                            match unverified_consensus_msg.clone().try_into() {
                                Ok(consensus_msg) => {
                                    // Note that we do not update `responder_id_to_last_heard` here
                                    // since this will get to us
                                    // through the `incoming_consensus_msgs` processing loop
                                    // in `ConsensusService`.
                                    log::trace!(
                                        logger,
                                        "heard back from silent node {} with a consensus message",
                                        responder_id
                                    );
                                    let _ =
                                        (incoming_consensus_msgs_sender)(IncomingConsensusMsg {
                                            from_responder_id: responder_id,
                                            consensus_msg,
                                        });
                                }
                                Err(err) => {
                                    log::error!(
                                        logger,
                                        "Signature verification failed for msg {:?} from node_id {:?}: {:?}, disregarding.",
                                        unverified_consensus_msg,
                                        responder_id,
                                        err
                                    );
                                }
                            };
                        }
                        Err(err) => {
                            log::info!(
                                logger,
                                "failed checking with silent node {}: {:?}",
                                responder_id,
                                err
                            );
                        }
                    }
                }
            }

            thread::sleep(Duration::from_secs(1));
        }
    }
}

impl Drop for PeerKeepalive {
    fn drop(&mut self) {
        self.stop();
    }
}
