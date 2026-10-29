// Copyright (c) 2018-2022 The MobileCoin Foundation

//! PeerKeepalive is used to start a thread that periodically pings nodes we
//! have not received an SCP statement from in a while. This allows nodes who
//! have temporarily lost connectivity and came back online to re-sync with
//! their peers.

use crate::{
    background_work_queue::BackgroundWorkQueueSenderFn,
    consensus_msg_verifier::{ConsensusMsgVerificationError, ConsensusMsgVerifier},
    consensus_service::IncomingConsensusMsg,
    counters,
};
use mc_common::{
    logger::{log, Logger},
    HashMap, ResponderId,
};
use mc_connection::ConnectionManager;
use mc_peers::{ConsensusConnection, ConsensusMsg, RetryableConsensusConnection};
use retry::Error as RetryError;
use std::{
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
        consensus_msg_verifier: Arc<ConsensusMsgVerifier>,
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
                        consensus_msg_verifier,
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
        consensus_msg_verifier: Arc<ConsensusMsgVerifier>,
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
                        .ok_or_else(|| RetryError {
                            error: mc_peers::Error::NotFound,
                            total_delay: Default::default(),
                            tries: 0,
                        })
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
                        Ok(Some(msg)) => Self::handle_consensus_msg(
                            msg,
                            responder_id,
                            &consensus_msg_verifier,
                            &incoming_consensus_msgs_sender,
                            &logger,
                        ),
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

    fn handle_consensus_msg(
        msg: ConsensusMsg,
        from_responder_id: ResponderId,
        verifier: &ConsensusMsgVerifier,
        incoming_consensus_msgs_sender: &BackgroundWorkQueueSenderFn<IncomingConsensusMsg>,
        logger: &Logger,
    ) {
        let issuer = msg.issuer_node_id().clone();
        let slot_index = msg.scp_msg.slot_index;
        match verifier.verify(msg) {
            Ok(consensus_msg) => {
                // The incoming-message loop updates when we last heard from the peer.
                log::trace!(
                    logger,
                    "heard back from silent node {} with a consensus message",
                    from_responder_id
                );
                let _ = (incoming_consensus_msgs_sender)(IncomingConsensusMsg {
                    from_responder_id,
                    consensus_msg,
                });
            }
            Err(err) => {
                if matches!(err, ConsensusMsgVerificationError::PublicKeyMismatch(_)) {
                    counters::CONSENSUS_MSG_ISSUER_KEY_MISMATCHES.inc();
                }
                log::error!(
                    logger,
                    "Consensus message verification failed for issuer {issuer} from {from_responder_id} at slot {slot_index}: {err}, disregarding."
                );
            }
        }
    }
}

impl Drop for PeerKeepalive {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mc_common::{logger::test_with_logger, NodeID};
    use mc_consensus_scp::QuorumSet;
    use mc_ledger_db::test_utils::get_mock_ledger;
    use mc_peers_test_utils::{create_consensus_msg, test_node_id_and_signer};

    #[test_with_logger]
    fn latest_messages_enforce_configured_issuer_keys(logger: Logger) {
        let (peer, signer) = test_node_id_and_signer(22);
        let (attacker, attacker_signer) = test_node_id_and_signer(33);
        let verifier = ConsensusMsgVerifier::new([peer.clone()]);
        let ledger = get_mock_ledger(1);
        let make_message =
            |node, key| create_consensus_msg(&ledger, node, QuorumSet::empty(), 1, "value", key);
        let received = Arc::new(Mutex::new(Vec::new()));
        let sender_received = received.clone();
        let sender: BackgroundWorkQueueSenderFn<IncomingConsensusMsg> = Arc::new(move |msg| {
            sender_received.lock().unwrap().push(msg);
            Ok(())
        });
        let forged = make_message(
            NodeID {
                responder_id: peer.responder_id.clone(),
                public_key: attacker.public_key,
            },
            &attacker_signer,
        );
        forged.verify_signature().unwrap();
        let mismatches_before = counters::CONSENSUS_MSG_ISSUER_KEY_MISMATCHES.get();
        for invalid in [forged, make_message(peer.clone(), &attacker_signer)] {
            PeerKeepalive::handle_consensus_msg(
                invalid,
                peer.responder_id.clone(),
                &verifier,
                &sender,
                &logger,
            );
        }
        assert!(received.lock().unwrap().is_empty());
        assert!(counters::CONSENSUS_MSG_ISSUER_KEY_MISMATCHES.get() > mismatches_before);

        let transitive = make_message(attacker, &attacker_signer);
        PeerKeepalive::handle_consensus_msg(
            transitive.clone(),
            peer.responder_id.clone(),
            &verifier,
            &sender,
            &logger,
        );
        let valid = make_message(peer.clone(), &signer);
        PeerKeepalive::handle_consensus_msg(
            valid.clone(),
            peer.responder_id.clone(),
            &verifier,
            &sender,
            &logger,
        );
        let received = received.lock().unwrap();
        assert_eq!(received.len(), 2);
        assert_eq!(received[0].consensus_msg.as_ref(), &transitive);
        assert_eq!(received[1].from_responder_id, peer.responder_id);
        assert_eq!(received[1].consensus_msg.as_ref(), &valid);
    }
}
