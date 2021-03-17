// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Mult-Threaded message broadcaster

use crate::{
    consensus_msg::ConsensusMsg,
    error::Error,
    threaded_broadcaster_retry::{FibonacciRetryPolicy, IteratorWithDeadlineExt, RetryPolicy},
    traits::{ConsensusConnection, RetryableConsensusConnection},
    Broadcast,
};
use mc_common::{
    logger::{log, o, Logger},
    Hash, LruCache, NodeID, ResponderId,
};
use mc_connection::{Connection, ConnectionManager, SyncConnection};
use mc_consensus_api::consensus_peer::ConsensusMsgResult;
use mc_consensus_enclave_api::WellFormedEncryptedTx;
use mc_crypto_digestible::{Digestible, MerlinTranscript};
use mc_transaction_core::tx::TxHash;
use mc_util_uri::ConnectionUri;
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};

/// Number of messages to keep track of.
const HISTORY_SIZE: usize = 10000;

/// `ThreadedBroadcaster` is used to broadcast consensus messages and
/// transactions to a list of peers. It keeps track of the last `HISTORY_SIZE`
/// messages handed to it, preventing duplicate messages from being broadcasted.
/// It can be used by `consensus_service` to deliver outgoing messages to the
/// local node's peers, as well as to relay messages received from peers to
/// other peers. A thread is created per each peer to handle message delivery.
/// This means a non-responsive peer does not slow message delivery to other
/// peers, and does not block the caller of `broadcast_consensus_msg`.
pub struct ThreadedBroadcaster<RP: RetryPolicy = FibonacciRetryPolicy> {
    /// List of peers to communicate with.
    peer_threads: Vec<PeerThread>,

    /// Hashes of messages we've already processed.
    /// (We store hashes to reduce memory footprint - we don't actually care
    /// about the message's contents)
    seen_msg_hashes: LruCache<Hash, ()>,

    /// Hashes of transactions we've already broadcasted.
    seen_tx_hashes: LruCache<TxHash, ()>,

    // Retry policy.
    retry_policy: RP,

    // Logger.
    logger: Logger,
}

impl<RP: RetryPolicy> ThreadedBroadcaster<RP> {
    pub fn new<CC: ConsensusConnection + 'static>(
        manager: &ConnectionManager<CC>,
        retry_policy: &RP,
        logger: Logger,
    ) -> Self {
        let peer_threads: Vec<PeerThread> = manager
            .conns()
            .into_iter()
            .filter(|conn| {
                conn.uri()
                    .get_param("broadcast-consensus-msgs")
                    .unwrap_or_else(|| "1".to_string())
                    == "1"
            })
            .map(|conn| {
                let peer_name = conn.to_string();
                PeerThread::new(
                    conn,
                    retry_policy,
                    logger.new(o!(
                        "mc.peers.peer_name" => peer_name,
                    )),
                )
            })
            .collect();
        Self {
            peer_threads,
            seen_msg_hashes: LruCache::new(HISTORY_SIZE),
            seen_tx_hashes: LruCache::new(HISTORY_SIZE),
            retry_policy: retry_policy.clone(),
            logger,
        }
    }

    pub fn stop(&mut self) {
        for peer_thread in self.peer_threads.iter_mut() {
            peer_thread.stop();
        }
    }

    /// Broadcasts a propose transaction message.
    ///
    /// # Arguments
    ///
    /// * `origin_node` - The node the transaction was originally submitted to
    ///   by a client.
    ///
    /// * `from_node` - The node the transaction was received from. This allows
    ///   us to not echo the
    /// message back to the node that handed it to us. Note that due to message
    /// relaying, this can be a different node than the one that created the
    /// message (`origin_node`).
    ///
    /// * `msgs` - A map of peer id -> message to broadcast. We need a map since
    ///   messages are
    /// encrypted for each peer using a peer-specific session key.
    pub fn broadcast_propose_tx_msg(
        &mut self,
        tx_hash: &TxHash,
        encrypted_tx: WellFormedEncryptedTx,
        origin_node: &NodeID,
        relayed_by: &ResponderId,
    ) {
        let deadline = Instant::now() + self.retry_policy.get_max_message_age();

        // If we've already seen this transaction, we don't need to do anything.
        // We use `get()` instead of `contains()` to update LRU state.
        if self.seen_tx_hashes.get(tx_hash).is_some() {
            return;
        }

        // Store message so it doesn't get processed again.
        self.seen_tx_hashes.put(*tx_hash, ());

        // Create arcs to prevent cloning of larger data structures.
        let arc_encrypted_tx = Arc::new(encrypted_tx);
        let arc_origin_node = Arc::new(origin_node.clone());

        // Broadcast to all peers except the originating one.
        for peer_thread in self.peer_threads.iter() {
            // Do not broadcast to the originating node or the sender node.
            if *peer_thread.responder_id() == origin_node.responder_id
                || peer_thread.responder_id() == relayed_by
            {
                continue;
            }

            // Send message to peer.
            if let Err(err) = peer_thread.handle_propose_tx_msg(
                arc_encrypted_tx.clone(),
                arc_origin_node.clone(),
                deadline,
            ) {
                log::error!(
                    self.logger,
                    "failed broadcasting propose tx msg to {}: {:?}",
                    peer_thread.responder_id(),
                    err
                );
            }
        }
    }

    /// Tests helper: wait until a barrier message is processed (indicating
    /// all previous messages were also processed).
    pub fn barrier(&self) {
        for peer_thread in self.peer_threads.iter() {
            peer_thread.barrier();
        }
    }
}

impl<RP: RetryPolicy> Drop for ThreadedBroadcaster<RP> {
    fn drop(&mut self) {
        self.stop();
    }
}

impl<RP: RetryPolicy> Broadcast for ThreadedBroadcaster<RP> {
    /// Broadcasts a consensus message.
    ///
    /// # Arguments
    /// * `msg` - The message to be broadcast.
    /// * `received_from` - The peer the message was received from. This allows
    ///   us to not echo the message back to the peer that handed it to us. Note
    ///   that due to message relaying, this can be a different peer than the
    ///   one that created the message.
    fn broadcast_consensus_msg(&mut self, msg: &ConsensusMsg, received_from: &ResponderId) {
        let msg_hash = msg.digest32::<MerlinTranscript>(b"broadcast");

        // If we've already seen this message, we don't need to do anything.
        // We use `get()` instead of `contains()` to update LRU state.
        if self.seen_msg_hashes.get(&msg_hash).is_some() {
            return;
        }

        // Store message so it doesn't get processed again.
        self.seen_msg_hashes.put(msg_hash, ());

        // Broadcast to all peers except the originating one.
        let arc_msg = Arc::new(msg.clone());
        let deadline = Instant::now() + self.retry_policy.get_max_message_age();

        for peer_thread in self.peer_threads.iter() {
            // Do not broadcast to the originating node or the sender node.
            if peer_thread.responder_id() == msg.issuer_responder_id()
                || peer_thread.responder_id() == received_from
            {
                log::trace!(
                    self.logger,
                    "Not broadcasting to issuer {:?} ",
                    received_from
                );
                continue;
            }

            if let Err(err) = peer_thread.send_consensus_msg(arc_msg.clone(), deadline) {
                log::error!(
                    self.logger,
                    "failed broadcasting consensus msg to {}: {:?}",
                    peer_thread.responder_id(),
                    err
                );
            }
        }

        // Some debug logging
        log::trace!(self.logger, "broadcasted: {:?} ({:?})", msg, msg_hash);
    }
}

/// Possible messages sent to peer worker threads.
enum ThreadMsg {
    /// Send a consensus message.
    HandleConsensusMsg {
        msg: Arc<ConsensusMsg>,
        deadline: Instant,
    },

    /// Propose a transaction.
    HandleProposeTx {
        encrypted_tx: Arc<WellFormedEncryptedTx>,
        origin_node: Arc<NodeID>,
        deadline: Instant,
    },

    /// Request the worker thread to stop.
    StopTrigger,

    /// Debug helper: Set the atomic variable to one. This allows our tests
    /// to know all messaged submitted prior to this one have been processed.
    Barrier(Arc<AtomicBool>),
}

/// A single peer thread.
struct PeerThread {
    responder_id: ResponderId,
    sender: crossbeam_channel::Sender<ThreadMsg>,
    join_handle: Option<thread::JoinHandle<()>>,
}

impl PeerThread {
    pub fn new<CC: ConsensusConnection + 'static, RP: RetryPolicy>(
        conn: SyncConnection<CC>,
        retry_policy: &RP,
        logger: Logger,
    ) -> Self {
        let (sender, receiver) = crossbeam_channel::unbounded();

        let responder_id = conn.remote_responder_id();

        let retry_policy = retry_policy.clone();

        let join_handle = Some(
            thread::Builder::new()
                .name(format!("{}", conn))
                .spawn(move || {
                    Self::thread_entrypoint(conn, retry_policy, receiver, logger);
                })
                .expect("failed spawning peer thread"),
        );
        Self {
            responder_id,
            sender,
            join_handle,
        }
    }

    pub fn responder_id(&self) -> &ResponderId {
        &self.responder_id
    }

    pub fn send_consensus_msg(
        &self,
        msg: Arc<ConsensusMsg>,
        deadline: Instant,
    ) -> Result<(), Error> {
        self.sender
            .send(ThreadMsg::HandleConsensusMsg { msg, deadline })
            .map_err(|_err| Error::ChannelSend)
    }

    pub fn handle_propose_tx_msg(
        &self,
        encrypted_tx: Arc<WellFormedEncryptedTx>,
        origin_node: Arc<NodeID>,
        deadline: Instant,
    ) -> Result<(), Error> {
        self.sender
            .send(ThreadMsg::HandleProposeTx {
                encrypted_tx,
                origin_node,
                deadline,
            })
            .map_err(|_err| Error::ChannelSend)
    }

    /// Tests helper: wait until a barrier message is processed (indicating
    /// all previous messages were also processed).
    pub fn barrier(&self) {
        let atomic = Arc::new(AtomicBool::new(false));
        // Arbitrary number
        let deadline = Instant::now() + Duration::from_secs(10);

        self.sender
            .send(ThreadMsg::Barrier(atomic.clone()))
            .expect("failed sending barrier message");

        while Instant::now() < deadline {
            if atomic.load(Ordering::Relaxed) {
                return;
            }

            thread::sleep(Duration::from_millis(10));
        }

        panic!("timeout waiting for barrier!");
    }

    pub fn stop(&mut self) {
        if let Some(join_handle) = self.join_handle.take() {
            let _ = self.sender.send(ThreadMsg::StopTrigger);
            let _ = join_handle.join();
        }
    }

    fn thread_entrypoint<CC: ConsensusConnection + 'static, RP: RetryPolicy>(
        conn: SyncConnection<CC>,
        retry_policy: RP,
        receiver: crossbeam_channel::Receiver<ThreadMsg>,
        logger: Logger,
    ) {
        loop {
            match receiver.recv() {
                Ok(msg) => match msg {
                    ThreadMsg::HandleConsensusMsg { msg, deadline } => {
                        Self::do_send_consensus_msg(&conn, &retry_policy, msg, deadline, &logger)
                    }
                    ThreadMsg::HandleProposeTx {
                        encrypted_tx,
                        origin_node,
                        deadline,
                    } => Self::do_handle_propose_tx_msg(
                        &conn,
                        &retry_policy,
                        &encrypted_tx,
                        &origin_node,
                        deadline,
                        &logger,
                    ),
                    ThreadMsg::StopTrigger => {
                        break;
                    }
                    ThreadMsg::Barrier(barrier) => {
                        barrier.store(true, Ordering::Relaxed);
                    }
                },
                Err(err) => {
                    log::error!(logger, "Peer thread failed receiving: {:?}", err);
                    break;
                }
            }
        }
    }

    fn do_send_consensus_msg<CC: ConsensusConnection + 'static, RP: RetryPolicy>(
        conn: &SyncConnection<CC>,
        retry_policy: &RP,
        arc_msg: Arc<ConsensusMsg>,
        deadline: Instant,
        logger: &Logger,
    ) {
        if Instant::now() > deadline {
            return;
        }

        let retry_iterator = retry_policy.get_delay_iterator().with_deadline(deadline);

        match conn.send_consensus_msg(&*arc_msg, retry_iterator) {
            Ok(resp) => match resp.get_result() {
                ConsensusMsgResult::Ok => {}
                ConsensusMsgResult::UnknownPeer => log::info!(
                    logger,
                    "Peer {}: does not accept broadcast messages from unknown peers",
                    conn
                ),
            },
            Err(err) => {
                log::error!(
                    logger,
                    "failed broadcasting send consensus msg to {}: {:?}",
                    conn,
                    err
                );
            }
        }
    }

    fn do_handle_propose_tx_msg<CC: ConsensusConnection + 'static, RP: RetryPolicy>(
        conn: &SyncConnection<CC>,
        retry_policy: &RP,
        encrypted_tx: &WellFormedEncryptedTx,
        origin_node: &NodeID,
        deadline: Instant,
        logger: &Logger,
    ) {
        if Instant::now() > deadline {
            return;
        }

        let retry_iterator = retry_policy.get_delay_iterator().with_deadline(deadline);

        if let Err(err) = conn.send_propose_tx(encrypted_tx, origin_node, retry_iterator) {
            log::error!(
                logger,
                "failed broadcasting propose tx to {}: {:?}",
                conn,
                err
            );
        }
    }
}
