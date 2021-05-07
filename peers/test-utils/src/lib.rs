// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Mock Peer test utilities

use mc_common::{NodeID, ResponderId};
use mc_connection::{
    BlockInfo, BlockchainConnection, Connection, Error as ConnectionError,
    Result as ConnectionResult,
};
use mc_consensus_api::consensus_peer::{ConsensusMsgResponse, ConsensusMsgResult};
use mc_consensus_enclave_api::{TxContext, WellFormedEncryptedTx};
use mc_consensus_scp::{
    msg::{Msg, NominatePayload},
    quorum_set::QuorumSet,
    SlotIndex, Topic,
};
use mc_crypto_keys::Ed25519Pair;
use mc_ledger_db::{test_utils::mock_ledger::MockLedger, Ledger};
use mc_peers::{ConsensusConnection, ConsensusMsg, Error as PeerError, Result as PeerResult};
use mc_transaction_core::{tx::TxHash, Block, BlockID, BlockIndex};
use mc_util_from_random::FromRandom;
use mc_util_uri::{ConnectionUri, ConsensusPeerUri as PeerUri};
use rand::SeedableRng;
use rand_hc::Hc128Rng as FixedRng;
use sha2::{digest::Digest, Sha512Trunc256};
use std::{
    cmp::{min, Ordering},
    collections::{BTreeSet, VecDeque},
    convert::TryFrom,
    fmt::{Display, Formatter, Result as FmtResult},
    hash::{Hash, Hasher},
    ops::Range,
    str::FromStr,
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

#[derive(Clone, Default)]
pub struct MockPeerState {
    /// Messages broadcast to this peer
    pub msgs: VecDeque<ConsensusMsg>,

    /// Number of times send_consensus_msg was called.
    pub send_consensus_msg_call_count: usize,

    /// Number of times to return an error code when send_consensus_msg is
    /// called.
    pub send_consensus_msg_should_error_count: usize,
}

/// MockPeerConnection simulates a network-connected peer and adds a
/// configurable amount of latency to each request.
#[derive(Clone)]
pub struct MockPeerConnection<L: Ledger + Sync = MockLedger> {
    pub uri: PeerUri,
    pub local_node_id: NodeID,
    pub ledger: L,
    pub latency_millis: u64,
    pub state: Arc<Mutex<MockPeerState>>,
}

impl<L: Ledger + Sync> MockPeerConnection<L> {
    /// Creates a Test Peer.
    ///
    /// # Arguments
    /// * `uri` - URI of mock peer.
    /// * `local_node_id` - The local node id.
    /// * `ledger` - This peer's ledger.
    /// * `latency_millis` - Additional latency added to requests to this peer.
    pub fn new(uri: PeerUri, local_node_id: NodeID, ledger: L, latency_millis: u64) -> Self {
        MockPeerConnection {
            uri,
            local_node_id,
            ledger,
            latency_millis,
            state: Arc::new(Mutex::new(MockPeerState::default())),
        }
    }

    pub fn state(&self) -> MockPeerState {
        self.state.lock().expect("mutex poisoined").clone()
    }

    pub fn msgs(&self) -> Vec<ConsensusMsg> {
        self.state
            .lock()
            .expect("mutex poisoned")
            .msgs
            .iter()
            .cloned()
            .collect()
    }

    pub fn reset_call_count(&mut self) {
        self.state
            .lock()
            .expect("mutex poisoned")
            .send_consensus_msg_call_count = 0;
    }

    pub fn set_send_consensus_msg_should_error_count(&mut self, val: usize) {
        self.state
            .lock()
            .expect("mutex poisoned")
            .send_consensus_msg_should_error_count = val;
    }
}

impl<L: Ledger + Sync> Display for MockPeerConnection<L> {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "{}", self.uri)
    }
}

impl<L: Ledger + Sync> Eq for MockPeerConnection<L> {}

impl<L: Ledger + Sync> Hash for MockPeerConnection<L> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.uri.addr().hash(state);
    }
}

impl<L: Ledger + Sync> Ord for MockPeerConnection<L> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.uri.addr().cmp(&other.uri.addr())
    }
}

impl<L: Ledger + Sync> PartialEq for MockPeerConnection<L> {
    fn eq(&self, other: &MockPeerConnection<L>) -> bool {
        self.uri.addr() == other.uri.addr()
    }
}

impl<L: Ledger + Sync> PartialOrd for MockPeerConnection<L> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.uri.addr().partial_cmp(&other.uri.addr())
    }
}

impl<L: Ledger + Sync> Connection for MockPeerConnection<L> {
    type Uri = PeerUri;

    fn uri(&self) -> Self::Uri {
        self.uri.clone()
    }
}

impl<L: Ledger + Sync> BlockchainConnection for MockPeerConnection<L> {
    fn fetch_blocks(&mut self, range: Range<u64>) -> ConnectionResult<Vec<Block>> {
        thread::sleep(Duration::from_millis(self.latency_millis));

        let mut real_range = range;

        if real_range.start >= self.ledger.num_blocks().unwrap() {
            return Err(ConnectionError::NotFound);
        }

        real_range.end = min(real_range.end, self.ledger.num_blocks().unwrap());

        // Ledger-type blocks.
        real_range
            .map(|block_index| self.ledger.get_block(block_index))
            .collect::<Result<Vec<Block>, _>>()
            .or(Err(ConnectionError::NotFound))
    }

    fn fetch_block_ids(&mut self, _range: Range<BlockIndex>) -> ConnectionResult<Vec<BlockID>> {
        unimplemented!()
    }

    fn fetch_block_height(&mut self) -> ConnectionResult<BlockIndex> {
        unimplemented!()
    }

    fn fetch_block_info(&mut self) -> ConnectionResult<BlockInfo> {
        unimplemented!()
    }
}

impl<L: Ledger + Sync> ConsensusConnection for MockPeerConnection<L> {
    fn remote_responder_id(&self) -> ResponderId {
        self.uri.responder_id().unwrap_or_else(|_| {
            panic!("Could not get responder ID from {:?}", self.uri.to_string())
        })
    }

    fn local_node_id(&self) -> NodeID {
        self.local_node_id.clone()
    }

    fn send_consensus_msg(&mut self, msg: &ConsensusMsg) -> PeerResult<ConsensusMsgResponse> {
        let mut locked_state = self.state.lock().expect("Locked poisoned");
        locked_state.send_consensus_msg_call_count += 1;
        if locked_state.send_consensus_msg_should_error_count > 0 {
            locked_state.send_consensus_msg_should_error_count -= 1;
            return Err(PeerError::Grpc(grpcio::Error::RemoteStopped));
        }

        locked_state.msgs.push_back(msg.clone());
        let mut resp = ConsensusMsgResponse::new();
        resp.set_result(ConsensusMsgResult::Ok);
        Ok(resp)
    }

    fn send_propose_tx(
        &mut self,
        _encrypted_tx: &WellFormedEncryptedTx,
        _origin_node: &NodeID,
    ) -> PeerResult<()> {
        unimplemented!()
    }

    fn fetch_txs(&mut self, _hashes: &[TxHash]) -> PeerResult<Vec<TxContext>> {
        unimplemented!()
    }

    fn fetch_latest_msg(&mut self) -> PeerResult<Option<ConsensusMsg>> {
        unimplemented!()
    }
}
pub fn create_consensus_msg(
    ledger: &impl Ledger,
    sender_id: NodeID,
    quorum_set: QuorumSet,
    slot_index: SlotIndex,
    msg: &str,
    signer_key: &Ed25519Pair,
) -> ConsensusMsg {
    let msg_hash = TxHash::try_from(Sha512Trunc256::digest(msg.as_bytes()).as_slice())
        .expect("Could not hash message into TxHash");
    let mut payload = NominatePayload {
        X: BTreeSet::default(),
        Y: BTreeSet::default(),
    };

    payload.X.insert(msg_hash);
    let topic = Topic::Nominate(payload);
    let scp_msg = Msg::new(sender_id, quorum_set, slot_index, topic);
    ConsensusMsg::from_scp_msg(ledger, scp_msg, signer_key)
        .expect("Could not create consensus message")
}

pub fn test_node_id(node_id: u32) -> NodeID {
    let (node_id, _signer) = test_node_id_and_signer(node_id);
    node_id
}

pub fn test_node_id_and_signer(node_id: u32) -> (NodeID, Ed25519Pair) {
    let mut seed_bytes = [0u8; 32];
    let node_id_bytes = node_id.to_be_bytes();
    seed_bytes[..node_id_bytes.len()].copy_from_slice(&node_id_bytes[..]);

    let mut seeded_rng: FixedRng = SeedableRng::from_seed(seed_bytes);
    let signer_keypair = Ed25519Pair::from_random(&mut seeded_rng);
    (
        NodeID {
            responder_id: ResponderId::from_str(&format!("node{}.test.com:8443", node_id)).unwrap(),
            public_key: signer_keypair.public_key(),
        },
        signer_keypair,
    )
}

pub fn test_peer_uri(node_id_int: u32) -> PeerUri {
    let (_node_id, signer_keypair) = test_node_id_and_signer(node_id_int);

    PeerUri::from_str(&format!(
        "mcp://node{}.test.com?consensus-msg-key={}",
        node_id_int,
        hex::encode(signer_keypair.public_key()),
    ))
    .expect("Could not construct peer URI from string")
}

#[cfg(test)]
mod peer_manager_tests {
    use super::*;
    use mc_common::logger::{test_with_logger, Logger};
    use mc_connection::ConnectionManager;
    use mc_ledger_db::test_utils::get_mock_ledger;
    use mc_peers::RetryableConsensusConnection;
    use retry::delay::Fibonacci;

    #[test]
    // Mock peer should return the correct range of blocks.
    fn mock_peer_fetch_blocks() {
        let (local_node_id, _) = test_node_id_and_signer(1);
        let mock_ledger = get_mock_ledger(25);
        assert_eq!(mock_ledger.lock().blocks_by_block_number.len(), 25);
        let mut mock_peer =
            MockPeerConnection::new(test_peer_uri(123), local_node_id, mock_ledger, 50);

        {
            // Get a subset of the peer's blocks.
            let blocks = mock_peer.fetch_blocks(0..10).unwrap();
            assert_eq!(blocks.len(), 10)
        }

        {
            // Get blocks 4,5,6,7,8,9.
            let blocks = mock_peer.fetch_blocks(4..10).unwrap();
            assert_eq!(blocks.len(), 6)
        }

        {
            // Get blocks 25,26,27. These are entirely out of range, so should return an
            // error.
            if let Ok(blocks) = mock_peer.fetch_blocks(25..28) {
                println!("Blocks: {:?}", blocks);
                panic!();
            }
        }

        {
            // Get blocks 20,21,..,29. Should return 20..24
            match mock_peer.fetch_blocks(20..30) {
                Ok(blocks) => {
                    assert_eq!(blocks.len(), 5);
                }
                _ => {
                    panic!("didn't fail as expected");
                }
            }
        }
    }

    #[test_with_logger]
    // Calling send_consensus_msg should be retried
    fn send_consensus_msg_retries(logger: Logger) {
        let peer_uri = test_peer_uri(1111);
        let node = NodeID::from(&peer_uri);
        let (local_node_id, _) = test_node_id_and_signer(3333);

        let quorum_set = QuorumSet::new_with_node_ids(1, vec![node]);
        let ledger = get_mock_ledger(1);
        let mut seeded_rng: FixedRng = SeedableRng::from_seed([1u8; 32]);
        let local_signer_key = Ed25519Pair::from_random(&mut seeded_rng);
        let msg = create_consensus_msg(
            &ledger,
            local_node_id.clone(),
            quorum_set,
            1,
            "test-msg-for-retries",
            &local_signer_key,
        );
        let mut peer = MockPeerConnection::new(peer_uri.clone(), local_node_id, ledger, 0);

        // Configure peer to fail many times - we should see 8 attempts
        // (number is hardcoded in `get_retry_iterator`.
        peer.set_send_consensus_msg_should_error_count(100);

        let peer_manager = ConnectionManager::new(vec![peer.clone()], logger);

        // Perform the actual test.
        let ret = peer_manager
            .conn(
                &peer_uri
                    .responder_id()
                    .expect("failed getting responder_id from peer_uri"),
            )
            .expect("failed getting peer conn")
            .send_consensus_msg(&msg, Fibonacci::from_millis(10).take(7));

        match ret {
            Ok(_) => panic!("should've failed"),
            Err(retry::Error::Operation { .. }) => {
                // This is expected
            }
            Err(e) => {
                panic!("got unexpected error {:?}", e);
            }
        };

        assert_eq!(peer.state().send_consensus_msg_call_count, 8);

        // Try again, this time we should succeed after 4 failures.
        peer.reset_call_count();
        peer.set_send_consensus_msg_should_error_count(4);

        let ret = peer_manager
            .conn(
                &peer_uri
                    .responder_id()
                    .expect("Failed getting responder_id from peer_uri"),
            )
            .expect("failed getting peer conn")
            .send_consensus_msg(&msg, Fibonacci::from_millis(10).take(7));

        assert!(ret.is_ok());
        assert_eq!(peer.state().send_consensus_msg_call_count, 5);
    }
}

#[cfg(test)]
mod threaded_broadcaster_tests {
    use super::*;
    use mc_common::logger::{test_with_logger, Logger};
    use mc_connection::ConnectionManager;
    use mc_consensus_scp::QuorumSet;
    use mc_ledger_db::test_utils::get_mock_ledger;
    use mc_peers::{
        Broadcast, ThreadedBroadcaster,
        ThreadedBroadcasterFibonacciRetryPolicy as FibonacciRetryPolicy,
        DEFAULT_RETRY_MAX_ATTEMPTS,
    };

    #[test_with_logger]
    // A message from a local node (who is not in the peers list) should be
    // broadcasted to all peers exactly once. A different message should also be
    // broadcasted exactly once.
    fn test_local_broadcast(logger: Logger) {
        let (local_node_id, _) = test_node_id_and_signer(1);
        let node2_uri = test_peer_uri(2);
        let node2 = NodeID::from(&node2_uri);
        let node3_uri = test_peer_uri(3);
        let node3 = NodeID::from(&node3_uri);

        let quorum_set = QuorumSet::new_with_node_ids(2, vec![node2, node3]);
        let ledger = get_mock_ledger(1);
        let peer2 = MockPeerConnection::new(node2_uri, local_node_id.clone(), ledger.clone(), 0);
        let peer3 = MockPeerConnection::new(node3_uri, local_node_id.clone(), ledger.clone(), 0);

        let peer_manager =
            ConnectionManager::new(vec![peer2.clone(), peer3.clone()], logger.clone());

        let mut broadcaster = ThreadedBroadcaster::new(
            &peer_manager,
            &FibonacciRetryPolicy::default(),
            logger.clone(),
        );

        // Initially, nothing is broadcasted to either of our nodes.
        {
            assert!(peer2.msgs().is_empty());
            assert!(peer3.msgs().is_empty());
        }

        let mut seeded_rng: FixedRng = SeedableRng::from_seed([1u8; 32]);
        let local_signer_key = Ed25519Pair::from_random(&mut seeded_rng);
        // Broadcast the first message three times, it should only appear once per peer.
        {
            let msg1 = create_consensus_msg(
                &ledger,
                local_node_id.clone(),
                quorum_set.clone(),
                1,
                "msg1",
                &local_signer_key,
            );

            broadcaster.broadcast_consensus_msg(&msg1, &msg1.issuer_responder_id());
            broadcaster.broadcast_consensus_msg(&msg1, &msg1.issuer_responder_id());
            broadcaster.broadcast_consensus_msg(&msg1, &msg1.issuer_responder_id());

            broadcaster.barrier();

            // Each peer should have received message exactly once.
            assert_eq!(peer2.msgs().len(), 1);
            assert_eq!(peer2.msgs()[0], msg1);

            assert_eq!(peer3.msgs().len(), 1);
            assert_eq!(peer3.msgs()[0], msg1);
        }

        // Broadcast a different message, it should only appear once per peer.
        {
            let msg2 = create_consensus_msg(
                &ledger,
                local_node_id,
                quorum_set,
                1,
                "msg2",
                &local_signer_key,
            );

            broadcaster.broadcast_consensus_msg(&msg2, &msg2.issuer_responder_id());
            broadcaster.broadcast_consensus_msg(&msg2, &msg2.issuer_responder_id());
            broadcaster.broadcast_consensus_msg(&msg2, &msg2.issuer_responder_id());

            broadcaster.barrier();

            // Each peer should have received message exactly once.
            assert_eq!(peer2.msgs().len(), 2);
            assert_eq!(peer2.msgs()[1], msg2);

            assert_eq!(peer3.msgs().len(), 2);
            assert_eq!(peer3.msgs()[1], msg2);
        }
    }

    #[test_with_logger]
    // A message from a peer should be broadcasted only to other peers, but not to
    // the peer who sent it.
    fn test_relay_broadcast(logger: Logger) {
        let (local_node_id, _) = test_node_id_and_signer(100);
        let node1_uri = test_peer_uri(1);
        let node1 = NodeID::from(&node1_uri);
        let node2_uri = test_peer_uri(2);
        let node2 = NodeID::from(&node2_uri);
        let node3_uri = test_peer_uri(3);
        let node3 = NodeID::from(&node3_uri);

        let ledger = get_mock_ledger(10);
        let quorum_set = QuorumSet::new_with_node_ids(3, vec![node1, node2.clone(), node3]);

        let peer1 = MockPeerConnection::new(node1_uri, local_node_id.clone(), ledger.clone(), 0);
        let peer2 = MockPeerConnection::new(node2_uri, local_node_id.clone(), ledger.clone(), 0);
        let peer3 = MockPeerConnection::new(node3_uri, local_node_id, ledger.clone(), 0);

        let peer_manager = ConnectionManager::new(
            vec![peer1.clone(), peer2.clone(), peer3.clone()],
            logger.clone(),
        );

        let mut broadcaster = ThreadedBroadcaster::new(
            &peer_manager,
            &FibonacciRetryPolicy::default(),
            logger.clone(),
        );

        // Initially, nothing is broadcasted to either of our nodes.
        {
            assert!(peer1.msgs().is_empty());
            assert!(peer2.msgs().is_empty());
            assert!(peer3.msgs().is_empty());
        }

        let mut seeded_rng: FixedRng = SeedableRng::from_seed([1u8; 32]);
        let node2_signer_key = Ed25519Pair::from_random(&mut seeded_rng);

        // A message from node2 should go to node1 and node3.
        {
            let msg1 = create_consensus_msg(
                &ledger,
                node2.clone(),
                quorum_set.clone(),
                1,
                "msg1",
                &node2_signer_key,
            );

            broadcaster.broadcast_consensus_msg(&msg1, &msg1.issuer_responder_id());
            broadcaster.broadcast_consensus_msg(&msg1, &msg1.issuer_responder_id());
            broadcaster.broadcast_consensus_msg(&msg1, &msg1.issuer_responder_id());

            broadcaster.barrier();

            assert_eq!(peer1.msgs().len(), 1);
            assert_eq!(peer1.msgs()[0], msg1);

            assert_eq!(peer2.msgs().len(), 0);

            assert_eq!(peer3.msgs().len(), 1);
            assert_eq!(peer3.msgs()[0], msg1);
        }

        // A different message from node2 should go to node1 and node3.
        {
            let msg2 =
                create_consensus_msg(&ledger, node2, quorum_set, 1, "msg2", &node2_signer_key);

            broadcaster.broadcast_consensus_msg(&msg2, &msg2.issuer_responder_id());
            broadcaster.broadcast_consensus_msg(&msg2, &msg2.issuer_responder_id());
            broadcaster.broadcast_consensus_msg(&msg2, &msg2.issuer_responder_id());

            broadcaster.barrier();

            assert_eq!(peer1.msgs().len(), 2);
            assert_eq!(peer1.msgs()[1], msg2);

            assert_eq!(peer2.msgs().len(), 0);

            assert_eq!(peer3.msgs().len(), 2);
            assert_eq!(peer3.msgs()[1], msg2);
        }
    }

    // ThreadedBroadcaster should retry sending messages on failure.
    #[test_with_logger]
    fn test_retry(logger: Logger) {
        let (local_node_id, _) = test_node_id_and_signer(1);
        let node2_uri = test_peer_uri(2);
        let node2 = NodeID::from(&node2_uri);
        let node3_uri = test_peer_uri(3);
        let node3 = NodeID::from(&node3_uri);

        let ledger = get_mock_ledger(1);

        let quorum_set = QuorumSet::new_with_node_ids(1, vec![node2, node3]);
        let mut peer2 =
            MockPeerConnection::new(node2_uri, local_node_id.clone(), ledger.clone(), 0);
        let peer3 = MockPeerConnection::new(node3_uri, local_node_id.clone(), ledger.clone(), 0);

        let peer_manager =
            ConnectionManager::new(vec![peer2.clone(), peer3.clone()], logger.clone());

        let mut broadcaster = ThreadedBroadcaster::new(
            &peer_manager,
            FibonacciRetryPolicy::default().initial_delay(Duration::from_millis(10)),
            logger.clone(),
        );

        // Initially, nothing is broadcasted to either of our nodes.
        {
            assert!(peer2.msgs().is_empty());
            assert!(peer3.msgs().is_empty());
        }

        // Configure peer2 to fail a lot of times - we should see RETRY_MAX_ATTEMPTS
        // attempts made but no message delivered.
        peer2.set_send_consensus_msg_should_error_count(100);

        let mut seeded_rng: FixedRng = SeedableRng::from_seed([1u8; 32]);
        let local_signer_key = Ed25519Pair::from_random(&mut seeded_rng);

        // Broadcast the first message three times, it should only appear once per peer.
        {
            let msg1 = create_consensus_msg(
                &ledger,
                local_node_id.clone(),
                quorum_set.clone(),
                1,
                "msg1",
                &local_signer_key,
            );

            broadcaster.broadcast_consensus_msg(&msg1, &msg1.issuer_responder_id());
            broadcaster.broadcast_consensus_msg(&msg1, &msg1.issuer_responder_id());
            broadcaster.broadcast_consensus_msg(&msg1, &msg1.issuer_responder_id());

            broadcaster.barrier();

            // peer3 should have received no message, but RETRY_MAX_ATTEMPTS were made.
            assert_eq!(peer2.msgs().len(), 0);
            assert_eq!(
                peer2.state().send_consensus_msg_call_count,
                DEFAULT_RETRY_MAX_ATTEMPTS
            );

            // peer3 should have received message exactly once.
            assert_eq!(peer3.msgs().len(), 1);
            assert_eq!(peer3.msgs()[0], msg1);
            assert_eq!(peer3.state().send_consensus_msg_call_count, 1);
        }

        // Configure peer2 to fail after one attempt, we should see 2 calls made
        // and the message should arrive
        peer2.reset_call_count();
        peer2.set_send_consensus_msg_should_error_count(1);

        {
            let msg2 = create_consensus_msg(
                &ledger,
                local_node_id,
                quorum_set,
                1,
                "msg2",
                &local_signer_key,
            );

            broadcaster.broadcast_consensus_msg(&msg2, &msg2.issuer_responder_id());
            broadcaster.broadcast_consensus_msg(&msg2, &msg2.issuer_responder_id());
            broadcaster.broadcast_consensus_msg(&msg2, &msg2.issuer_responder_id());

            broadcaster.barrier();

            // Each peer should have received message exactly once.
            assert_eq!(peer2.msgs().len(), 1);
            assert_eq!(peer2.msgs()[0], msg2);
            assert_eq!(peer2.state().send_consensus_msg_call_count, 2);

            assert_eq!(peer3.msgs().len(), 2);
            assert_eq!(peer3.msgs()[1], msg2);
            assert_eq!(peer3.state().send_consensus_msg_call_count, 2);
        }
    }
}
