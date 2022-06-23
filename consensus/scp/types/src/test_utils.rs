// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Utilities for SCP tests.

use crate::QuorumSet;
use alloc::vec;
use core::str::FromStr;
use mc_common::{NodeID, ResponderId};
use mc_crypto_keys::Ed25519Pair;
use mc_util_from_random::FromRandom;
use mc_util_test_helper::SeedableRng;
use rand_hc::Hc128Rng as FixedRng;

/// Creates NodeID from integer for testing.
pub fn test_node_id(node_id: u32) -> NodeID {
    test_node_id_and_signer(node_id).0
}

/// Creates NodeID and Signer keypair from integer for testing.
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

/// Three nodes that form a three-node cycle.
///
/// * Node 1 has the quorum slice {1,2}, where {2} is a blocking set.
/// * Node 2 has the quorum slice {2,3}, where {3} is a blocking set.
/// * Node 3 has the quorum slice {1,3}, where {1} is a blocking set.
/// * The only quorum is the set of all three nodes {1, 2, 3}.
pub fn three_node_cycle() -> (
    (NodeID, QuorumSet),
    (NodeID, QuorumSet),
    (NodeID, QuorumSet),
) {
    let node_1 = (
        test_node_id(1),
        QuorumSet::new_with_node_ids(1, vec![test_node_id(2)]),
    );
    let node_2 = (
        test_node_id(2),
        QuorumSet::new_with_node_ids(1, vec![test_node_id(3)]),
    );
    let node_3 = (
        test_node_id(3),
        QuorumSet::new_with_node_ids(1, vec![test_node_id(1)]),
    );
    (node_1, node_2, node_3)
}

/// The four-node network from Fig. 2 of the [Stellar Whitepaper](https://www.stellar.org/papers/stellar-consensus-protocol).
///
/// * Node 1 has the quorum slice {1,2,3}, where {2}, {3}, {2,3} are blocking
///   sets.
/// * Nodes 2,3, and 4 have the quorum slice {2,3,4}.
/// * The only quorum is the set of all nodes {1,2,3,4}.
pub fn fig_2_network() -> (
    (NodeID, QuorumSet),
    (NodeID, QuorumSet),
    (NodeID, QuorumSet),
    (NodeID, QuorumSet),
) {
    let node_1 = (
        test_node_id(1),
        QuorumSet::new_with_node_ids(2, vec![test_node_id(2), test_node_id(3)]),
    );
    let node_2 = (
        test_node_id(2),
        QuorumSet::new_with_node_ids(2, vec![test_node_id(3), test_node_id(4)]),
    );
    let node_3 = (
        test_node_id(3),
        QuorumSet::new_with_node_ids(2, vec![test_node_id(2), test_node_id(4)]),
    );
    let node_4 = (
        test_node_id(4),
        QuorumSet::new_with_node_ids(2, vec![test_node_id(2), test_node_id(4)]),
    );

    (node_1, node_2, node_3, node_4)
}

/// A three-node network where the only quorum is the set of all three nodes.
/// Each node is a blocking set for each other.
pub fn three_node_dense_graph() -> (
    (NodeID, QuorumSet),
    (NodeID, QuorumSet),
    (NodeID, QuorumSet),
) {
    let node_1 = (
        test_node_id(1),
        QuorumSet::new_with_node_ids(2, vec![test_node_id(2), test_node_id(3)]),
    );
    let node_2 = (
        test_node_id(2),
        QuorumSet::new_with_node_ids(2, vec![test_node_id(1), test_node_id(3)]),
    );
    let node_3 = (
        test_node_id(3),
        QuorumSet::new_with_node_ids(2, vec![test_node_id(1), test_node_id(2)]),
    );
    (node_1, node_2, node_3)
}
