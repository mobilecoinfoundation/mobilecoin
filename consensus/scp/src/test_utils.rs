// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Utilities for Stellar Consensus Protocol tests.
use crate::{core_types::Value, slot::Slot, QuorumSet, SlotIndex};
use mc_common::{logger::Logger, NodeID, ResponderId};
use mc_crypto_keys::Ed25519Pair;
use mc_util_from_random::FromRandom;
use rand::SeedableRng;
use rand_hc::Hc128Rng as FixedRng;
use std::{fmt, str::FromStr, sync::Arc};

/// Error for transaction validation
#[derive(Clone)]
pub struct TransactionValidationError;
impl fmt::Display for TransactionValidationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("TransactionValidationError")
    }
}

/// Returns Ok.
pub fn trivial_validity_fn<T: Value>(_value: &T) -> Result<(), TransactionValidationError> {
    Ok(())
}

/// Returns `values` in sorted order.
pub fn trivial_combine_fn<V: Value>(values: &[V]) -> Result<Vec<V>, TransactionValidationError> {
    let mut values_as_vec: Vec<V> = values.to_vec();
    values_as_vec.sort();
    values_as_vec.dedup();
    Ok(values_as_vec)
}

/// Returns at most the first `n` values.
#[allow(unused)]
pub fn get_bounded_combine_fn<V: Value>(
    max_elements: usize,
) -> impl Fn(&[V]) -> Result<Vec<V>, TransactionValidationError> {
    move |values: &[V]| -> Result<Vec<V>, TransactionValidationError> {
        trivial_combine_fn(values).map(|mut combined| {
            combined.truncate(max_elements);
            combined
        })
    }
}

/// Creates NodeID from integer for testing.
pub fn test_node_id(node_id: u32) -> NodeID {
    let (node_id, _signer) = test_node_id_and_signer(node_id);
    node_id
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

/// Creates a new slot.
pub fn get_slot(
    slot_index: SlotIndex,
    node_id: &NodeID,
    quorum_set: &QuorumSet,
    logger: Logger,
) -> Slot<u32, TransactionValidationError> {
    Slot::<u32, TransactionValidationError>::new(
        node_id.clone(),
        quorum_set.clone(),
        slot_index,
        Arc::new(trivial_validity_fn),
        Arc::new(trivial_combine_fn),
        logger,
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
