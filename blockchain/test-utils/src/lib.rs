// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Helpers for block-related tests.
#![deny(missing_docs)]

pub use mc_consensus_scp_types::test_utils::test_node_id;

use mc_blockchain_types::{
    BlockID, BlockMetadata, BlockMetadataContents, QuorumSet, VerificationReport,
};
use mc_crypto_keys::Ed25519Pair;
use mc_util_from_random::FromRandom;
use mc_util_test_helper::{random_bytes_vec, CryptoRng, Rng, RngCore};

/// Generate a [BlockID] from random bytes.
pub fn make_block_id(rng: &mut (impl RngCore + CryptoRng)) -> BlockID {
    BlockID(FromRandom::from_random(rng))
}

/// Generate a [QuorumSet] with the specified number of randomly generated node
/// IDs.
pub fn make_quorum_set_with_count(
    num_nodes: u32,
    rng: &mut (impl RngCore + CryptoRng),
) -> QuorumSet {
    let threshold = rng.gen_range(1..=num_nodes);
    let node_ids = (0..num_nodes).map(test_node_id).collect();
    QuorumSet::new_with_node_ids(threshold, node_ids)
}

/// Generate a [QuorumSet] with a random number of randomly generated node IDs.
pub fn make_quorum_set(rng: &mut (impl RngCore + CryptoRng)) -> QuorumSet {
    make_quorum_set_with_count(rng.gen_range(1..=42), rng)
}

/// Generate a [VerificationReport] from random bytes.
pub fn make_verification_report(rng: &mut (impl RngCore + CryptoRng)) -> VerificationReport {
    let sig = random_bytes_vec(42, rng).into();
    let chain_len = rng.gen_range(2..42);
    let chain = (1..=chain_len)
        .map(|n| random_bytes_vec(n as usize, rng))
        .collect();
    VerificationReport {
        sig,
        chain,
        http_body: "testing".to_owned(),
    }
}

/// Generate a [BlockMetadataContents] for the given block ID, and otherwise
/// random contents.
pub fn make_block_metadata_contents(
    block_id: BlockID,
    rng: &mut (impl RngCore + CryptoRng),
) -> BlockMetadataContents {
    BlockMetadataContents::new(
        block_id,
        make_quorum_set(rng),
        make_verification_report(rng),
    )
}

/// Generate a [BlockMetadata] for the given block ID, and otherwise random
/// contents.
pub fn make_block_metadata(
    block_id: BlockID,
    rng: &mut (impl RngCore + CryptoRng),
) -> BlockMetadata {
    let signer = Ed25519Pair::from_random(rng);
    let metadata = make_block_metadata_contents(block_id, rng);
    BlockMetadata::from_contents_and_keypair(metadata, &signer)
        .expect("BlockMetadata::from_contents_and_keypair")
}
