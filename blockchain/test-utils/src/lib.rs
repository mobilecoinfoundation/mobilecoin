// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Helpers for block-related tests.
#![deny(missing_docs)]

pub use mc_consensus_scp_types::test_utils::test_node_id;

use mc_blockchain_types::{
    Block, BlockContents, BlockData, BlockID, BlockMetadata, BlockMetadataContents, BlockSignature,
    BlockVersion, QuorumSet, VerificationReport,
};
use mc_crypto_keys::Ed25519Pair;
use mc_transaction_core_test_utils::{get_outputs, Amount, KeyImage};
use mc_util_from_random::FromRandom;
use mc_util_test_helper::{random_bytes_vec, AccountKey, CryptoRng, PublicAddress, Rng, RngCore};

/// Get blocks with custom contents to simulate conditions seen in production.
///
/// * `block_version`: the desired block version.
/// * `num_blocks`: total number of simulated blocks to create.
/// * `num_recipients`: number of randomly generated recipients.
/// * `num_tokens`: number of distinct token ids per block.
/// * `num_tx_outs_per_recipient_per_token_per_block`: number of outputs for
///   each token ID per recipient per block.
/// * `amount_per_tx_out`: amount per TxOut (per token per recipient per block).
/// * `prev_block`: Optional previous block; otherwise create an origin block.
/// * `rng`: A CSPRNG.
pub fn get_blocks<R: RngCore + CryptoRng>(
    block_version: BlockVersion,
    num_blocks: usize,
    num_recipients: usize,
    num_tokens: u64,
    num_tx_outs_per_recipient_per_token_per_block: usize,
    amount_per_tx_out: u64,
    prev_block: impl Into<Option<Block>>,
    rng: &mut R,
) -> Vec<BlockData> {
    let recipients = (0..num_recipients)
        .map(|_i| AccountKey::random(rng).default_subaddress())
        .collect::<Vec<_>>();
    get_blocks_with_recipients(
        block_version,
        num_blocks,
        &recipients,
        num_tokens,
        num_tx_outs_per_recipient_per_token_per_block,
        amount_per_tx_out,
        prev_block,
        rng,
    )
}

/// Get blocks with custom content in order to simulate conditions seen in
/// production
///
/// * `block_version`: the desired block version
/// * `num_blocks`: total number of simulated blocks to create
/// * `recipients`: recipients' public addresses
/// * `num_tokens`: number of distinct token ids per block
/// * `num_tx_outs_per_recipient_per_token_per_block`: number of outputs for
///   each token ID per recipient per block
/// * `prev_block`: Optional previous block; otherwise create an origin block.
/// * `rng`: A CSPRNG
pub fn get_blocks_with_recipients<R: RngCore + CryptoRng>(
    block_version: BlockVersion,
    num_blocks: usize,
    recipients: &[PublicAddress],
    num_tokens: u64,
    num_tx_outs_per_recipient_per_token_per_block: usize,
    amount_per_tx_out: u64,
    prev_block: impl Into<Option<Block>>,
    rng: &mut R,
) -> Vec<BlockData> {
    assert!(!recipients.is_empty());
    assert!(num_tokens > 0);
    assert!(num_tx_outs_per_recipient_per_token_per_block > 0);
    assert!(amount_per_tx_out > 0);
    assert!(block_version.mixed_transactions_are_supported() || num_tokens == 1);

    let mut blocks = Vec::with_capacity(num_blocks);
    let mut prev_block: Option<Block> = prev_block.into();

    for _ in 0..num_blocks {
        let mut recipient_and_amount = Vec::with_capacity(
            recipients.len() * num_tokens as usize * num_tx_outs_per_recipient_per_token_per_block,
        );
        for recipient in recipients {
            for _ in 0..num_tx_outs_per_recipient_per_token_per_block {
                // Create outputs for each token in round-robin
                for token_id in 0..num_tokens {
                    let amount = Amount::new(amount_per_tx_out, token_id.into());
                    recipient_and_amount.push((recipient.clone(), amount));
                }
            }
        }
        let outputs = get_outputs(block_version, &recipient_and_amount, rng);

        // Non-origin blocks must have at least one key image.
        let key_images = match &prev_block {
            Some(_) => vec![KeyImage::from(rng.next_u64())],
            None => vec![],
        };

        let block_contents = BlockContents {
            key_images,
            outputs,
            ..Default::default()
        };

        let block = match &prev_block {
            Some(parent) => {
                Block::new_with_parent(block_version, parent, &Default::default(), &block_contents)
            }
            None => Block::new_origin_block(&block_contents.outputs),
        };
        prev_block = Some(block.clone());

        let signature = make_block_signature(&block, rng);
        let metadata = make_block_metadata(block.id.clone(), rng);

        let block_data = BlockData::new(block, block_contents, signature, metadata);

        blocks.push(block_data);
    }
    blocks
}

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

/// Generate a [BlockSignature] for the given block ID, and otherwise random
/// contents.
pub fn make_block_signature<RNG: RngCore + CryptoRng>(
    block: &Block,
    rng: &mut RNG,
) -> BlockSignature {
    let signer = Ed25519Pair::from_random(rng);
    let mut signature = BlockSignature::from_block_and_keypair(block, &signer)
        .expect("Could not create block signature from keypair");
    signature.set_signed_at(block.index);
    signature
}

#[cfg(test)]
mod tests {
    use super::*;
    use mc_blockchain_types::compute_block_id;
    use mc_util_test_helper::get_seeded_rng;

    #[test]
    /// [get_blocks] should return blocks that match the configuration specified
    /// in the arguments and pass all normal consistency tests
    fn test_get_blocks_correctness() {
        let blocks = get_blocks(
            BlockVersion::MAX,
            4,
            3,
            2,
            1,
            42,
            None,
            &mut get_seeded_rng(),
        );

        // Ensure the correct amount of blocks have been created
        assert_eq!(blocks.len(), 4);

        // Ensure the origin block ID isn't a hash of another block
        let origin_block: &Block = blocks[0].block();
        assert_eq!(origin_block.parent_id.as_ref(), [0u8; 32]);
        assert_eq!(origin_block.index, 0);

        for block_data in blocks {
            let block = block_data.block();
            let contents = block_data.contents();

            // Ensure the block_id matches the id computed via the merlin transcript
            let derived_block_id = compute_block_id(
                block.version,
                &block.parent_id,
                block.index,
                block.cumulative_txo_count,
                &block.root_element,
                &block.contents_hash,
            );
            assert_eq!(derived_block_id, block.id);

            // Ensure stated block hash matches the computed hash
            assert_eq!(block.contents_hash, contents.hash());

            // Ensure the amount of transactions present matches expected amount
            assert_eq!(block.cumulative_txo_count, (block.index + 1) * 6);

            // Ensure the correct number of key images exist
            let num_key_images = if block.index == 0 { 0 } else { 1 };
            assert_eq!(contents.key_images.len(), num_key_images);
        }
    }
}
