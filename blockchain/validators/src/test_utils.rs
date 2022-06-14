// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Test helpers.

use mc_blockchain_test_utils::{make_block_id, make_block_metadata_contents};
use mc_blockchain_types::BlockMetadata;
use mc_crypto_keys::{Ed25519Pair, Ed25519Public};
use mc_util_from_random::FromRandom;
use mc_util_test_helper::{RngType as FixedRng, SeedableRng};

pub fn make_key(seed: u64) -> Ed25519Public {
    *make_metadata(seed).node_key()
}

pub fn make_metadata(seed: u64) -> BlockMetadata {
    let seed_bytes = seed.to_be_bytes();
    let mut seed = [0u8; 32];
    seed[0..seed_bytes.len()].copy_from_slice(&seed_bytes);
    let mut rng = FixedRng::from_seed(seed);

    let signer = Ed25519Pair::from_random(&mut rng);

    BlockMetadata::from_contents_and_keypair(
        make_block_metadata_contents(make_block_id(&mut rng), &mut rng),
        &signer,
    )
    .expect("BlockMetadata::from_contents_and_keypair")
}
