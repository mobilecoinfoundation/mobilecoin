// Copyright (c) 2018-2020 MobileCoin Inc.

use mc_account_keys::PublicAddress;
use mc_crypto_keys::RistrettoPrivate;
use mc_ledger_db::{Ledger, LedgerDB};
use mc_transaction_core::{
    constants::TOTAL_MOB, encrypted_fog_hint::EncryptedFogHint, ring_signature::KeyImage,
    tx::TxOut, Block, BlockContents, BLOCK_VERSION,
};
use mc_util_from_random::FromRandom;
use rand::{RngCore, SeedableRng};
use rand_hc::Hc128Rng as FixedRng;
use std::{path::PathBuf, vec::Vec};

/// Deterministically populates a testnet ledger.
///
/// Distributes the full value of the ledger equally to each recipient.
///
/// # Arguments
/// * `path` - Opens a LedgerDB instance at the given path.
/// * `recipients` -
/// * `num_outputs_per_recipient` - Number of equal-valued outputs that each recipient receives, per block.
/// * `num_blocks` - Number of blocks that will be created.
/// * `key_images_per_block` - Number of randomly generated key images per block.
///
/// This will panic if it attempts to distribute the total value of mobilecoin into fewer than 16 outputs.
pub fn bootstrap_ledger(
    path: &PathBuf,
    recipients: &[PublicAddress],
    outputs_per_recipient_per_block: usize,
    num_blocks: usize,
    key_images_per_block: usize,
    seed: Option<[u8; 32]>,
) {
    // Create the DB
    std::fs::create_dir_all(path.clone()).expect("Could not create ledger dir");
    LedgerDB::create(path.clone()).expect("Could not create ledger_db");
    let mut db = LedgerDB::open(path.clone()).expect("Could not open ledger_db");

    let num_outputs: u64 = (recipients.len() * outputs_per_recipient_per_block * num_blocks) as u64;
    let picomob_per_output: u64 = (TOTAL_MOB / num_outputs) * 1_000_000_000_000;

    println!("recipients: {}", recipients.len());
    println!(
        "Making {:?} outputs of {:?} picoMOB.",
        num_outputs, picomob_per_output
    );

    let mut blocks_and_contents: Vec<(Block, BlockContents)> = Vec::new();
    let mut previous_block: Option<Block> = None;

    let mut rng: FixedRng = SeedableRng::from_seed(seed.unwrap_or([33u8; 32]));

    for block_index in 0..num_blocks as u64 {
        println!("Creating block {} of {}.", block_index, num_blocks);

        let mut outputs: Vec<TxOut> = Vec::new();
        for recipient in recipients {
            for _i in 0..outputs_per_recipient_per_block {
                outputs.push(create_output(recipient, picomob_per_output, &mut rng));
            }
        }

        let key_images: Vec<KeyImage> = (0..key_images_per_block)
            .map(|_i| KeyImage::from(rng.next_u64()))
            .collect();

        let block_contents = BlockContents::new(key_images, outputs.clone());

        let block = match previous_block {
            Some(parent) => {
                Block::new_with_parent(BLOCK_VERSION, &parent, &Default::default(), &block_contents)
            }
            None => Block::new_origin_block(&outputs),
        };
        previous_block = Some(block.clone());
        blocks_and_contents.push((block, block_contents));
    }

    for (block, block_contents) in blocks_and_contents {
        db.append_block(&block, &block_contents, None).unwrap();
    }

    // Write conf.json
    let mut file = std::fs::File::create("conf.json").expect("File creation");
    use std::io::Write;
    write!(&mut file,
           r##"{{ "NUM_KEYS": {}, "NUM_UTXOS_PER_ACCOUNT": {}, "NUM_BLOCKS": {}, "NUM_EXTRA_KEY_IMAGES_PER_BLOCK": {}, "GIT_COMMIT": "{}" }}"##,
           recipients.len(),
           outputs_per_recipient_per_block,
           num_blocks,
           key_images_per_block,
           mc_util_build_info::GIT_COMMIT,
    ).expect("File I/O");
}

fn create_output(recipient: &PublicAddress, value: u64, rng: &mut FixedRng) -> TxOut {
    let tx_private_key = RistrettoPrivate::from_random(rng);
    let hint = EncryptedFogHint::fake_onetime_hint(rng);
    TxOut::new(value, recipient, &tx_private_key, hint, rng).unwrap()
}
