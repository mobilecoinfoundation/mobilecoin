// Copyright (c) 2018-2020 MobileCoin Inc.

use curve25519_dalek::ristretto::RistrettoPoint;
use keys::{FromRandom, RistrettoPrivate};
use ledger_db::{Ledger, LedgerDB};
use rand::SeedableRng;
use rand_hc::Hc128Rng as FixedRng;
use rayon::prelude::*;
use std::{path::PathBuf, vec::Vec};
use transaction::{
    account_keys::PublicAddress, constants::TOTAL_MOB, encrypted_fog_hint::EncryptedFogHint,
    ring_signature::KeyImage, tx::TxOut, Block, RedactedTx, BLOCK_VERSION,
};

/// Deterministically populates a testnet ledger.
///
/// Distributes the full value of the ledger equally to each recipient.
///
/// # Arguments
/// * `path` - Opens a LedgerDB instance at the given path.
/// * `recipients` -
/// * `num_outputs_per_recipient` - Number of equal-valued outputs that each recipient receives, per block.
/// * `num_blocks` - Number of blocks that will be created.
///
/// This will panic if it attempts to distribute the total value of mobilecoin into fewer than 16 outputs.
pub fn bootstrap_ledger(
    path: &PathBuf,
    recipients: &[PublicAddress],
    num_txos_per_account: usize,
    num_blocks: usize,
    key_image_count: usize,
) {
    // Create the DB
    std::fs::create_dir_all(path.clone()).expect("Could not create ledger dir");
    LedgerDB::create(path.clone()).expect("Could not create ledger_db");
    let mut db = LedgerDB::open(path.clone()).expect("Could not open ledger_db");

    let num_outputs: u64 = (recipients.len() * num_txos_per_account * num_blocks) as u64;
    let picomob_per_output: u64 = (TOTAL_MOB / num_outputs) * 1_000_000_000_000;

    println!("recipients: {}", recipients.len());
    println!(
        "Making {:?} outputs of {:?} picoMOB.",
        num_outputs, picomob_per_output
    );

    let mut blocks_and_transactions: Vec<(Block, Vec<RedactedTx>)> = Vec::new();
    let mut previous_block: Option<Block> = None;

    for block_index in 0..num_blocks as u64 {
        println!("Creating block {} of {}.", block_index, num_blocks);

        // Transactions in this block.
        let minting_transactions: Vec<RedactedTx> = recipients
            .par_iter()
            .enumerate()
            .flat_map(|(recipient_index, recipient)| {
                // Create a uniquely seeded RNG for this block and recipient. This allows parallelization.
                let mut seed = [0u8; 32];
                seed[0..8].clone_from_slice(&(recipient_index as u64).to_le_bytes());
                seed[8..16].clone_from_slice(&(block_index as u64).to_le_bytes());
                let mut rng: FixedRng = SeedableRng::from_seed(seed);

                let redacted_transactions: Vec<RedactedTx> = (0..num_txos_per_account)
                    .map(|_i| {
                        create_minting_transaction(
                            recipient,
                            picomob_per_output,
                            key_image_count as u64,
                            &mut rng,
                        )
                    })
                    .collect();

                redacted_transactions
            })
            .collect();

        let block = match previous_block {
            Some(parent) => Block::new(
                BLOCK_VERSION,
                &parent.id,
                block_index,
                parent.cumulative_txo_count + minting_transactions.len() as u64,
                &Default::default(),
                &minting_transactions,
            ),
            None => Block::new_origin_block(&minting_transactions),
        };
        previous_block = Some(block.clone());
        blocks_and_transactions.push((block, minting_transactions));
    }

    for (block, redacted_transactions) in blocks_and_transactions {
        db.append_block(&block, &redacted_transactions, None)
            .unwrap();
    }

    // Write conf.json
    let mut file = std::fs::File::create("conf.json").expect("File creation");
    use std::io::Write;
    write!(&mut file,
        r##"{{ "NUM_KEYS": {}, "NUM_UTXOS_PER_ACCOUNT": {}, "NUM_BLOCKS": {}, "NUM_EXTRA_KEY_IMAGES_PER_BLOCK": {}, "GIT_COMMIT": "{}" }}"##,
        recipients.len(),
        num_txos_per_account,
        num_blocks,
        key_image_count,
        build_info::GIT_COMMIT,
    ).expect("File I/O");
}

/// Creates a Redacted Tx that outputs `amount` to a single `recipient`.
fn create_minting_transaction(
    recipient: &PublicAddress,
    amount: u64,
    num_key_images: u64,
    rng: &mut FixedRng,
) -> RedactedTx {
    let tx_private_key = RistrettoPrivate::from_random(rng);
    // TODO: Use the "minting" fog public key? See mobilecoin-internal/bootstrap
    let hint = EncryptedFogHint::fake_onetime_hint(rng);
    let tx_out = TxOut::new(amount, recipient, &tx_private_key, hint, rng).unwrap();

    // Generate random key images.
    let key_images: Vec<KeyImage> = (0..num_key_images)
        .map(|_i| KeyImage::from(RistrettoPoint::random(rng)))
        .collect();
    RedactedTx::new(vec![tx_out], key_images)
}
