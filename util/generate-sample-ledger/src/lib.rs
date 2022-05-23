// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Generates a bootstrapped ledger for testing purposes

#![deny(missing_docs)]

use mc_account_keys::PublicAddress;
use mc_blockchain_types::{Block, BlockContents, BlockVersion};
use mc_common::logger::{log, Logger};
use mc_crypto_keys::RistrettoPrivate;
use mc_ledger_db::{Ledger, LedgerDB};
use mc_transaction_core::{
    constants::TOTAL_MOB,
    encrypted_fog_hint::{EncryptedFogHint, ENCRYPTED_FOG_HINT_LEN},
    ring_signature::KeyImage,
    tx::TxOut,
    Amount,
};
use mc_util_from_random::FromRandom;
use rand::{RngCore, SeedableRng};
use rand_hc::Hc128Rng as FixedRng;
use std::{path::Path, vec::Vec};

// This is historically the version created by bootstrap
const BLOCK_VERSION: BlockVersion = BlockVersion::ZERO;

/// Deterministically populates a testnet ledger.
///
/// Distributes the full value of the ledger equally to each recipient.
///
/// # Arguments
/// * `path` - Opens a LedgerDB instance at the given path.
/// * `recipients` -
/// * `num_outputs_per_recipient` - Number of equal-valued outputs that each
///   recipient receives, per block.
/// * `num_blocks` - Number of blocks that will be created.
/// * `key_images_per_block` - Number of randomly generated key images per
///   block.
/// * `hint_text` - A string to be used as the hints for the outputs, as an
///   easter egg
/// * `max_token_id` - The maximum token id value to bootstrap a supply for. All
///   token ids will have the same bootstrapped supply.
///
/// This will panic if it attempts to distribute the total value of mobilecoin
/// into fewer than 16 outputs.
pub fn bootstrap_ledger(
    path: &Path,
    recipients: &[PublicAddress],
    outputs_per_recipient_per_block: usize,
    num_blocks: usize,
    key_images_per_block: usize,
    seed: Option<[u8; 32]>,
    hint_text: Option<&str>,
    max_token_id: u64,
    logger: Logger,
) {
    // Create the DB
    std::fs::create_dir_all(path).expect("Could not create ledger dir");
    LedgerDB::create(path).expect("Could not create ledger_db");
    let mut db = LedgerDB::open(path).expect("Could not open ledger_db");

    let num_outputs: u64 = (recipients.len()
        * outputs_per_recipient_per_block
        * num_blocks
        * (max_token_id as usize + 1)) as u64;
    assert!(num_outputs >= 16);

    let picomob_per_output: u64 = (TOTAL_MOB / num_outputs) * 1_000_000_000_000;

    log::info!(logger, "recipients: {}", recipients.len());
    log::info!(
        logger,
        "Making {:?} outputs of {:?} picoMOB.",
        num_outputs,
        picomob_per_output
    );

    let mut blocks_and_contents: Vec<(Block, BlockContents)> = Vec::new();
    let mut previous_block: Option<Block> = None;

    let mut rng: FixedRng = SeedableRng::from_seed(seed.unwrap_or([33u8; 32]));

    let block_version = if max_token_id > 0 {
        BlockVersion::TWO
    } else {
        BLOCK_VERSION
    };

    for block_index in 0..num_blocks as u64 {
        log::info!(logger, "Creating block {} of {}.", block_index, num_blocks);

        let mut outputs: Vec<TxOut> = Vec::new();
        for recipient in recipients {
            for _i in 0..outputs_per_recipient_per_block {
                // Create outputs of each token id in round-robin
                for token_id in 0..=max_token_id {
                    let amount = Amount {
                        value: picomob_per_output,
                        token_id: token_id.into(),
                    };
                    outputs.push(create_output(
                        recipient, amount, &mut rng, hint_text, &logger,
                    ));
                }
            }
        }

        // The origin block doesn't have any key images
        let key_images: Vec<KeyImage> = if previous_block.is_some() {
            (0..key_images_per_block)
                .map(|_i| KeyImage::from(rng.next_u64()))
                .collect()
        } else {
            Default::default()
        };

        let block_contents = BlockContents {
            key_images,
            outputs: outputs.clone(),
            ..Default::default()
        };

        let block = match previous_block {
            Some(parent) => {
                Block::new_with_parent(block_version, &parent, &Default::default(), &block_contents)
            }
            None => Block::new_origin_block(&outputs),
        };
        previous_block = Some(block.clone());
        blocks_and_contents.push((block, block_contents));
    }

    for (block, block_contents) in blocks_and_contents {
        // FIXME: Add metadata, too.
        db.append_block(&block, &block_contents, None, None)
            .unwrap();
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
           mc_util_build_info::git_commit(),
    ).expect("File I/O");
}

fn create_output(
    recipient: &PublicAddress,
    amount: Amount,
    rng: &mut FixedRng,
    hint_slice: Option<&str>,
    logger: &Logger,
) -> TxOut {
    let tx_private_key = RistrettoPrivate::from_random(rng);

    let hint = if let Some(hs) = hint_slice {
        let mut hint_buf = [1u8; ENCRYPTED_FOG_HINT_LEN];
        let hint_len = hs.as_bytes().len();
        if hint_len > 0 {
            let slice_len = std::cmp::min(hint_len, ENCRYPTED_FOG_HINT_LEN);
            hint_buf[..slice_len].copy_from_slice(&hs.as_bytes()[..slice_len]);
        }

        EncryptedFogHint::new(&hint_buf)
    } else {
        EncryptedFogHint::fake_onetime_hint(rng)
    };

    let output = TxOut::new(BLOCK_VERSION, amount, recipient, &tx_private_key, hint).unwrap();
    log::debug!(logger, "Creating output: {:?}", output);
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use mc_account_keys::{AccountKey, RootIdentity};
    use mc_common::logger::test_with_logger;
    use mc_transaction_core::{tokens::Mob, Token};
    use rand::{rngs::StdRng, SeedableRng};

    #[test_with_logger]
    fn test_arbitrary_hint_text(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([20u8; 32]);
        let mut fixed_rng: FixedRng = SeedableRng::from_seed([33u8; 32]);

        let amount = Amount {
            value: 10,
            token_id: Mob::ID,
        };

        let account_key = AccountKey::from(&RootIdentity::from_random(&mut rng));

        // Case with short hint text
        let hint_slice = "Vaccine 90% effective";
        let output = create_output(
            &account_key.subaddress(0),
            amount,
            &mut fixed_rng,
            Some(hint_slice),
            &logger,
        );
        let mut expected = [1u8; ENCRYPTED_FOG_HINT_LEN];
        expected[..hint_slice.as_bytes().len()].copy_from_slice(hint_slice.as_bytes());
        assert_eq!(output.e_fog_hint.to_bytes().to_vec(), expected.to_vec());

        // Case hint text longer than ENCRYPTED_FOG_HINT_LEN
        let hint_slice = "Covid-19 Vaccine 90% Up to 90% Effective in Late-Stage Trials - LONDON — the University of Oxford added their vaccine candidate to a growing list of shots showing promising effectiveness against Covid-19 — setting in motion disparate regulatory and distribution tracks that executives and researchers hope will result in the start of widespread vaccinations by the end of the year.";
        let output = create_output(
            &account_key.subaddress(0),
            amount,
            &mut fixed_rng,
            Some(hint_slice),
            &logger,
        );
        let mut expected = [1u8; ENCRYPTED_FOG_HINT_LEN];
        expected[..ENCRYPTED_FOG_HINT_LEN]
            .copy_from_slice(&hint_slice.as_bytes()[..ENCRYPTED_FOG_HINT_LEN]);
        assert_eq!(output.e_fog_hint.to_bytes().to_vec(), expected.to_vec());

        // Case with empty string as hint text
        let hint_slice = "";
        let output = create_output(
            &account_key.subaddress(0),
            amount,
            &mut fixed_rng,
            Some(hint_slice),
            &logger,
        );
        let expected = [1u8; ENCRYPTED_FOG_HINT_LEN];
        assert_eq!(output.e_fog_hint.to_bytes().to_vec(), expected.to_vec());
    }
}
