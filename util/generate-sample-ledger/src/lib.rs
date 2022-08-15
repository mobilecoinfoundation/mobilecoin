// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Generates a bootstrapped ledger for testing purposes

#![deny(missing_docs)]

use mc_account_keys::PublicAddress;
use mc_blockchain_test_utils::get_blocks_with_recipients;
use mc_common::logger::{log, Logger};
use mc_ledger_db::{Ledger, LedgerDB};
use mc_transaction_core::{
    constants::TOTAL_MOB, mint::MintTx as CoreMintTx, BlockVersion, TokenId,
};
use mc_transaction_core_test_utils::{create_mint_config_tx_and_signers, create_mint_tx};
use rand::SeedableRng;
use rand_hc::Hc128Rng as FixedRng;
use std::path::Path;

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

    log::info!(
        logger,
        "Making {} outputs of {} picoMOB across {} recipients ({} outputs per recipient, {} tokens, {} blocks).",
        num_outputs,
        picomob_per_output,
        recipients.len(),
        outputs_per_recipient_per_block,
        max_token_id + 1,
        num_blocks
    );

    let block_version = if max_token_id > 0 {
        BlockVersion::THREE
    } else {
        // This is historically the version created by bootstrap
        BlockVersion::ZERO
    };

    let mut rng = FixedRng::from_seed(seed.unwrap_or([33u8; 32]));

    let blocks = get_blocks_with_recipients(
        block_version,
        num_blocks,
        recipients,
        max_token_id + 1,
        outputs_per_recipient_per_block,
        picomob_per_output,
        None,
        &mut rng,
    );

    for block_data in blocks {
        db.append_block_data(&block_data).unwrap_or_else(|err| {
            let block = block_data.block();
            panic!(
                "Failed to add block with index {} and ID {}: {}",
                block.index, block.id, err
            )
        });
    }

    log::info!(logger, "Wrote LedgerDB to {:?}", path);

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

pub fn bootstrap_mints_burns(
    path: &Path,
    burn_amount: u64,
    burn_tx_count: u16,
    mint_amount: u64,
    mint_tx_count: u16,
    seed: Option<[u8; 32]>,
    logger: Logger,
) {
    let mut db = LedgerDB::open(path).expect("Could not open ledger_db");
    let conn = db.get_conn().unwrap();

    // generate mint config // not sure if this is still needed
    let max_mintable = if (mint_amount <= TOTAL_MOB) {
        TOTAL_MOB
    } else {
        mint_amount
    };

    let mut rng = mc_util_test_helper::get_seeded_rnt();

    // create the core mint and mint configs
    let token_id = TokenId::from(1);
    let (_mint_config_tx, signers) = create_mint_config_tx_and_signers(token_id1, &mut rng);
    let mint_tx1 = create_mint_tx(token_id, &signers, 100, &mut rng);

    let mut mint_txs = Vec<MintTx>::with_capacity(100);

    // for 100 records
    for i in 0..100 {
        // create the core mint and mint configs
        let token_id = TokenId::from(i+1);
        let (_mint_config_tx, signers) = create_mint_config_tx_and_signers(token_id, &mut rng);
        mint_txs[i] = create_mint_tx(token_id, &signers, 100, &mut rng);

        // store record in db
        MintTx::insert_from_core_mint_tx(5, None, &mint_tx1, &conn).unwrap();
    }

    // store the mints
    // MintTx::insert_from_core_mint_tx(5, None, &mint_tx1, &conn).unwrap();

    // iterate through mint_tx_count, creating gnosis safe deposits and mint
    // transactions

    // iterate through burn_tx_count, creating burn txos and gnosis safe
    // withdrawals
}
