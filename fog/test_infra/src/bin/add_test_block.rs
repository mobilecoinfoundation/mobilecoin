// Copyright (c) 2018-2022 The MobileCoin Foundation
#![deny(missing_docs)]

//! Add a block to the test ledger.
//! This is intended for fog conformance testing
//!
//! Assumes that there is already an origin block and keys.
//! Appends one block with new TxOuts and with specified key images burned.
//! Returns a list of key images corresponding to the freshly created TxOuts.
//!
//! Usage:
//! Command-line arguments:
//! - keys (path to keys directory for the test)
//! - ledger (path to ledger directory to modify)
//! - watcher (path to watcher directory to modify)
//! - seed (a seed to use for the Rng when making the new transactions)
//! - fog_pubkey (a hex-encoded fog public key to encrypt fog hints against)
//!
//! On STDIN, pass a json object of schema:
//! { credits: [{account: XXX, amount: YYY}, ...], key_images: [...] }
//! The "credits" will be converted to TxOuts of those amounts, and this will
//! be the block contents.
//!
//! On STDOUT, a json object of schema
//! { key_images: [...] }
//! is returned.

use clap::Parser;
use mc_account_keys::DEFAULT_SUBADDRESS_INDEX;

use mc_blockchain_types::BlockVersion;
use mc_common::logger::create_root_logger;
use mc_crypto_hashes::{Blake2b256, Digest};
use mc_crypto_keys::{RistrettoPrivate, RistrettoPublic};
use mc_ledger_db::{test_utils::add_txos_and_key_images_to_ledger, Ledger, LedgerDB};
use mc_transaction_core::{
    fog_hint::FogHint, onetime_keys::recover_onetime_private_key, ring_signature::KeyImage,
    tokens::Mob, tx::TxOut, Amount, Token,
};
use mc_util_from_random::FromRandom;
use rand_core::SeedableRng;
use rand_hc::Hc128Rng;
use serde::{Deserialize, Serialize};
use std::{path::PathBuf, str::FromStr};
use url::Url;

/// The command-line arguments
#[derive(Debug, Parser)]
struct Config {
    /// Path to keys
    #[clap(long, short, env = "MC_KEYS")]
    pub keys: PathBuf,

    /// Path to output ledger
    #[clap(long = "ledger-db", short, env = "MC_LEDGER_DB")]
    pub ledger: PathBuf,

    /// Path to output watcher db
    #[clap(long = "watcher-db", short, env = "MC_WATCHER_DB")]
    pub watcher: PathBuf,

    // Seed to use when generating randomness
    #[clap(long, short, default_value = "99", env = "MC_SEED")]
    pub seed: u64,

    // Fog public key
    #[clap(long, short, parse(try_from_str = hex::FromHex::from_hex), env = "MC_FOG_PUBKEY")]
    pub fog_pubkey: [u8; 32],
}

/// A request to credit an account with an amount of mobilecoin
#[derive(Serialize, Deserialize)]
struct Credit {
    /// The index of an account in the keys directory
    account: usize,
    /// An amount of picomob for the TxOut
    amount: u64,
}

/// This object is the schema that we parse STDIN to, via json
#[derive(Serialize, Deserialize)]
struct ParsedBlockContents {
    /// Accounts and amounts that we should credit in the next block
    credits: Vec<Credit>,
    /// Key images that we should mark as spent in the next block
    key_images: Vec<String>,
}

fn main() {
    // Logging must go to stderr to not interfere with STDOUT
    std::env::set_var("MC_LOG_STDERR", "1");
    let config = Config::parse();

    let logger = create_root_logger();

    // Read fog public key and decompress it
    let fog_pubkey = RistrettoPublic::try_from(&config.fog_pubkey)
        .expect("Could not parse fog_pubkey as Ristretto");

    // Read account keys from disk
    let account_keys = mc_util_keyfile::keygen::read_default_mnemonics(config.keys)
        .expect("Could not read mnemonic files");
    assert_ne!(0, account_keys.len());

    // Open the ledger db
    let mut ledger = LedgerDB::open(&config.ledger).expect("Could not open ledger db");
    let num_blocks = ledger.num_blocks().expect("Could not compute num_blocks");
    assert_ne!(0, num_blocks);

    // Open the watcher db
    let tx_source_url = Url::from_str("https://localhost").unwrap();
    let watcher = mc_watcher::watcher_db::WatcherDB::open_rw(
        &config.watcher,
        &[tx_source_url.clone()],
        logger.clone(),
    )
    .expect("Could not create watcher_db");

    // Read seed, expand to 32 bytes and create an Rng
    let mut hasher = Blake2b256::new();
    hasher.update(config.seed.to_le_bytes());
    let mut rng: Hc128Rng = SeedableRng::from_seed(hasher.finalize().into());

    // Parse stdin, collecting "credits" and "key images"
    let input: ParsedBlockContents = serde_json::from_reader(std::io::stdin().lock()).unwrap();
    let key_images_to_burn: Vec<KeyImage> = input
        .key_images
        .iter()
        .map(|key_image_hex| {
            assert_eq!(
                key_image_hex.len(),
                64,
                "Expected key image to be a 64-character hex string"
            );
            let decoded = hex::decode(key_image_hex).expect("Could not decode hex string");
            KeyImage::try_from(&decoded[..]).expect("Could not convert decoded bytes to key image")
        })
        .collect();

    // Convert credits to tx_outs, collecting the new key images also
    let mut tx_outs = Vec::<TxOut>::default();
    let mut new_key_images = Vec::<KeyImage>::default();
    for credit in input.credits.iter() {
        if credit.account > account_keys.len() {
            panic!(
                "account idx out of bounds: {} > {}",
                credit.account,
                account_keys.len()
            );
        }

        let fog_hint = FogHint::new(
            *account_keys[credit.account]
                .default_subaddress()
                .view_public_key(),
        );
        let e_fog_hint = fog_hint.encrypt(&fog_pubkey, &mut rng);

        // Assume MOB token for these tests
        let token_id = Mob::ID;

        let tx_private_key = RistrettoPrivate::from_random(&mut rng);
        let tx_out = TxOut::new(
            BlockVersion::MAX,
            Amount {
                value: credit.amount,
                token_id,
            },
            &account_keys[credit.account].default_subaddress(),
            &tx_private_key,
            e_fog_hint,
        )
        .expect("Could not create tx_out");

        let onetime_private_key = recover_onetime_private_key(
            &RistrettoPublic::try_from(&tx_out.public_key).unwrap(),
            account_keys[credit.account].view_private_key(),
            &account_keys[credit.account].subaddress_spend_private(DEFAULT_SUBADDRESS_INDEX),
        );

        let new_key_image = KeyImage::from(&onetime_private_key);
        tx_outs.push(tx_out);
        new_key_images.push(new_key_image);
    }

    // Use the same block version as the previous block
    let last_block = ledger.get_latest_block().unwrap();
    let block_version = BlockVersion::try_from(last_block.version).unwrap();

    // Make the new block and append to database
    let block_data = add_txos_and_key_images_to_ledger(
        &mut ledger,
        block_version,
        tx_outs,
        key_images_to_burn,
        &mut rng,
    )
    .unwrap();

    // Add to WatcherDB, too
    watcher
        .add_block_data(&tx_source_url, &block_data)
        .expect("Could not add block data to watcher");

    watcher
        .add_block_signature(
            &tx_source_url,
            num_blocks,
            block_data.signature().cloned().unwrap(),
            "archive".to_string(),
        )
        .expect("Could not add block signature to watcher");

    // Print hex-encoded key images of new tx outs, in correct order, on stdout.
    let output = JsonOutput {
        key_images: new_key_images
            .iter()
            .map(|key_image| hex::encode(key_image.as_bytes()))
            .collect(),
    };
    print!("{}", serde_json::to_string(&output).unwrap());
}

/// The json schema that we output according to
#[derive(Serialize, Deserialize)]
struct JsonOutput {
    /// The new key images corresponding to the credits that we created
    key_images: Vec<String>,
}
