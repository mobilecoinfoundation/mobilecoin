// Copyright (c) 2018-2022 The MobileCoin Foundation

pub mod mock_ledger;
pub use mock_ledger::{get_mock_ledger, get_test_ledger_blocks, MockLedger};

use crate::{Ledger, LedgerDB};
use mc_account_keys::{AccountKey, PublicAddress, DEFAULT_SUBADDRESS_INDEX};
use mc_blockchain_test_utils::make_block_metadata;
use mc_blockchain_types::{Block, BlockContents, BlockData, BlockIndex, BlockVersion};
use mc_crypto_keys::{CompressedRistrettoPublic, RistrettoPrivate, RistrettoPublic};
use mc_transaction_core::{
    constants::RING_SIZE,
    get_tx_out_shared_secret,
    onetime_keys::recover_onetime_private_key,
    tokens::Mob,
    tx::{Tx, TxOut},
    Amount, Token,
};
use mc_transaction_core_test_utils::{MockFogResolver, NoKeysRingSigner};
use mc_transaction_std::{
    DefaultTxOutputsOrdering, EmptyMemoBuilder, InputCredentials, TransactionBuilder,
    TxOutputsOrdering,
};
use mc_util_from_random::FromRandom;
use rand::{CryptoRng, RngCore};
use std::cmp::Ordering;
use tempdir::TempDir;

/// The amount minted by `initialize_ledger`, 1 million milliMOB.
pub const INITIALIZE_LEDGER_AMOUNT: u64 = 1_000_000 * 1_000_000_000;

/// Creates a LedgerDB instance.
pub fn create_ledger() -> LedgerDB {
    let temp_dir = TempDir::new("ledger").unwrap();
    let path = temp_dir.path();
    LedgerDB::create(path).unwrap();
    LedgerDB::open(path).unwrap()
}

/// Populates the LedgerDB with initial data.
///
/// Creates a number of blocks, each of which contains a single transaction.
/// The first contains RING_SIZE txos so we can create more valid transactions.
/// The rest have a single TxOut.
///
/// The first block "mints" coins, and each subsequent block spends the TxOut
/// produced by the previous block.
///
/// # Arguments
/// * `ledger` -
/// * `n_blocks` - The number of blocks of transactions to write to `db`.
/// * `account_key` - The recipient of all TxOuts generated.
/// * `rng` -
///
/// Returns the blocks that were created.
pub fn initialize_ledger<L: Ledger, R: RngCore + CryptoRng>(
    block_version: BlockVersion,
    ledger: &mut L,
    n_blocks: u64,
    account_key: &AccountKey,
    rng: &mut R,
) -> Vec<BlockData> {
    let value: u64 = INITIALIZE_LEDGER_AMOUNT;
    let token_id = Mob::ID;

    // TxOut from the previous block
    let mut to_spend: Option<TxOut> = None;
    let mut parent: Option<Block> = None;

    let mut results = Vec::with_capacity(n_blocks.try_into().unwrap());
    for block_index in 0..n_blocks {
        let (block, block_contents) = match to_spend {
            Some(tx_out) => {
                let tx = create_transaction(
                    block_version,
                    ledger,
                    &tx_out,
                    account_key,
                    &account_key.default_subaddress(),
                    block_index + 1,
                    rng,
                );

                let key_images = tx.key_images();
                let outputs = tx.prefix.outputs.clone();

                let block_contents = BlockContents {
                    key_images,
                    outputs,
                    ..Default::default()
                };

                let block = Block::new(
                    block_version,
                    &parent.as_ref().unwrap().id,
                    block_index,
                    parent.as_ref().unwrap().cumulative_txo_count,
                    &Default::default(),
                    &block_contents,
                );

                (block, block_contents)
            }
            None => {
                // Create an origin block.
                let outputs: Vec<TxOut> = (0..RING_SIZE)
                    .map(|_i| {
                        TxOut::new(
                            BlockVersion::ZERO,
                            Amount { value, token_id },
                            &account_key.default_subaddress(),
                            &RistrettoPrivate::from_random(rng),
                            Default::default(),
                        )
                        .expect("Could not create origin block TxOut")
                    })
                    .collect();

                let block = Block::new_origin_block(&outputs);
                let block_contents = BlockContents {
                    outputs,
                    ..Default::default()
                };
                (block, block_contents)
            }
        };

        parent = Some(block.clone());
        to_spend = Some(block_contents.outputs[0].clone());

        let metadata = make_block_metadata(block.id.clone(), rng);
        let block_data = BlockData::new(block, block_contents, None, metadata);

        ledger
            .append_block_data(&block_data)
            .expect("failed writing initial blocks");

        results.push(block_data)
    }

    // Verify that db now contains n transactions.
    assert_eq!(ledger.num_blocks().unwrap(), n_blocks as u64);

    results
}

pub struct InverseTxOutputsOrdering;

impl TxOutputsOrdering for InverseTxOutputsOrdering {
    fn cmp(a: &CompressedRistrettoPublic, b: &CompressedRistrettoPublic) -> Ordering {
        b.cmp(a)
    }
}

/// Creates a transaction that sends the full value of `tx_out` to a single
/// recipient.
///
/// # Arguments:
/// * `ledger` - A ledger containing `tx_out`.
/// * `tx_out` - The TxOut that will be spent.
/// * `sender` - The owner of `tx_out`.
/// * `recipient` - The recipient of the new transaction.
/// * `tombstone_block` - The tombstone block for the new transaction.
/// * `rng` - The randomness used by this function
pub fn create_transaction<L: Ledger, R: RngCore + CryptoRng>(
    block_version: BlockVersion,
    ledger: &mut L,
    tx_out: &TxOut,
    sender: &AccountKey,
    recipient: &PublicAddress,
    tombstone_block: BlockIndex,
    rng: &mut R,
) -> Tx {
    // Get the output value.
    let tx_out_public_key = RistrettoPublic::try_from(&tx_out.public_key).unwrap();
    let shared_secret = get_tx_out_shared_secret(sender.view_private_key(), &tx_out_public_key);
    let (amount, _blinding) = tx_out.masked_amount.get_value(&shared_secret).unwrap();

    assert!(amount.value >= Mob::MINIMUM_FEE);
    create_transaction_with_amount(
        block_version,
        ledger,
        tx_out,
        sender,
        recipient,
        amount.value - Mob::MINIMUM_FEE,
        Mob::MINIMUM_FEE,
        tombstone_block,
        rng,
    )
}

/// Creates a transaction that sends an arbitrary amount to a single recipient.
///
/// # Arguments:
/// * `ledger` - A ledger containing `tx_out`.
/// * `tx_out` - The TxOut that will be spent.
/// * `sender` - The owner of `tx_out`.
/// * `recipient` - The recipient of the new transaction.
/// * `amount` - Amount to send.
/// * `tombstone_block` - The tombstone block for the new transaction.
/// * `rng` - The randomness used by this function
pub fn create_transaction_with_amount<L: Ledger, R: RngCore + CryptoRng>(
    block_version: BlockVersion,
    ledger: &mut L,
    tx_out: &TxOut,
    sender: &AccountKey,
    recipient: &PublicAddress,
    amount: u64,
    fee: u64,
    tombstone_block: BlockIndex,
    rng: &mut R,
) -> Tx {
    create_transaction_with_amount_and_comparer::<L, R, DefaultTxOutputsOrdering>(
        block_version,
        ledger,
        tx_out,
        sender,
        recipient,
        amount,
        fee,
        tombstone_block,
        rng,
    )
}

/// Creates a transaction that sends an arbitrary amount to a single recipient.
///
/// # Arguments:
/// * `ledger` - A ledger containing `tx_out`.
/// * `tx_out` - The TxOut that will be spent.
/// * `sender` - The owner of `tx_out`.
/// * `recipient` - The recipient of the new transaction.
/// * `amount` - Amount to send.
/// * `tombstone_block` - The tombstone block for the new transaction.
/// * `rng` - The randomness used by this function
pub fn create_transaction_with_amount_and_comparer<
    L: Ledger,
    R: RngCore + CryptoRng,
    O: TxOutputsOrdering,
>(
    block_version: BlockVersion,
    ledger: &mut L,
    tx_out: &TxOut,
    sender: &AccountKey,
    recipient: &PublicAddress,
    value: u64,
    fee: u64,
    tombstone_block: BlockIndex,
    rng: &mut R,
) -> Tx {
    create_transaction_with_amount_and_comparer_and_recipients::<L, R, O>(
        block_version,
        ledger,
        tx_out,
        sender,
        &[recipient],
        value,
        fee,
        tombstone_block,
        rng,
    )
}

/// Creates a transaction that sends an arbitrary amount to a single recipient.
///
/// # Arguments:
/// * `ledger` - A ledger containing `tx_out`.
/// * `tx_out` - The TxOut that will be spent.
/// * `sender` - The owner of `tx_out`.
/// * `recipient` - The recipient of the new transaction.
/// * `amount` - Amount to send.
/// * `tombstone_block` - The tombstone block for the new transaction.
/// * `rng` - The randomness used by this function
pub fn create_transaction_with_amount_and_comparer_and_recipients<
    L: Ledger,
    R: RngCore + CryptoRng,
    O: TxOutputsOrdering,
>(
    block_version: BlockVersion,
    ledger: &mut L,
    tx_out: &TxOut,
    sender: &AccountKey,
    recipients: &[&PublicAddress],
    value: u64,
    fee: u64,
    tombstone_block: BlockIndex,
    rng: &mut R,
) -> Tx {
    let (sender_amount, _) = tx_out.view_key_match(sender.view_private_key()).unwrap();

    let mut transaction_builder = TransactionBuilder::new(
        block_version,
        Amount::new(fee, sender_amount.token_id),
        MockFogResolver::default(),
        EmptyMemoBuilder::default(),
    )
    .unwrap();

    // The first transaction in the origin block should contain enough outputs to
    // use as mixins.
    let origin_block_contents = ledger.get_block_contents(0).unwrap();
    let origin_outputs = &origin_block_contents.outputs;

    // Populate a ring with mixins.
    let mut ring: Vec<TxOut> = origin_outputs.iter().take(RING_SIZE).cloned().collect();
    if !ring.contains(tx_out) {
        ring[0] = tx_out.clone();
    }
    let real_index = ring.iter().position(|element| element == tx_out).unwrap();

    // Membership proofs for the full ring.
    let indexes = ring
        .iter()
        .map(|tx_out| ledger.get_tx_out_index_by_hash(&tx_out.hash()).unwrap())
        .collect::<Vec<u64>>();
    let membership_proofs = ledger.get_tx_out_proof_of_memberships(&indexes).unwrap();

    let spend_private_key = sender.subaddress_spend_private(DEFAULT_SUBADDRESS_INDEX);
    let tx_out_public_key = RistrettoPublic::try_from(&tx_out.public_key).unwrap();
    let onetime_private_key = recover_onetime_private_key(
        &tx_out_public_key,
        sender.view_private_key(),
        &spend_private_key,
    );

    let input_credentials = InputCredentials::new(
        ring,
        membership_proofs,
        real_index,
        onetime_private_key,
        *sender.view_private_key(),
    )
    .unwrap();
    transaction_builder.add_input(input_credentials);

    let amount = Amount {
        value: value / recipients.len() as u64,
        token_id: sender_amount.token_id,
    };

    let rest = value % recipients.len() as u64;

    // Output
    for (idx, recipient) in recipients.iter().enumerate() {
        if idx == 0 && rest != 0 {
            let mut dup_amount = amount;
            dup_amount.value += rest;
            transaction_builder
                .add_output(dup_amount, recipient, rng)
                .unwrap();
            continue;
        }

        transaction_builder
            .add_output(amount, recipient, rng)
            .unwrap();
    }

    // Tombstone block
    transaction_builder.set_tombstone_block(tombstone_block);

    // Build and return the transaction
    transaction_builder
        .build_with_sorter::<_, O, _>(&NoKeysRingSigner {}, rng)
        .unwrap()
}
