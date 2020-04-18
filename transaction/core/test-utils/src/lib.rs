// Copyright (c) 2018-2020 MobileCoin Inc.

use core::convert::TryFrom;
use keys::{FromRandom, RistrettoPrivate, RistrettoPublic};
use ledger_db::{Ledger, LedgerDB};
use mcrand::{CryptoRng, RngCore};
use rand::{seq::SliceRandom, Rng};
use tempdir::TempDir;
use transaction::constants::RING_SIZE;
pub use transaction::{
    account_keys::{AccountKey, PublicAddress, DEFAULT_SUBADDRESS_INDEX},
    constants::BASE_FEE,
    get_tx_out_shared_secret,
    onetime_keys::recover_onetime_private_key,
    range::Range,
    tx::{Tx, TxOut, TxOutMembershipElement, TxOutMembershipHash},
    Block, BlockID, BlockIndex, RedactedTx, BLOCK_VERSION,
};
use transaction_std::{InputCredentials, TransactionBuilder};

/// The amount minted by `initialize_ledger`.
pub const INITIALIZE_LEDGER_AMOUNT: u64 = 1_000_000;

/// Creates a LedgerDB instance.
pub fn create_ledger() -> LedgerDB {
    let temp_dir = TempDir::new("test").unwrap();
    let path = temp_dir.path().to_path_buf();
    LedgerDB::create(path.clone()).unwrap();
    LedgerDB::open(path).unwrap()
}

/// Creates a transaction that sends the full value of `tx_out` to a single recipient.
///
/// # Arguments:
/// * `ledger` - A ledger containing `tx_out`.
/// * `tx_out` - The TxOut that will be spent.
/// * `sender` - The owner of `tx_out`.
/// * `recipient` - The recipient of the new transaction.
/// * `tombstone_block` - The tombstone block for the new transaction.
/// * `rng` - The randomness used by this function
pub fn create_transaction<L: Ledger, R: RngCore + CryptoRng>(
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
    let (value, _blinding) = tx_out.amount.get_value(&shared_secret).unwrap();

    assert!(value >= BASE_FEE);
    create_transaction_with_amount(
        ledger,
        tx_out,
        sender,
        recipient,
        value - BASE_FEE,
        BASE_FEE,
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
    ledger: &mut L,
    tx_out: &TxOut,
    sender: &AccountKey,
    recipient: &PublicAddress,
    amount: u64,
    fee: u64,
    tombstone_block: BlockIndex,
    rng: &mut R,
) -> Tx {
    let mut transaction_builder = TransactionBuilder::new();

    // The first transaction in the origin block should contain enough outputs to use as mixins.
    let origin_tx = &ledger.get_transactions_by_block(0).unwrap()[0];
    let origin_outputs = &origin_tx.outputs;

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

    let spend_private_key = sender.subaddress_spend_key(DEFAULT_SUBADDRESS_INDEX);
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
        rng,
    )
    .unwrap();
    transaction_builder.add_input(input_credentials);

    // Output
    transaction_builder
        .add_output(amount, recipient, None, rng)
        .unwrap();

    // Tombstone block
    transaction_builder.set_tombstone_block(tombstone_block);

    // Fee
    transaction_builder.set_fee(fee);

    // Build and return the transaction
    transaction_builder.build(rng).unwrap()
}

/// Populates the LedgerDB with initial data.
///
/// Creates a number of blocks, each of which contains a single transaction.
/// The first contains RING_SIZE txos so we can create more valid transactions.
/// The rest have a single TxOut.
///
/// The first block "mints" coins, and each subsequent block spends the TxOut produced by the
/// previous block.
///
/// # Arguments
/// * `ledger` -
/// * `n_blocks` - The number of blocks of transactions to write to `db`.
/// * `account_key` - The recipient of all TxOuts generated.
/// * `rng` -
///
/// Returns the blocks that were created.
pub fn initialize_ledger<L: Ledger, R: RngCore + CryptoRng>(
    ledger: &mut L,
    n_blocks: u64,
    account_key: &AccountKey,
    rng: &mut R,
) -> Vec<Block> {
    let value: u64 = INITIALIZE_LEDGER_AMOUNT;

    // TxOut from the previous block
    let mut to_spend: Option<TxOut> = None;
    let mut parent: Option<Block> = None;

    let mut blocks: Vec<Block> = Vec::new();

    for block_index in 0..n_blocks {
        let (block, redacted_transactions) = match to_spend {
            Some(tx_out) => {
                let tx = create_transaction(
                    ledger,
                    &tx_out,
                    account_key,
                    &account_key.default_subaddress(),
                    block_index + 1,
                    rng,
                );

                let redacted_transactions = vec![tx.redact()];

                let block = Block::new(
                    BLOCK_VERSION,
                    &parent.as_ref().unwrap().id,
                    block_index,
                    parent.as_ref().unwrap().cumulative_txo_count + 1,
                    &Default::default(),
                    &redacted_transactions,
                );

                (block, redacted_transactions)
            }
            None => {
                // Create an origin block.
                let outputs: Vec<TxOut> = (0..RING_SIZE)
                    .map(|_i| {
                        TxOut::new(
                            value,
                            &account_key.default_subaddress(),
                            &RistrettoPrivate::from_random(rng),
                            Default::default(),
                            rng,
                        )
                        .unwrap()
                    })
                    .collect();

                let redacted_transactions = vec![RedactedTx {
                    outputs,
                    key_images: vec![],
                }];

                let block = Block::new_origin_block(&redacted_transactions);
                (block, redacted_transactions)
            }
        };

        ledger
            .append_block(&block, &redacted_transactions, None)
            .expect("failed writing initial transactions");

        blocks.push(block.clone());
        parent = Some(block);
        let tx_out = redacted_transactions[0].outputs[0].clone();
        to_spend = Some(tx_out);
    }

    // Verify that db now contains n transactions.
    assert_eq!(ledger.num_blocks().unwrap(), n_blocks as u64);
    assert_eq!(ledger.num_txs().unwrap(), n_blocks as u64);

    blocks
}

/// Generate a list of blocks, each with a random number of transactions
pub fn get_blocks<T: Rng + RngCore + CryptoRng>(
    recipients: &[PublicAddress],
    n_blocks: usize,
    min_txs_per_block: usize,
    max_txs_per_block: usize,
    initial_block_index: u64,
    initial_block_id: BlockID,
    rng: &mut T,
) -> Vec<(Block, Vec<RedactedTx>)> {
    assert!(!recipients.is_empty());
    assert!(max_txs_per_block >= min_txs_per_block);

    let mut results = Vec::<(Block, Vec<RedactedTx>)>::new();
    let mut last_block_id = initial_block_id;
    let mut cumulative_txo_count = 0u64;

    for block_index in 0..n_blocks {
        let n_txs = rng.gen_range(min_txs_per_block, max_txs_per_block + 1);
        let mut txs = Vec::<RedactedTx>::new();
        let recipient_and_amount: Vec<(PublicAddress, u64)> = (0..n_txs)
            .map(|_| {
                (
                    recipients.choose(rng).unwrap().clone(),
                    rng.gen_range(1, 10_000_000_000),
                )
            })
            .collect();
        let outputs = get_outputs(&recipient_and_amount, rng);

        for output in outputs {
            let key_images = Vec::new();
            let tx = RedactedTx::new(vec![output.clone()], key_images);
            txs.push(tx);
        }

        cumulative_txo_count += txs.len() as u64;

        // Fake proofs
        let root_element = TxOutMembershipElement {
            range: Range::new(0, block_index as u64).unwrap(),
            hash: TxOutMembershipHash::from([0u8; 32]),
        };

        let block = Block::new(
            BLOCK_VERSION,
            &last_block_id,
            initial_block_index + block_index as u64,
            cumulative_txo_count,
            &root_element,
            &txs,
        );

        last_block_id = block.id.clone();
        results.push((block, txs));
    }

    results
}

/// Generate a set of outputs that "mint" coins for each recipient.
pub fn get_outputs<T: RngCore + CryptoRng>(
    recipient_and_amount: &[(PublicAddress, u64)],
    rng: &mut T,
) -> Vec<TxOut> {
    recipient_and_amount
        .iter()
        .map(|(recipient, value)| {
            TxOut::new(
                *value,
                recipient,
                &RistrettoPrivate::from_random(rng),
                Default::default(),
                rng,
            )
            .unwrap()
        })
        .collect()
}
