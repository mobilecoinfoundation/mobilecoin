// Copyright (c) 2018-2022 The MobileCoin Foundation

// We allow dead code because not all integration tests use all of the common
// code. https://github.com/rust-lang/rust/issues/46379
#![allow(dead_code)]

use mc_account_keys::PublicAddress;
use mc_ledger_db::{
    test_utils::{
        create_ledger, create_transaction, create_transaction_with_amount_and_comparer,
        create_transaction_with_amount_and_comparer_and_recipients, initialize_ledger,
    },
    Ledger, LedgerDB,
};
use mc_transaction_core::{tx::Tx, BlockVersion};
use mc_transaction_core_test_utils::AccountKey;
use mc_transaction_std::{DefaultTxOutputsOrdering, TxOutputsOrdering};
use mc_util_test_helper::{RngType, SeedableRng};

pub fn create_test_tx(block_version: BlockVersion) -> (Tx, LedgerDB) {
    let mut rng: RngType = SeedableRng::from_seed([1u8; 32]);
    let sender = AccountKey::random(&mut rng);
    let mut ledger = create_ledger();
    let n_blocks = 1;
    initialize_ledger(block_version, &mut ledger, n_blocks, &sender, &mut rng);

    // Spend an output from the last block.
    let block_contents = ledger.get_block_contents(n_blocks - 1).unwrap();
    let tx_out = block_contents.outputs[0].clone();

    let recipient = AccountKey::random(&mut rng);
    let tx = create_transaction(
        block_version,
        &mut ledger,
        &tx_out,
        &sender,
        &recipient.default_subaddress(),
        n_blocks + 1,
        &mut rng,
    );

    (tx, ledger)
}

pub fn create_test_tx_with_amount(
    block_version: BlockVersion,
    amount: u64,
    fee: u64,
) -> (Tx, LedgerDB) {
    create_test_tx_with_amount_and_comparer::<DefaultTxOutputsOrdering>(block_version, amount, fee)
}

pub fn create_test_tx_with_amount_and_comparer<O: TxOutputsOrdering>(
    block_version: BlockVersion,
    amount: u64,
    fee: u64,
) -> (Tx, LedgerDB) {
    let mut rng: RngType = SeedableRng::from_seed([1u8; 32]);
    let sender = AccountKey::random(&mut rng);
    let mut ledger = create_ledger();
    let n_blocks = 1;
    initialize_ledger(block_version, &mut ledger, n_blocks, &sender, &mut rng);

    // Spend an output from the last block.
    let block_contents = ledger.get_block_contents(n_blocks - 1).unwrap();
    let tx_out = block_contents.outputs[0].clone();

    let recipient = AccountKey::random(&mut rng);
    let tx = create_transaction_with_amount_and_comparer::<_, _, O>(
        block_version,
        &mut ledger,
        &tx_out,
        &sender,
        &recipient.default_subaddress(),
        amount,
        fee,
        n_blocks + 1,
        &mut rng,
    );

    (tx, ledger)
}

#[allow(unused)]
pub fn create_test_tx_with_amount_and_comparer_and_recipients<O: TxOutputsOrdering>(
    block_version: BlockVersion,
    amount: u64,
    fee: u64,
    recipients: &[&PublicAddress],
) -> (Tx, LedgerDB) {
    let mut rng: RngType = SeedableRng::from_seed([1u8; 32]);
    let sender = AccountKey::random(&mut rng);
    let mut ledger = create_ledger();
    let n_blocks = 1;
    initialize_ledger(block_version, &mut ledger, n_blocks, &sender, &mut rng);

    // Spend an output from the last block.
    let block_contents = ledger.get_block_contents(n_blocks - 1).unwrap();
    let tx_out = block_contents.outputs[0].clone();

    let tx = create_transaction_with_amount_and_comparer_and_recipients::<_, _, O>(
        block_version,
        &mut ledger,
        &tx_out,
        &sender,
        recipients,
        amount,
        fee,
        n_blocks + 1,
        &mut rng,
    );

    (tx, ledger)
}
