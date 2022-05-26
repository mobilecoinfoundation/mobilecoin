// Copyright (c) 2018-2022 The MobileCoin Foundation

mod mint;

pub use mc_account_keys::{AccountKey, PublicAddress, DEFAULT_SUBADDRESS_INDEX};
pub use mc_blockchain_types::{
    Block, BlockContents, BlockID, BlockIndex, BlockMetadata, BlockSignature, BlockVersion,
};
pub use mc_crypto_ring_signature_signer::NoKeysRingSigner;
pub use mc_fog_report_validation_test_utils::MockFogResolver;
pub use mc_transaction_core::{
    get_tx_out_shared_secret,
    onetime_keys::recover_onetime_private_key,
    ring_signature::KeyImage,
    tokens::Mob,
    tx::{Tx, TxOut, TxOutMembershipElement, TxOutMembershipHash},
    Amount, Token,
};
pub use mc_util_serial::round_trip_message;
pub use mint::{
    create_mint_config_tx, create_mint_config_tx_and_signers, create_mint_tx,
    create_mint_tx_to_recipient, mint_config_tx_to_validated,
};

use mc_crypto_keys::RistrettoPrivate;
use mc_transaction_core::membership_proofs::Range;
use mc_util_from_random::FromRandom;
use rand::{seq::SliceRandom, CryptoRng, Rng, RngCore};

/// Generate a list of blocks, each with a random number of transactions.
// FIXME: Change to return Vec<BlockData> with metadata.
pub fn get_blocks<T: Rng + RngCore + CryptoRng>(
    block_version: BlockVersion,
    recipients: &[PublicAddress],
    n_blocks: usize,
    min_txs_per_block: usize,
    max_txs_per_block: usize,
    initial_block: &Block,
    rng: &mut T,
) -> Vec<(Block, BlockContents)> {
    assert!(!recipients.is_empty());
    assert!(max_txs_per_block >= min_txs_per_block);

    let mut results = Vec::<(Block, BlockContents)>::new();
    let mut last_block = initial_block.clone();

    for block_index in 0..n_blocks {
        let n_txs = rng.gen_range(min_txs_per_block..=max_txs_per_block);
        let recipient_and_amount: Vec<(PublicAddress, u64)> = (0..n_txs)
            .map(|_| {
                (
                    recipients.choose(rng).unwrap().clone(),
                    rng.gen_range(1..10_000_000_000),
                )
            })
            .collect();
        let outputs = get_outputs(block_version, &recipient_and_amount, rng);

        // Non-origin blocks must have at least one key image.
        let key_images = vec![KeyImage::from(block_index as u64)];

        let block_contents = BlockContents {
            key_images,
            outputs,
            ..Default::default()
        };

        // Fake proofs
        let root_element = TxOutMembershipElement {
            range: Range::new(0, block_index as u64).unwrap(),
            hash: TxOutMembershipHash::from([0u8; 32]),
        };

        let block =
            Block::new_with_parent(block_version, &last_block, &root_element, &block_contents);

        last_block = block.clone();

        results.push((block, block_contents));
    }

    results
}

/// Generate a set of outputs that "mint" coins for each recipient.
pub fn get_outputs<T: RngCore + CryptoRng>(
    block_version: BlockVersion,
    recipient_and_amount: &[(PublicAddress, u64)],
    rng: &mut T,
) -> Vec<TxOut> {
    recipient_and_amount
        .iter()
        .map(|(recipient, value)| {
            TxOut::new(
                block_version,
                Amount {
                    value: *value,
                    token_id: Mob::ID,
                },
                recipient,
                &RistrettoPrivate::from_random(rng),
                Default::default(),
            )
            .unwrap()
        })
        .collect()
}

/// Generate a dummy txout for testing.
pub fn create_test_tx_out(
    block_version: BlockVersion,
    rng: &mut (impl RngCore + CryptoRng),
) -> TxOut {
    let account_key = AccountKey::random(rng);
    TxOut::new(
        block_version,
        Amount {
            value: rng.next_u64(),
            token_id: Mob::ID,
        },
        &account_key.default_subaddress(),
        &RistrettoPrivate::from_random(rng),
        Default::default(),
    )
    .unwrap()
}
