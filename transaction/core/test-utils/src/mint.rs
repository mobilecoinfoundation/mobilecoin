// Copyright (c) 2018-2022 The MobileCoin Foundation
//! Test helpers for minting transactions

use mc_account_keys::PublicAddress;
use mc_crypto_keys::{Ed25519Pair, RistrettoPublic, Signer};
use mc_crypto_multisig::{MultiSig, SignerSet};
use mc_crypto_rand::{CryptoRng, RngCore};
use mc_transaction_core::{
    mint::{
        constants::NONCE_LENGTH, MintConfig, MintConfigTx, MintConfigTxPrefix, MintTx,
        MintTxPrefix, ValidatedMintConfigTx,
    },
    TokenId,
};
use mc_util_from_random::FromRandom;

/// Generate a valid MintConfigTx and return it together with the set of signing
/// keys that are allowed to sign it.
///
/// # Arguments
/// `token_id` - The token id to use.
/// `rng` - Randomness source.
pub fn create_mint_config_tx_and_signers(
    token_id: TokenId,
    rng: &mut (impl RngCore + CryptoRng),
) -> (MintConfigTx, Vec<Ed25519Pair>) {
    let signer_1 = Ed25519Pair::from_random(rng);
    let signer_2 = Ed25519Pair::from_random(rng);
    let signer_3 = Ed25519Pair::from_random(rng);
    let signer_4 = Ed25519Pair::from_random(rng);
    let signer_5 = Ed25519Pair::from_random(rng);

    let mut nonce: Vec<u8> = vec![0u8; NONCE_LENGTH];
    rng.fill_bytes(&mut nonce);

    // We use next_u32 for individual configurations mint limit to ensure the total
    // mint limit does not overflow.
    let configs = vec![
        MintConfig {
            token_id: *token_id,
            signer_set: SignerSet::new(vec![signer_1.public_key()], 1),
            mint_limit: rng.next_u32() as u64,
        },
        MintConfig {
            token_id: *token_id,
            signer_set: SignerSet::new(vec![signer_2.public_key(), signer_3.public_key()], 1),
            mint_limit: rng.next_u32() as u64,
        },
        MintConfig {
            token_id: *token_id,
            signer_set: SignerSet::new(
                vec![
                    signer_3.public_key(),
                    signer_4.public_key(),
                    signer_5.public_key(),
                ],
                2,
            ),
            mint_limit: rng.next_u32() as u64,
        },
    ];

    let prefix = MintConfigTxPrefix {
        token_id: *token_id,
        configs: configs.clone(),
        nonce,
        tombstone_block: 2,
        total_mint_limit: configs[0].mint_limit + configs[1].mint_limit + configs[2].mint_limit,
    };

    let message = prefix.hash();
    let signature = MultiSig::new(vec![signer_1.try_sign(message.as_ref()).unwrap()]);

    (
        MintConfigTx { prefix, signature },
        vec![signer_1, signer_2, signer_3, signer_4, signer_5],
    )
}

/// Generate a valid MintConfigTx.
///
/// # Arguments
/// `token_id` - The token id to use.
/// `rng` - Randomness source.
pub fn create_mint_config_tx(
    token_id: TokenId,
    rng: &mut (impl RngCore + CryptoRng),
) -> MintConfigTx {
    let (mint_config_tx, _signers) = create_mint_config_tx_and_signers(token_id, rng);
    mint_config_tx
}

/// A helper for mocking a `ValidatedMintConfigTx` from a `MintConfigTx`.
pub fn mint_config_tx_to_validated(mint_config_tx: &MintConfigTx) -> ValidatedMintConfigTx {
    ValidatedMintConfigTx {
        mint_config_tx: mint_config_tx.clone(),
        signer_set: SignerSet::default(),
    }
}

/// Generate a random, valid mint tx
///
/// # Arguments
/// * `token_id` - The token id to use.
/// * `signers` - The signing keys to sign the transaction with.
/// * `amount` - The amount to mint.
/// * `recipient` - The recipient of the minting.
/// * `rng` - Randomness source.
pub fn create_mint_tx_to_recipient(
    token_id: TokenId,
    signers: &[Ed25519Pair],
    amount: u64,
    recipient: &PublicAddress,
    rng: &mut (impl RngCore + CryptoRng),
) -> MintTx {
    let mut nonce: Vec<u8> = vec![0u8; NONCE_LENGTH];
    rng.fill_bytes(&mut nonce);

    let prefix = MintTxPrefix {
        token_id: *token_id,
        amount,
        view_public_key: *recipient.view_public_key(),
        spend_public_key: *recipient.spend_public_key(),
        nonce,
        tombstone_block: 10,
    };

    let message = prefix.hash();

    let signatures = signers
        .iter()
        .map(|signer| signer.try_sign(message.as_ref()).unwrap())
        .collect();
    let signature = MultiSig::new(signatures);

    MintTx { prefix, signature }
}

/// Generate a random, valid mint tx
///
/// # Arguments
/// * `token_id` - The token id to use.
/// * `signers` - The signing keys to sign the transaction with.
/// * `amount` - The amount to mint.
/// * `rng` - Randomness source.
pub fn create_mint_tx(
    token_id: TokenId,
    signers: &[Ed25519Pair],
    amount: u64,
    rng: &mut (impl RngCore + CryptoRng),
) -> MintTx {
    let public_address = PublicAddress::new(
        &RistrettoPublic::from_random(rng),
        &RistrettoPublic::from_random(rng),
    );
    create_mint_tx_to_recipient(token_id, signers, amount, &public_address, rng)
}
