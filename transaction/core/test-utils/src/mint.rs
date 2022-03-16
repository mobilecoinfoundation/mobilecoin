// Copyright (c) 2018-2022 The MobileCoin Foundation
//! Test helpers for minting transactions

use mc_crypto_keys::{Ed25519Pair, RistrettoPublic, Signer};
use mc_crypto_multisig::{MultiSig, SignerSet};
use mc_crypto_rand::{CryptoRng, RngCore};
use mc_transaction_core::{
    mint::{
        constants::NONCE_LENGTH, MintConfig, MintConfigTx, MintConfigTxPrefix, MintTx, MintTxPrefix,
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

    let mut nonce: Vec<u8> = vec![0u8; NONCE_LENGTH];
    rng.fill_bytes(&mut nonce);

    let prefix = MintConfigTxPrefix {
        token_id: *token_id,
        configs: vec![
            MintConfig {
                token_id: *token_id,
                signer_set: SignerSet::new(vec![signer_1.public_key()], 1),
                mint_limit: rng.next_u64(),
            },
            MintConfig {
                token_id: *token_id,
                signer_set: SignerSet::new(vec![signer_2.public_key(), signer_3.public_key()], 1),
                mint_limit: rng.next_u64(),
            },
        ],
        nonce,
        tombstone_block: 10,
    };

    let message = prefix.hash();
    let signature = MultiSig::new(vec![signer_1.try_sign(message.as_ref()).unwrap()]);

    (
        MintConfigTx { prefix, signature },
        vec![signer_1, signer_2, signer_3],
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
    let mut nonce: Vec<u8> = vec![0u8; NONCE_LENGTH];
    rng.fill_bytes(&mut nonce);

    let prefix = MintTxPrefix {
        token_id: *token_id,
        amount,
        view_public_key: RistrettoPublic::from_random(rng),
        spend_public_key: RistrettoPublic::from_random(rng),
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
