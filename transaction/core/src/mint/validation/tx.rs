// Copyright (c) 2018-2022 The MobileCoin Foundation

//! MintTx transaction validation.

use crate::{
    mint::{
        config::MintConfig,
        tx::MintTx,
        validation::{
            common::{
                validate_block_version, validate_nonce, validate_token_id, validate_tombstone,
            },
            error::Error,
        },
    },
    BlockVersion,
};
use mc_crypto_keys::Ed25519Public;
use mc_crypto_multisig::SignerSet;

/// Determines if the transaction is valid, with respect to the provided
/// context.
///
/// # Arguments
/// * `tx` - A pending transaction.
/// * `current_block_index` - The index of the current block that is being
///   built.
/// * `block_version` - The version of the block that is being built.
/// * `mint_config` - The minting configuration that is authorizing this minting
///   transaction.
pub fn validate_mint_tx(
    tx: &MintTx,
    current_block_index: u64,
    block_version: BlockVersion,
    mint_config: &MintConfig,
) -> Result<(), Error> {
    validate_block_version(block_version)?;

    validate_token_id(tx.prefix.token_id)?;

    validate_nonce(&tx.prefix.nonce)?;

    validate_tombstone(current_block_index, tx.prefix.tombstone_block)?;

    validate_against_mint_config(tx, mint_config)?;

    Ok(())
}

/// Validate the trnasaction against a specific mint config.
pub fn validate_against_mint_config(tx: &MintTx, mint_config: &MintConfig) -> Result<(), Error> {
    // The token id must match.
    if tx.prefix.token_id != mint_config.token_id {
        return Err(Error::TokenId(tx.prefix.token_id));
    }

    // The amount must not exceed the mint limit.
    if tx.prefix.amount > mint_config.mint_limit {
        return Err(Error::AmountExceedsMintLimit);
    }

    // The transaction must be signed by the mint config's signer set.
    validate_signature(tx, &mint_config.signer_set)?;

    // All good
    Ok(())
}

/// The transaction must be properly signed by the signer set.
fn validate_signature(tx: &MintTx, signer_set: &SignerSet<Ed25519Public>) -> Result<(), Error> {
    let message = tx.prefix.hash();

    signer_set
        .verify(&message[..], &tx.signature)
        .map_err(|_| Error::Signature)
        .map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mint::{constants::NONCE_MIN_LENGTH, MintTxPrefix};
    use mc_crypto_keys::{Ed25519Pair, RistrettoPublic, Signer};
    use mc_crypto_multisig::MultiSig;
    use mc_util_from_random::FromRandom;
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn validate_against_mint_config_accepts_valid_config() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let token_id = 123;
        let signer_1 = Ed25519Pair::from_random(&mut rng);
        let signer_2 = Ed25519Pair::from_random(&mut rng);
        let signer_3 = Ed25519Pair::from_random(&mut rng);

        let mint_config = MintConfig {
            token_id: token_id,
            signer_set: SignerSet::new(
                vec![
                    signer_1.public_key(),
                    signer_2.public_key(),
                    signer_3.public_key(),
                ],
                2,
            ),
            mint_limit: 500,
        };

        let prefix = MintTxPrefix {
            token_id: token_id,
            amount: 100,
            view_public_key: RistrettoPublic::from_random(&mut rng),
            spend_public_key: RistrettoPublic::from_random(&mut rng),
            nonce: vec![1u8; NONCE_MIN_LENGTH],
            tombstone_block: 10,
        };
        let message = prefix.hash();
        let signature = MultiSig::new(vec![
            signer_1.try_sign(message.as_ref()).unwrap(),
            signer_3.try_sign(message.as_ref()).unwrap(),
        ]);
        let tx = MintTx { prefix, signature };

        assert_eq!(validate_against_mint_config(&tx, &mint_config), Ok(()));
    }

    #[test]
    fn validate_against_mint_config_rejects_token_id_mismatch() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let token_id = 123;
        let signer_1 = Ed25519Pair::from_random(&mut rng);
        let signer_2 = Ed25519Pair::from_random(&mut rng);
        let signer_3 = Ed25519Pair::from_random(&mut rng);

        let mint_config = MintConfig {
            token_id: token_id,
            signer_set: SignerSet::new(
                vec![
                    signer_1.public_key(),
                    signer_2.public_key(),
                    signer_3.public_key(),
                ],
                2,
            ),
            mint_limit: 500,
        };

        let prefix = MintTxPrefix {
            token_id: token_id + 1,
            amount: 100,
            view_public_key: RistrettoPublic::from_random(&mut rng),
            spend_public_key: RistrettoPublic::from_random(&mut rng),
            nonce: vec![1u8; NONCE_MIN_LENGTH],
            tombstone_block: 10,
        };
        let message = prefix.hash();
        let signature = MultiSig::new(vec![
            signer_1.try_sign(message.as_ref()).unwrap(),
            signer_3.try_sign(message.as_ref()).unwrap(),
        ]);
        let tx = MintTx { prefix, signature };

        assert_eq!(
            validate_against_mint_config(&tx, &mint_config),
            Err(Error::TokenId(token_id + 1))
        );
    }

    #[test]
    fn validate_against_mint_config_rejects_amount_over_limit() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let token_id = 123;
        let signer_1 = Ed25519Pair::from_random(&mut rng);
        let signer_2 = Ed25519Pair::from_random(&mut rng);
        let signer_3 = Ed25519Pair::from_random(&mut rng);

        let mint_config = MintConfig {
            token_id: token_id,
            signer_set: SignerSet::new(
                vec![
                    signer_1.public_key(),
                    signer_2.public_key(),
                    signer_3.public_key(),
                ],
                2,
            ),
            mint_limit: 500,
        };

        let prefix = MintTxPrefix {
            token_id: token_id,
            amount: mint_config.mint_limit + 1,
            view_public_key: RistrettoPublic::from_random(&mut rng),
            spend_public_key: RistrettoPublic::from_random(&mut rng),
            nonce: vec![1u8; NONCE_MIN_LENGTH],
            tombstone_block: 10,
        };
        let message = prefix.hash();
        let signature = MultiSig::new(vec![
            signer_1.try_sign(message.as_ref()).unwrap(),
            signer_3.try_sign(message.as_ref()).unwrap(),
        ]);
        let tx = MintTx { prefix, signature };

        assert_eq!(
            validate_against_mint_config(&tx, &mint_config),
            Err(Error::AmountExceedsMintLimit)
        );
    }

    #[test]
    fn validate_against_mint_config_rejects_signature_mismatch() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let token_id = 123;
        let signer_1 = Ed25519Pair::from_random(&mut rng);
        let signer_2 = Ed25519Pair::from_random(&mut rng);
        let signer_3 = Ed25519Pair::from_random(&mut rng);

        let mint_config = MintConfig {
            token_id: token_id,
            signer_set: SignerSet::new(
                vec![
                    signer_1.public_key(),
                    signer_2.public_key(),
                    signer_3.public_key(),
                ],
                2,
            ),
            mint_limit: 500,
        };

        let prefix = MintTxPrefix {
            token_id: token_id,
            amount: 1,
            view_public_key: RistrettoPublic::from_random(&mut rng),
            spend_public_key: RistrettoPublic::from_random(&mut rng),
            nonce: vec![1u8; NONCE_MIN_LENGTH],
            tombstone_block: 10,
        };
        let message = prefix.hash();
        let signature = MultiSig::new(vec![
            signer_1.try_sign(message.as_ref()).unwrap(), // Only one signer is not enough
        ]);
        let tx = MintTx { prefix, signature };

        assert_eq!(
            validate_against_mint_config(&tx, &mint_config),
            Err(Error::Signature)
        );
    }

    #[test]
    fn validate_signature_accepts_valid_signature() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let token_id = 123;
        let signer_1 = Ed25519Pair::from_random(&mut rng);

        let prefix = MintTxPrefix {
            token_id: token_id,
            amount: 10,
            view_public_key: RistrettoPublic::from_random(&mut rng),
            spend_public_key: RistrettoPublic::from_random(&mut rng),
            nonce: vec![1u8; NONCE_MIN_LENGTH],
            tombstone_block: 10,
        };
        let message = prefix.hash();
        let signature = MultiSig::new(vec![signer_1.try_sign(message.as_ref()).unwrap()]);
        let tx = MintTx { prefix, signature };

        let signer_set = SignerSet::new(vec![signer_1.public_key()], 1);

        assert_eq!(validate_signature(&tx, &signer_set), Ok(()));
    }

    #[test]
    fn validate_signature_rejects_signers_mismatch() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let token_id = 123;
        let signer_1 = Ed25519Pair::from_random(&mut rng);
        let signer_2 = Ed25519Pair::from_random(&mut rng);

        let prefix = MintTxPrefix {
            token_id: token_id,
            amount: 1,
            view_public_key: RistrettoPublic::from_random(&mut rng),
            spend_public_key: RistrettoPublic::from_random(&mut rng),
            nonce: vec![1u8; NONCE_MIN_LENGTH],
            tombstone_block: 10,
        };
        let message = prefix.hash();
        let signature = MultiSig::new(vec![signer_1.try_sign(message.as_ref()).unwrap()]);
        let tx = MintTx { prefix, signature };

        let signer_set = SignerSet::new(vec![signer_2.public_key()], 1);

        assert_eq!(validate_signature(&tx, &signer_set), Err(Error::Signature));
    }

    #[test]
    fn validate_signature_rejects_tampered_messages() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let token_id = 123;
        let signer_1 = Ed25519Pair::from_random(&mut rng);

        let prefix = MintTxPrefix {
            token_id: token_id,
            amount: 1,
            view_public_key: RistrettoPublic::from_random(&mut rng),
            spend_public_key: RistrettoPublic::from_random(&mut rng),
            nonce: vec![1u8; NONCE_MIN_LENGTH],
            tombstone_block: 10,
        };
        let message = prefix.hash();
        let signature = MultiSig::new(vec![signer_1.try_sign(message.as_ref()).unwrap()]);
        let signer_set = SignerSet::new(vec![signer_1.public_key()], 1);

        let mut prefix1 = prefix.clone();
        prefix1.amount = 2;
        let tx = MintTx {
            prefix: prefix1,
            signature: signature.clone(),
        };
        assert_eq!(validate_signature(&tx, &signer_set), Err(Error::Signature));

        let mut prefix2 = prefix.clone();
        prefix2.token_id += 1;
        let tx = MintTx {
            prefix: prefix2,
            signature: signature.clone(),
        };
        assert_eq!(validate_signature(&tx, &signer_set), Err(Error::Signature));

        let mut prefix3 = prefix.clone();
        prefix3.nonce.push(5);
        let tx = MintTx {
            prefix: prefix3,
            signature,
        };
        assert_eq!(validate_signature(&tx, &signer_set), Err(Error::Signature));
    }
}
