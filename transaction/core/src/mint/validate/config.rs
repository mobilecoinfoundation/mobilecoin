// Copyright (c) 2018-2022 The MobileCoin Foundation

//! SetMintConfigTx transaction validation.

use crate::{
    mint::{
        config::{MintConfig, SetMintConfigTx},
        constants::{NONCE_MAX_LENGTH, NONCE_MIN_LENGTH},
    },
    validation::{validate_tombstone, TransactionValidationError},
    BlockVersion, TokenId,
};
use displaydoc::Display;
use mc_crypto_keys::Ed25519Public;
use mc_crypto_multisig::SignerSet;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Display, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum Error {
    /// Invalid block version: {0}
    BlockVersion(BlockVersion),

    /// Invalid token id: {0}
    TokenId(u32),

    /// Invalid nonce length: {0}
    NonceLength(usize),

    /// Invalid signer set
    SignerSet,

    /// Invalid signature
    Signature,

    /// Number of blocks in ledger exceeds the tombstone block number
    TombstoneBlockExceeded,

    /// Tombstone block is too far in the future
    TombstoneBlockTooFar,

    /// Unknown error (should never happen)
    Unknown,
}

/// Determines if the transaction is valid, with respect to the provided
/// context.
///
/// # Arguments
/// * `tx` - A pending transaction.
/// * `current_block_index` - The index of the current block that is being
///   built.
/// * `block_version` - The version of the block that is being built.
/// * `master_minters` - The set of signers that are allowed to sign
///   SetMintConfigTx transactions.
pub fn validate_set_mint_config_tx(
    tx: &SetMintConfigTx,
    current_block_index: u64,
    block_version: BlockVersion,
    master_minters: &SignerSet<Ed25519Public>,
) -> Result<(), Error> {
    validate_block_version(block_version)?;

    validate_token_id(tx.prefix.token_id)?;

    validate_configs(tx.prefix.token_id, &tx.prefix.configs)?;

    validate_nonce(&tx.prefix.nonce)?;

    validate_tombstone(current_block_index, tx.prefix.tombstone_block).map_err(
        |err| match err {
            TransactionValidationError::TombstoneBlockExceeded => Error::TombstoneBlockExceeded,
            TransactionValidationError::TombstoneBlockTooFar => Error::TombstoneBlockTooFar,
            _ => Error::Unknown, /* This should never happen since validate_tombstone only
                                  * returns one of the two error types above */
        },
    )?;

    validate_signature(tx, master_minters)?;

    Ok(())
}

/// The current block version being built must support minting.
fn validate_block_version(block_version: BlockVersion) -> Result<(), Error> {
    // TODO this should actually be block version THREE!
    if block_version < BlockVersion::TWO || BlockVersion::MAX < block_version {
        return Err(Error::BlockVersion(block_version));
    }

    Ok(())
}

/// The token id being minted must be supported.
fn validate_token_id(token_id: u32) -> Result<(), Error> {
    if token_id == *TokenId::MOB {
        return Err(Error::TokenId(token_id));
    }

    Ok(())
}

/// The minting configurations must all point to the same token id, and must
/// have a valid signer set.
fn validate_configs(token_id: u32, configs: &[MintConfig]) -> Result<(), Error> {
    for config in configs {
        if config.token_id != token_id {
            return Err(Error::TokenId(config.token_id));
        }

        let num_signers = config.signer_set.signers().len();
        if num_signers == 0 || num_signers < config.signer_set.threshold() as usize {
            return Err(Error::SignerSet);
        }
    }

    Ok(())
}

/// The nonce must be within the hardcoded lenght limit.
fn validate_nonce(nonce: &[u8]) -> Result<(), Error> {
    if nonce.len() < NONCE_MIN_LENGTH || nonce.len() > NONCE_MAX_LENGTH {
        return Err(Error::NonceLength(nonce.len()));
    }

    Ok(())
}

/// The transaction must be properly signed by the master minters set.
fn validate_signature(
    tx: &SetMintConfigTx,
    master_minters: &SignerSet<Ed25519Public>,
) -> Result<(), Error> {
    let message = tx.prefix.hash();

    master_minters
        .verify(&message[..], &tx.signature)
        .map_err(|_| Error::Signature)
        .map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mint::config::SetMintConfigTxPrefix;
    use mc_crypto_keys::{Ed25519Pair, Signer};
    use mc_crypto_multisig::MultiSig;
    use mc_util_from_random::FromRandom;
    use rand::{rngs::StdRng, SeedableRng};
    #[test]
    fn validate_block_version_accepts_valid_block_versions() {
        assert!(validate_block_version(BlockVersion::TWO).is_ok()); // TODO needs to be three
        assert!(validate_block_version(BlockVersion::MAX).is_ok()); // TODO needs to be three
    }

    #[test]
    fn validate_block_version_rejects_unsupported_block_versions() {
        assert_eq!(
            validate_block_version(BlockVersion::ONE),
            Err(Error::BlockVersion(BlockVersion::ONE))
        );
    }

    #[test]
    fn validate_token_id_accepts_valid_token_ids() {
        assert!(validate_token_id(1).is_ok());
        assert!(validate_token_id(10).is_ok());
    }

    #[test]
    fn validate_token_id_rejects_invalid_token_ids() {
        assert_eq!(validate_token_id(0), Err(Error::TokenId(0)));
    }

    #[test]
    fn validate_configs_accepts_valid_mint_configs() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let token_id = 123;
        let signer_1 = Ed25519Pair::from_random(&mut rng);
        let signer_2 = Ed25519Pair::from_random(&mut rng);
        let signer_3 = Ed25519Pair::from_random(&mut rng);

        let mint_config1 = MintConfig {
            token_id: token_id,
            signer_set: SignerSet::new(vec![signer_1.public_key()], 1),
            mint_limit: 10,
        };

        let mint_config2 = MintConfig {
            token_id: token_id,
            signer_set: SignerSet::new(vec![signer_2.public_key()], 1),
            mint_limit: 15,
        };

        let mint_config3 = MintConfig {
            token_id: token_id,
            signer_set: SignerSet::new(vec![signer_2.public_key(), signer_3.public_key()], 1),
            mint_limit: 15,
        };
        let mint_config4 = MintConfig {
            token_id: token_id,
            signer_set: SignerSet::new(vec![signer_2.public_key(), signer_3.public_key()], 2),
            mint_limit: 15,
        };

        assert!(validate_configs(
            token_id,
            &[mint_config1, mint_config2, mint_config3, mint_config4]
        )
        .is_ok());
    }

    #[test]
    fn validate_configs_rejects_mismatching_token_ids() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let signer_1 = Ed25519Pair::from_random(&mut rng);
        let signer_2 = Ed25519Pair::from_random(&mut rng);

        let mint_config1 = MintConfig {
            token_id: 123,
            signer_set: SignerSet::new(vec![signer_1.public_key()], 1),
            mint_limit: 10,
        };

        let mint_config2 = MintConfig {
            token_id: 234,
            signer_set: SignerSet::new(vec![signer_2.public_key()], 1),
            mint_limit: 15,
        };

        assert_eq!(
            validate_configs(123, &[mint_config1.clone(), mint_config2.clone()]),
            Err(Error::TokenId(234))
        );

        assert_eq!(
            validate_configs(1, &[mint_config1.clone(), mint_config2.clone()]),
            Err(Error::TokenId(123))
        );
    }

    #[test]
    fn validate_configs_rejects_invalid_signer_sets() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let signer_1 = Ed25519Pair::from_random(&mut rng);
        let token_id = 123;

        let mint_config1 = MintConfig {
            token_id: token_id,
            signer_set: SignerSet::new(vec![signer_1.public_key()], 2), /* threshold > number of
                                                                         * signers */
            mint_limit: 10,
        };

        let mint_config2 = MintConfig {
            token_id: token_id,
            signer_set: SignerSet::new(vec![], 1), // no signers
            mint_limit: 15,
        };

        assert_eq!(
            validate_configs(token_id, &[mint_config1]),
            Err(Error::SignerSet)
        );
        assert_eq!(
            validate_configs(token_id, &[mint_config2]),
            Err(Error::SignerSet)
        );
    }

    #[test]
    fn validate_nonce_accepts_valid_nonces() {
        validate_nonce(&[1u8; NONCE_MIN_LENGTH]).unwrap();
        validate_nonce(&[1u8; NONCE_MIN_LENGTH + 1]).unwrap();
        validate_nonce(&[1u8; NONCE_MAX_LENGTH]).unwrap();
    }

    #[test]
    fn validate_nonce_rejects_valid_nonces() {
        assert_eq!(validate_nonce(&[]), Err(Error::NonceLength(0)));
        assert_eq!(
            validate_nonce(&[1u8; NONCE_MIN_LENGTH - 1]),
            Err(Error::NonceLength(NONCE_MIN_LENGTH - 1))
        );
        assert_eq!(
            validate_nonce(&[1u8; NONCE_MAX_LENGTH + 1]),
            Err(Error::NonceLength(NONCE_MAX_LENGTH + 1))
        );
    }

    #[test]
    fn validate_signature_accepts_valid_signature() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let signer_1 = Ed25519Pair::from_random(&mut rng);
        let signer_2 = Ed25519Pair::from_random(&mut rng);
        let token_id = 123;

        let mint_config1 = MintConfig {
            token_id: 123,
            signer_set: SignerSet::new(vec![signer_1.public_key()], 1),
            mint_limit: 10,
        };

        let mint_config2 = MintConfig {
            token_id: 234,
            signer_set: SignerSet::new(vec![signer_2.public_key()], 1),
            mint_limit: 15,
        };

        let master_minter_1 = Ed25519Pair::from_random(&mut rng);
        let master_minter_2 = Ed25519Pair::from_random(&mut rng);
        let master_minter_3 = Ed25519Pair::from_random(&mut rng);

        let prefix = SetMintConfigTxPrefix {
            token_id: token_id,
            configs: vec![mint_config1.clone(), mint_config2.clone()],
            nonce: vec![2u8; NONCE_MIN_LENGTH],
            tombstone_block: 123,
        };
        let message = prefix.hash();

        // Try with 1 out of 3 signers.
        let signature = MultiSig::new(vec![master_minter_1.try_sign(message.as_ref()).unwrap()]);
        let tx = SetMintConfigTx {
            prefix: prefix.clone(),
            signature,
        };
        assert!(validate_signature(
            &tx,
            &SignerSet::new(
                vec![
                    master_minter_1.public_key(),
                    master_minter_2.public_key(),
                    master_minter_3.public_key()
                ],
                1
            )
        )
        .is_ok());

        // Try with 2 out of 3 signers.
        let signature = MultiSig::new(vec![
            master_minter_1.try_sign(message.as_ref()).unwrap(),
            master_minter_2.try_sign(message.as_ref()).unwrap(),
        ]);
        let tx = SetMintConfigTx {
            prefix: prefix.clone(),
            signature,
        };
        assert!(validate_signature(
            &tx,
            &SignerSet::new(
                vec![
                    master_minter_1.public_key(),
                    master_minter_2.public_key(),
                    master_minter_3.public_key()
                ],
                2
            )
        )
        .is_ok());

        // Try with different 2 out of 3 signers.
        let signature = MultiSig::new(vec![
            master_minter_3.try_sign(message.as_ref()).unwrap(),
            master_minter_1.try_sign(message.as_ref()).unwrap(),
        ]);
        let tx = SetMintConfigTx {
            prefix: prefix.clone(),
            signature,
        };
        assert!(validate_signature(
            &tx,
            &SignerSet::new(
                vec![
                    master_minter_1.public_key(),
                    master_minter_2.public_key(),
                    master_minter_3.public_key()
                ],
                2
            )
        )
        .is_ok());

        // Try with 3 out of 3 signers.
        let signature = MultiSig::new(vec![
            master_minter_1.try_sign(message.as_ref()).unwrap(),
            master_minter_2.try_sign(message.as_ref()).unwrap(),
            master_minter_3.try_sign(message.as_ref()).unwrap(),
        ]);
        let tx = SetMintConfigTx { prefix, signature };
        assert!(validate_signature(
            &tx,
            &SignerSet::new(
                vec![
                    master_minter_1.public_key(),
                    master_minter_2.public_key(),
                    master_minter_3.public_key()
                ],
                3
            )
        )
        .is_ok());
    }

    #[test]
    fn validate_signature_rejects_tampered_messages() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

        let signer_1 = Ed25519Pair::from_random(&mut rng);
        let signer_2 = Ed25519Pair::from_random(&mut rng);
        let token_id = 123;

        let mint_config1 = MintConfig {
            token_id: 123,
            signer_set: SignerSet::new(vec![signer_1.public_key()], 1),
            mint_limit: 10,
        };

        let mint_config2 = MintConfig {
            token_id: 234,
            signer_set: SignerSet::new(vec![signer_2.public_key()], 1),
            mint_limit: 15,
        };

        let master_minter_1 = Ed25519Pair::from_random(&mut rng);
        let master_minter_2 = Ed25519Pair::from_random(&mut rng);
        let master_minter_3 = Ed25519Pair::from_random(&mut rng);

        let prefix = SetMintConfigTxPrefix {
            token_id: token_id,
            configs: vec![mint_config1.clone(), mint_config2.clone()],
            nonce: vec![2u8; NONCE_MIN_LENGTH],
            tombstone_block: 123,
        };
        let message = prefix.hash();

        // Tamper with the mint limit.
        let signature = MultiSig::new(vec![master_minter_1.try_sign(message.as_ref()).unwrap()]);
        let mut tx = SetMintConfigTx {
            prefix: prefix.clone(),
            signature,
        };
        tx.prefix.configs[0].mint_limit += 1;
        assert_eq!(
            validate_signature(
                &tx,
                &SignerSet::new(
                    vec![
                        master_minter_1.public_key(),
                        master_minter_2.public_key(),
                        master_minter_3.public_key()
                    ],
                    1
                )
            ),
            Err(Error::Signature)
        );

        // Tamper with the tombstone block.
        let signature = MultiSig::new(vec![master_minter_1.try_sign(message.as_ref()).unwrap()]);
        let mut tx = SetMintConfigTx {
            prefix: prefix.clone(),
            signature,
        };
        tx.prefix.tombstone_block += 1;
        assert_eq!(
            validate_signature(
                &tx,
                &SignerSet::new(
                    vec![
                        master_minter_1.public_key(),
                        master_minter_2.public_key(),
                        master_minter_3.public_key()
                    ],
                    1
                )
            ),
            Err(Error::Signature)
        );
    }

    #[test]
    fn validate_signature_rejects_signers_mismatch() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

        let signer_1 = Ed25519Pair::from_random(&mut rng);
        let signer_2 = Ed25519Pair::from_random(&mut rng);
        let token_id = 123;

        let mint_config1 = MintConfig {
            token_id: 123,
            signer_set: SignerSet::new(vec![signer_1.public_key()], 1),
            mint_limit: 10,
        };

        let mint_config2 = MintConfig {
            token_id: 234,
            signer_set: SignerSet::new(vec![signer_2.public_key()], 1),
            mint_limit: 15,
        };

        let master_minter_1 = Ed25519Pair::from_random(&mut rng);
        let master_minter_2 = Ed25519Pair::from_random(&mut rng);
        let master_minter_3 = Ed25519Pair::from_random(&mut rng);

        let prefix = SetMintConfigTxPrefix {
            token_id: token_id,
            configs: vec![mint_config1.clone(), mint_config2.clone()],
            nonce: vec![2u8; NONCE_MIN_LENGTH],
            tombstone_block: 123,
        };
        let message = prefix.hash();

        // Signing below threshold
        let signature = MultiSig::new(vec![master_minter_1.try_sign(message.as_ref()).unwrap()]);
        let tx = SetMintConfigTx {
            prefix: prefix.clone(),
            signature,
        };
        assert_eq!(
            validate_signature(
                &tx,
                &SignerSet::new(
                    vec![
                        master_minter_1.public_key(),
                        master_minter_2.public_key(),
                        master_minter_3.public_key()
                    ],
                    2
                )
            ),
            Err(Error::Signature)
        );

        // Signing with unknown signers.
        let signature = MultiSig::new(vec![master_minter_1.try_sign(message.as_ref()).unwrap()]);
        let tx = SetMintConfigTx {
            prefix: prefix.clone(),
            signature,
        };
        assert_eq!(
            validate_signature(
                &tx,
                &SignerSet::new(
                    vec![master_minter_2.public_key(), master_minter_3.public_key()],
                    1
                )
            ),
            Err(Error::Signature)
        );

        // Signing below threshold with one known signers and one unknown.
        let signature = MultiSig::new(vec![
            master_minter_1.try_sign(message.as_ref()).unwrap(),
            master_minter_2.try_sign(message.as_ref()).unwrap(),
        ]);
        let tx = SetMintConfigTx {
            prefix: prefix.clone(),
            signature,
        };
        assert_eq!(
            validate_signature(
                &tx,
                &SignerSet::new(
                    vec![master_minter_2.public_key(), master_minter_3.public_key()],
                    2
                )
            ),
            Err(Error::Signature)
        );
    }

    #[test]
    fn validate_signature_rejects_duplicate_signer() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

        let signer_1 = Ed25519Pair::from_random(&mut rng);
        let signer_2 = Ed25519Pair::from_random(&mut rng);
        let token_id = 123;

        let mint_config1 = MintConfig {
            token_id: 123,
            signer_set: SignerSet::new(vec![signer_1.public_key()], 1),
            mint_limit: 10,
        };

        let mint_config2 = MintConfig {
            token_id: 234,
            signer_set: SignerSet::new(vec![signer_2.public_key()], 1),
            mint_limit: 15,
        };

        let master_minter_1 = Ed25519Pair::from_random(&mut rng);
        let master_minter_2 = Ed25519Pair::from_random(&mut rng);
        let master_minter_3 = Ed25519Pair::from_random(&mut rng);

        let prefix = SetMintConfigTxPrefix {
            token_id: token_id,
            configs: vec![mint_config1.clone(), mint_config2.clone()],
            nonce: vec![2u8; NONCE_MIN_LENGTH],
            tombstone_block: 123,
        };
        let message = prefix.hash();

        // Signing below threshold (duplicate isnger not counted twice)
        let signature = MultiSig::new(vec![
            master_minter_1.try_sign(message.as_ref()).unwrap(),
            master_minter_1.try_sign(message.as_ref()).unwrap(),
        ]);
        let tx = SetMintConfigTx {
            prefix: prefix.clone(),
            signature,
        };
        assert_eq!(
            validate_signature(
                &tx,
                &SignerSet::new(
                    vec![
                        master_minter_1.public_key(),
                        master_minter_2.public_key(),
                        master_minter_3.public_key()
                    ],
                    2
                )
            ),
            Err(Error::Signature)
        );
    }
}
