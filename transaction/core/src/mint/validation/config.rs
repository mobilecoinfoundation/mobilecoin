// Copyright (c) 2018-2022 The MobileCoin Foundation

//! MintConfigTx transaction validation.

use crate::{
    mint::{
        config::{MintConfig, MintConfigTx},
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
/// * `master_minters` - The set of signers that are allowed to sign
///   MintConfigTx transactions.
pub fn validate_mint_config_tx(
    tx: &MintConfigTx,
    current_block_index: u64,
    block_version: BlockVersion,
    master_minters: &SignerSet<Ed25519Public>,
) -> Result<(), Error> {
    validate_block_version(block_version)?;

    validate_token_id(tx.prefix.token_id)?;

    validate_configs(tx.prefix.token_id, &tx.prefix.configs)?;

    validate_nonce(&tx.prefix.nonce)?;

    validate_tombstone(current_block_index, tx.prefix.tombstone_block)?;

    validate_signature(tx, master_minters)?;

    Ok(())
}

/// The minting configurations must all point to the same token id, and must
/// have a valid signer set.
///
/// # Arguments
/// * `token_id` - The token id we are trying to mint.
/// * `configs` - The minting configurations to validate.
fn validate_configs(token_id: u32, configs: &[MintConfig]) -> Result<(), Error> {
    for config in configs {
        if config.token_id != token_id {
            return Err(Error::InvalidTokenId(config.token_id));
        }

        let num_signers = config.signer_set.signers().len();
        if num_signers == 0 || num_signers < config.signer_set.threshold() as usize {
            return Err(Error::InvalidSignerSet);
        }
    }

    Ok(())
}

/// The transaction must be properly signed by the master minters set.
///
/// # Arguments
/// * `tx` - A pending transaction that is being validated.
/// * `signer_set` - The signer set that is permitted to sign the transaction.
fn validate_signature(
    tx: &MintConfigTx,
    master_minters: &SignerSet<Ed25519Public>,
) -> Result<(), Error> {
    let message = tx.prefix.hash();

    master_minters
        .verify(&message[..], &tx.signature)
        .map_err(|_| Error::InvalidSignature)
        .map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mint::{config::MintConfigTxPrefix, constants::NONCE_LENGTH};
    use mc_crypto_keys::{Ed25519Pair, Signer};
    use mc_crypto_multisig::MultiSig;
    use mc_util_from_random::FromRandom;
    use rand::{rngs::StdRng, SeedableRng};

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
            Err(Error::InvalidTokenId(234))
        );

        assert_eq!(
            validate_configs(1, &[mint_config1.clone(), mint_config2.clone()]),
            Err(Error::InvalidTokenId(123))
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
            Err(Error::InvalidSignerSet)
        );
        assert_eq!(
            validate_configs(token_id, &[mint_config2]),
            Err(Error::InvalidSignerSet)
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

        let prefix = MintConfigTxPrefix {
            token_id: token_id,
            configs: vec![mint_config1.clone(), mint_config2.clone()],
            nonce: vec![2u8; NONCE_LENGTH],
            tombstone_block: 123,
        };
        let message = prefix.hash();

        // Try with 1 out of 3 signers.
        let signature = MultiSig::new(vec![master_minter_1.try_sign(message.as_ref()).unwrap()]);
        let tx = MintConfigTx {
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
        let tx = MintConfigTx {
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
        let tx = MintConfigTx {
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
        let tx = MintConfigTx { prefix, signature };
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

        let prefix = MintConfigTxPrefix {
            token_id: token_id,
            configs: vec![mint_config1.clone(), mint_config2.clone()],
            nonce: vec![2u8; NONCE_LENGTH],
            tombstone_block: 123,
        };
        let message = prefix.hash();

        // Tamper with the mint limit.
        let signature = MultiSig::new(vec![master_minter_1.try_sign(message.as_ref()).unwrap()]);
        let mut tx = MintConfigTx {
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
            Err(Error::InvalidSignature)
        );

        // Tamper with the tombstone block.
        let signature = MultiSig::new(vec![master_minter_1.try_sign(message.as_ref()).unwrap()]);
        let mut tx = MintConfigTx {
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
            Err(Error::InvalidSignature)
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

        let prefix = MintConfigTxPrefix {
            token_id: token_id,
            configs: vec![mint_config1.clone(), mint_config2.clone()],
            nonce: vec![2u8; NONCE_LENGTH],
            tombstone_block: 123,
        };
        let message = prefix.hash();

        // Signing below threshold
        let signature = MultiSig::new(vec![master_minter_1.try_sign(message.as_ref()).unwrap()]);
        let tx = MintConfigTx {
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
            Err(Error::InvalidSignature)
        );

        // Signing with unknown signers.
        let signature = MultiSig::new(vec![master_minter_1.try_sign(message.as_ref()).unwrap()]);
        let tx = MintConfigTx {
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
            Err(Error::InvalidSignature)
        );

        // Signing below threshold with one known signers and one unknown.
        let signature = MultiSig::new(vec![
            master_minter_1.try_sign(message.as_ref()).unwrap(),
            master_minter_2.try_sign(message.as_ref()).unwrap(),
        ]);
        let tx = MintConfigTx {
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
            Err(Error::InvalidSignature)
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

        let prefix = MintConfigTxPrefix {
            token_id: token_id,
            configs: vec![mint_config1.clone(), mint_config2.clone()],
            nonce: vec![2u8; NONCE_LENGTH],
            tombstone_block: 123,
        };
        let message = prefix.hash();

        // Signing below threshold (duplicate singer not counted twice)
        let signature = MultiSig::new(vec![
            master_minter_1.try_sign(message.as_ref()).unwrap(),
            master_minter_1.try_sign(message.as_ref()).unwrap(),
        ]);
        let tx = MintConfigTx {
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
            Err(Error::InvalidSignature)
        );
    }
}
