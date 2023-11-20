// Copyright (c) 2018-2022 The MobileCoin Foundation

//! MintTxManager provides the backend for the mc-consensus-scp validation and
//! combine callbacks.
//!
//! This file contains the actual implementation of the validation and combine
//! logic mint-related transactions.

mod error;
mod traits;

pub use error::{MintTxManagerError, MintTxManagerResult};
pub use traits::MintTxManager;

#[cfg(test)]
pub use traits::MockMintTxManager;

use crate::timestamp_validator;
use mc_common::{
    logger::{log, Logger},
    HashSet,
};
use mc_consensus_enclave::GovernorsMap;
use mc_ledger_db::{Error as LedgerError, Ledger};
use mc_transaction_core::{
    mint::{
        validate_mint_config_tx, validate_mint_tx, MintConfig, MintConfigTx, MintTx,
        MintValidationError,
    },
    BlockVersion, TokenId,
};

#[derive(Clone)]
pub struct MintTxManagerImpl<L: Ledger> {
    /// Ledger DB.
    ledger_db: L,

    /// The configured block version.
    block_version: BlockVersion,

    /// A map of token id -> governors.
    token_id_to_governors: GovernorsMap,

    /// Logger.
    logger: Logger,
}

impl<L: Ledger> MintTxManagerImpl<L> {
    pub fn new(
        ledger_db: L,
        block_version: BlockVersion,
        token_id_to_governors: GovernorsMap,
        logger: Logger,
    ) -> Self {
        Self {
            ledger_db,
            block_version,
            token_id_to_governors,
            logger,
        }
    }
}

impl<L: Ledger> MintTxManager for MintTxManagerImpl<L> {
    fn validate_mint_config_tx(
        &self,
        mint_config_tx: &MintConfigTx,
        timestamp: Option<u64>,
    ) -> MintTxManagerResult<()> {
        let latest_block = self.ledger_db.get_latest_block()?;

        if let Some(timestamp) = timestamp {
            timestamp_validator::validate(timestamp, &latest_block)?;
        }

        // Ensure that we have not seen this transaction before.
        if self
            .ledger_db
            .check_mint_config_tx_nonce(
                mint_config_tx.prefix.token_id,
                &mint_config_tx.prefix.nonce,
            )?
            .is_some()
        {
            return Err(MintTxManagerError::MintValidation(
                MintValidationError::NonceAlreadyUsed,
            ));
        }

        // Get the governors for this token id.
        let token_id = TokenId::from(mint_config_tx.prefix.token_id);
        let governors = self
            .token_id_to_governors
            .get_governors_for_token(&token_id)
            .ok_or(MintTxManagerError::MintValidation(
                MintValidationError::NoGovernors(token_id),
            ))?;

        // Perform the actual validation.
        validate_mint_config_tx(
            mint_config_tx,
            Some(latest_block.index + 1),
            self.block_version,
            &governors,
        )?;

        Ok(())
    }

    fn combine_mint_config_txs(
        &self,
        txs: &[(MintConfigTx, u64)],
        max_elements: usize,
    ) -> MintTxManagerResult<Vec<(MintConfigTx, u64)>> {
        let mut candidates = timestamp_validator::sort_and_dedup(txs.iter());
        candidates.truncate(max_elements);
        Ok(candidates)
    }

    fn validate_mint_tx(
        &self,
        mint_tx: &MintTx,
        timestamp: Option<u64>,
    ) -> MintTxManagerResult<()> {
        let latest_block = self.ledger_db.get_latest_block()?;

        if let Some(timestamp) = timestamp {
            timestamp_validator::validate(timestamp, &latest_block)?;
        }

        // Ensure that we have not seen this transaction before.
        if self
            .ledger_db
            .check_mint_tx_nonce(mint_tx.prefix.token_id, &mint_tx.prefix.nonce)?
            .is_some()
        {
            return Err(MintTxManagerError::MintValidation(
                MintValidationError::NonceAlreadyUsed,
            ));
        }

        // Try and get an active minting configuration that can validate the signature
        // of this transaction.
        let active_mint_config = self
            .ledger_db
            .get_active_mint_config_for_mint_tx(mint_tx)
            .map_err(|err| match err {
                LedgerError::NotFound => {
                    MintTxManagerError::MintValidation(MintValidationError::NoMatchingMintConfig)
                }
                LedgerError::MintLimitExceeded(_, _, _) => {
                    MintTxManagerError::MintValidation(MintValidationError::AmountExceedsMintLimit)
                }
                err => err.into(),
            })?;

        // Perform the actual validation.
        validate_mint_tx(
            mint_tx,
            latest_block.index + 1,
            self.block_version,
            &active_mint_config.mint_config,
        )?;

        Ok(())
    }

    fn combine_mint_txs(
        &self,
        txs: &[(MintTx, u64)],
        max_elements: usize,
    ) -> MintTxManagerResult<Vec<(MintTx, u64)>> {
        let candidates = timestamp_validator::sort_and_dedup(txs.iter());

        let mut seen_mint_configs = HashSet::default();
        let allowed_txs = candidates
            .into_iter()
            .filter(|(tx, _)| {
                // We allow a specific MintConfig to be used only once per block - this
                // simplifies enforcing the total mint limit.
                let active_mint_config = match self.ledger_db.get_active_mint_config_for_mint_tx(tx)
                {
                    Ok(active_mint_config) => active_mint_config,
                    Err(err) => {
                        log::warn!(
                            self.logger,
                            "failed finding an active mint config for mint tx {}: {}",
                            tx,
                            err
                        );
                        return false;
                    }
                };
                if seen_mint_configs.contains(&active_mint_config.mint_config) {
                    return false;
                }

                seen_mint_configs.insert(active_mint_config.mint_config);
                true
            })
            .take(max_elements)
            .collect();

        Ok(allowed_txs)
    }

    fn mint_txs_with_config(
        &self,
        txs: &[MintTx],
    ) -> MintTxManagerResult<Vec<(MintTx, MintConfigTx, MintConfig)>> {
        txs.iter()
            .map(|mint_tx| {
                let active_mint_configs = self
                    .ledger_db
                    .get_active_mint_configs(TokenId::from(mint_tx.prefix.token_id))?
                    .ok_or(MintTxManagerError::MintValidation(
                        MintValidationError::NoMatchingMintConfig,
                    ))?;

                let active_mint_config =
                    active_mint_configs.get_active_mint_config_for_mint_tx(mint_tx)?;

                Ok((
                    mint_tx.clone(),
                    active_mint_configs.mint_config_tx,
                    active_mint_config.mint_config,
                ))
            })
            .collect::<MintTxManagerResult<_>>()
    }
}

#[cfg(test)]
mod mint_config_tx_tests {
    use super::*;
    use assert_matches::assert_matches;
    use mc_blockchain_types::BlockContents;
    use mc_common::logger::test_with_logger;
    use mc_crypto_multisig::SignerSet;
    use mc_ledger_db::test_utils::{
        add_block_contents_to_ledger, create_ledger, initialize_ledger,
    };
    use mc_transaction_core::ring_signature::KeyImage;
    use mc_transaction_core_test_utils::{
        create_mint_config_tx_and_signers, create_test_tx_out,
        mint_config_tx_to_validated as to_validated, AccountKey,
    };
    use rand::{rngs::StdRng, SeedableRng};
    use std::time::SystemTime;

    const BLOCK_VERSION: BlockVersion = BlockVersion::MAX;

    /// validate_mint_config_tx accepts a valid mint config tx when only a
    /// single token is configured.
    #[test_with_logger]
    fn validate_mint_config_tx_accepts_valid_tx_single_token(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([77u8; 32]);
        let token_id_1 = TokenId::from(1);

        let mut ledger = create_ledger();
        let n_blocks = 1;
        let sender = AccountKey::random(&mut rng);
        initialize_ledger(BLOCK_VERSION, &mut ledger, n_blocks, &sender, &mut rng);

        let (mint_config_tx, signers) = create_mint_config_tx_and_signers(token_id_1, &mut rng);
        let token_id_to_governors = GovernorsMap::try_from_iter(vec![(
            token_id_1,
            SignerSet::new(signers.iter().map(|s| s.public_key()).collect(), 1),
        )])
        .unwrap();
        let mint_tx_manager =
            MintTxManagerImpl::new(ledger, BLOCK_VERSION, token_id_to_governors, logger);

        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("Failed getting the system time")
            .as_millis() as u64;

        assert_eq!(
            mint_tx_manager.validate_mint_config_tx(&mint_config_tx, Some(now)),
            Ok(())
        );
    }

    /// validate_mint_config_tx accepts a valid mint config tx when multiple
    /// tokens are configured.
    #[test_with_logger]
    fn validate_mint_config_tx_accepts_valid_tx_multiple_tokens(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([77u8; 32]);
        let token_id_1 = TokenId::from(1);
        let token_id_2 = TokenId::from(2);
        let token_id_3 = TokenId::from(3);

        let mut ledger = create_ledger();
        let n_blocks = 1;
        let sender = AccountKey::random(&mut rng);
        initialize_ledger(BLOCK_VERSION, &mut ledger, n_blocks, &sender, &mut rng);

        let (mint_config_tx1, signers1) = create_mint_config_tx_and_signers(token_id_1, &mut rng);
        let (mint_config_tx2, signers2) = create_mint_config_tx_and_signers(token_id_2, &mut rng);
        let (mint_config_tx3, signers3) = create_mint_config_tx_and_signers(token_id_3, &mut rng);
        let token_id_to_governors = GovernorsMap::try_from_iter(vec![
            (
                token_id_1,
                SignerSet::new(signers1.iter().map(|s| s.public_key()).collect(), 1),
            ),
            (
                token_id_2,
                SignerSet::new(signers2.iter().map(|s| s.public_key()).collect(), 1),
            ),
            (
                token_id_3,
                SignerSet::new(signers3.iter().map(|s| s.public_key()).collect(), 1),
            ),
        ])
        .unwrap();
        let mint_tx_manager =
            MintTxManagerImpl::new(ledger, BLOCK_VERSION, token_id_to_governors, logger);

        assert_eq!(
            mint_tx_manager.validate_mint_config_tx(&mint_config_tx1, None),
            Ok(())
        );

        assert_eq!(
            mint_tx_manager.validate_mint_config_tx(&mint_config_tx2, None),
            Ok(())
        );

        assert_eq!(
            mint_tx_manager.validate_mint_config_tx(&mint_config_tx3, None),
            Ok(())
        );
    }

    /// validate_mint_config_tx rejects a mint config tx with an exceeded
    /// tombstone block.
    #[test_with_logger]
    fn validate_mint_config_tx_rejects_past_tombstone(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([77u8; 32]);
        let token_id_1 = TokenId::from(1);

        let (mint_config_tx, signers) = create_mint_config_tx_and_signers(token_id_1, &mut rng);
        let token_id_to_governors = GovernorsMap::try_from_iter(vec![(
            token_id_1,
            SignerSet::new(signers.iter().map(|s| s.public_key()).collect(), 1),
        )])
        .unwrap();

        let mut ledger = create_ledger();
        // tombstone_block specifies that the tx will get accepted at any block whose
        // index is less than tombstone_block. n_blocks controls how many blocks
        // we create, specifically it will result in blocks with indexes [0, n_blocks).
        // setting n_blocks to tombstone_block - 1 means the transaction will be valid
        // for exactly 1 block, but once that's written it will exceed it.
        let n_blocks = mint_config_tx.prefix.tombstone_block - 1;
        let sender = AccountKey::random(&mut rng);
        initialize_ledger(BLOCK_VERSION, &mut ledger, n_blocks, &sender, &mut rng);

        let mint_tx_manager =
            MintTxManagerImpl::new(ledger.clone(), BLOCK_VERSION, token_id_to_governors, logger);

        // At first we should succeed since we have not yet exceeded the tombstone
        // block.
        assert_eq!(
            mint_tx_manager.validate_mint_config_tx(&mint_config_tx, None),
            Ok(())
        );

        // Append a block to the ledger.
        let block_contents = BlockContents {
            outputs: vec![create_test_tx_out(BLOCK_VERSION, &mut rng)],
            key_images: vec![KeyImage::from(123)],
            ..Default::default()
        };
        add_block_contents_to_ledger(&mut ledger, BLOCK_VERSION, block_contents, &mut rng).unwrap();

        // Try again, we should fail.
        assert_eq!(
            mint_tx_manager.validate_mint_config_tx(&mint_config_tx, None),
            Err(MintTxManagerError::MintValidation(
                MintValidationError::TombstoneBlockExceeded
            ))
        );
    }

    /// validate_mint_config_tx rejects a mint config tx with a nonce that
    /// already appears in the ledger.
    #[test_with_logger]
    fn validate_mint_config_tx_rejects_duplicate_nonce(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([77u8; 32]);
        let token_id_1 = TokenId::from(1);

        let mut ledger = create_ledger();
        let n_blocks = 1;
        let sender = AccountKey::random(&mut rng);
        initialize_ledger(BLOCK_VERSION, &mut ledger, n_blocks, &sender, &mut rng);

        let (mint_config_tx, signers) = create_mint_config_tx_and_signers(token_id_1, &mut rng);
        let token_id_to_governors = GovernorsMap::try_from_iter(vec![(
            token_id_1,
            SignerSet::new(signers.iter().map(|s| s.public_key()).collect(), 1),
        )])
        .unwrap();
        let mint_tx_manager =
            MintTxManagerImpl::new(ledger.clone(), BLOCK_VERSION, token_id_to_governors, logger);

        // At first we should succeed since the nonce is not yet in the ledger.
        assert_eq!(
            mint_tx_manager.validate_mint_config_tx(&mint_config_tx, None),
            Ok(())
        );

        // Append to the ledger.
        let block_contents = BlockContents {
            validated_mint_config_txs: vec![to_validated(&mint_config_tx)],
            ..Default::default()
        };
        add_block_contents_to_ledger(&mut ledger, BLOCK_VERSION, block_contents, &mut rng).unwrap();

        // Try again, we should fail.
        assert_eq!(
            mint_tx_manager.validate_mint_config_tx(&mint_config_tx, None),
            Err(MintTxManagerError::MintValidation(
                MintValidationError::NonceAlreadyUsed
            ))
        );
    }

    /// validate_mint_config_tx rejects a valid mint config tx for an unknown
    /// token.
    #[test_with_logger]
    fn validate_mint_config_tx_rejects_unknown_token(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([77u8; 32]);
        let token_id_1 = TokenId::from(1);
        let token_id_2 = TokenId::from(2);

        let mut ledger = create_ledger();
        let n_blocks = 3;
        let sender = AccountKey::random(&mut rng);
        initialize_ledger(BLOCK_VERSION, &mut ledger, n_blocks, &sender, &mut rng);

        let (_mint_config_tx, signers) = create_mint_config_tx_and_signers(token_id_1, &mut rng);
        let token_id_to_governors = GovernorsMap::try_from_iter(vec![(
            token_id_1,
            SignerSet::new(signers.iter().map(|s| s.public_key()).collect(), 1),
        )])
        .unwrap();
        let mint_tx_manager =
            MintTxManagerImpl::new(ledger, BLOCK_VERSION, token_id_to_governors, logger);

        let (mint_config_tx2, _signers) = create_mint_config_tx_and_signers(token_id_2, &mut rng);
        assert_eq!(
            mint_tx_manager.validate_mint_config_tx(&mint_config_tx2, None),
            Err(MintTxManagerError::MintValidation(
                MintValidationError::NoGovernors(token_id_2)
            ))
        );
    }

    /// validate_mint_config_tx rejects an invalid signature.
    /// (This test ensures we call the underlying validation method
    /// `validate_mint_config_tx`)
    #[test_with_logger]
    fn validate_mint_config_tx_rejects_invalid_signature(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([77u8; 32]);
        let token_id_1 = TokenId::from(1);

        let mut ledger = create_ledger();
        let n_blocks = 1;
        let sender = AccountKey::random(&mut rng);
        initialize_ledger(BLOCK_VERSION, &mut ledger, n_blocks, &sender, &mut rng);

        let (mut mint_config_tx, signers) = create_mint_config_tx_and_signers(token_id_1, &mut rng);
        let token_id_to_governors = GovernorsMap::try_from_iter(vec![(
            token_id_1,
            SignerSet::new(signers.iter().map(|s| s.public_key()).collect(), 1),
        )])
        .unwrap();
        let mint_tx_manager =
            MintTxManagerImpl::new(ledger, BLOCK_VERSION, token_id_to_governors, logger);

        mint_config_tx.prefix.tombstone_block += 1;

        assert_eq!(
            mint_tx_manager.validate_mint_config_tx(&mint_config_tx, None),
            Err(MintTxManagerError::MintValidation(
                MintValidationError::InvalidSignature
            ))
        );
    }

    #[test_with_logger]
    fn validate_mint_config_tx_rejects_old_timestamp(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([77u8; 32]);
        let token_id_1 = TokenId::from(1);

        let mut ledger = create_ledger();
        let n_blocks = 1;
        let sender = AccountKey::random(&mut rng);
        initialize_ledger(BLOCK_VERSION, &mut ledger, n_blocks, &sender, &mut rng);

        let (mint_config_tx, signers) = create_mint_config_tx_and_signers(token_id_1, &mut rng);
        let token_id_to_governors = GovernorsMap::try_from_iter(vec![(
            token_id_1,
            SignerSet::new(signers.iter().map(|s| s.public_key()).collect(), 1),
        )])
        .unwrap();
        let mint_tx_manager =
            MintTxManagerImpl::new(ledger, BLOCK_VERSION, token_id_to_governors, logger);

        // 1970 might be a bit extreme, but we only want to show we hooked up
        // the timestamp validator, not the edge cases of it.
        let timestamp_too_old = 0;

        assert_matches!(
            mint_tx_manager.validate_mint_config_tx(&mint_config_tx, Some(timestamp_too_old)),
            Err(MintTxManagerError::Timestamp(_))
        );
    }

    /// combine_mint_config_txs adequately sorts inputs and disposes of
    /// duplicates.
    #[test_with_logger]
    fn combine_mint_config_txs_sorts_and_removes_dupes(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([77u8; 32]);
        let token_id_1 = TokenId::from(1);

        let mut ledger = create_ledger();
        let n_blocks = 3;
        let sender = AccountKey::random(&mut rng);
        initialize_ledger(BLOCK_VERSION, &mut ledger, n_blocks, &sender, &mut rng);

        let (mint_config_tx1, signers) = create_mint_config_tx_and_signers(token_id_1, &mut rng);
        let (mint_config_tx2, _) = create_mint_config_tx_and_signers(token_id_1, &mut rng);
        let (mint_config_tx3, _) = create_mint_config_tx_and_signers(token_id_1, &mut rng);
        let (mint_config_tx4, _) = create_mint_config_tx_and_signers(token_id_1, &mut rng);
        let token_id_to_governors = GovernorsMap::try_from_iter(vec![(
            token_id_1,
            SignerSet::new(signers.iter().map(|s| s.public_key()).collect(), 1),
        )])
        .unwrap();
        let mint_tx_manager =
            MintTxManagerImpl::new(ledger, BLOCK_VERSION, token_id_to_governors, logger);

        let mut expected_result = vec![
            (mint_config_tx1.clone(), 100),
            (mint_config_tx2.clone(), 200),
            (mint_config_tx3.clone(), 300),
            (mint_config_tx4.clone(), 400),
        ];
        expected_result.sort();

        assert_eq!(
            mint_tx_manager.combine_mint_config_txs(
                &[
                    (mint_config_tx3.clone(), 3),
                    (mint_config_tx4, 400),
                    (mint_config_tx1.clone(), 1),
                    (mint_config_tx3.clone(), 300),
                    (mint_config_tx3, 3),
                    (mint_config_tx2.clone(), 2),
                    (mint_config_tx1.clone(), 100),
                    (mint_config_tx1, 1),
                    (mint_config_tx2, 200),
                ],
                100
            ),
            Ok(expected_result)
        );
    }

    /// combine_mint_config_txs adequately sorts inputs and disposes of
    /// duplicates when handling multiple token types.
    #[test_with_logger]
    fn combine_mint_config_txs_sorts_and_removes_dupes_multi_token(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([77u8; 32]);

        let token_id_1 = TokenId::from(1);
        let token_id_2 = TokenId::from(2);

        let mut ledger = create_ledger();
        let n_blocks = 3;
        let block_version = BlockVersion::MAX;
        let sender = AccountKey::random(&mut rng);
        initialize_ledger(block_version, &mut ledger, n_blocks, &sender, &mut rng);

        rng = SeedableRng::from_seed([77u8; 32]);
        let mut rng2: StdRng = SeedableRng::from_seed([77u8; 32]);

        let (mint_config_tx1, signers) = create_mint_config_tx_and_signers(token_id_1, &mut rng);
        let (mint_config_tx2, signers2) = create_mint_config_tx_and_signers(token_id_2, &mut rng2);

        assert_eq!(mint_config_tx1.prefix.nonce, mint_config_tx2.prefix.nonce);

        let token_id_to_governors = GovernorsMap::try_from_iter(vec![
            (
                token_id_1,
                SignerSet::new(signers.iter().map(|s| s.public_key()).collect(), 1),
            ),
            (
                token_id_2,
                SignerSet::new(signers2.iter().map(|s| s.public_key()).collect(), 1),
            ),
        ])
        .unwrap();
        let mint_tx_manager =
            MintTxManagerImpl::new(ledger, BlockVersion::MAX, token_id_to_governors, logger);

        let mut expected_result = vec![
            (mint_config_tx1.clone(), 1000),
            (mint_config_tx2.clone(), 2000),
        ];
        expected_result.sort();

        assert_eq!(
            mint_tx_manager.combine_mint_config_txs(
                &[
                    (mint_config_tx1.clone(), 10),
                    (mint_config_tx2.clone(), 20),
                    (mint_config_tx1.clone(), 1000),
                    (mint_config_tx1, 100),
                    (mint_config_tx2, 2000),
                ],
                100
            ),
            Ok(expected_result)
        );
    }

    /// combine_mint_config_txs adequately caps the number of outputs.
    #[test_with_logger]
    fn combine_mint_config_txs_caps_num_of_outputs(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([77u8; 32]);
        let token_id_1 = TokenId::from(1);

        let mut ledger = create_ledger();
        let n_blocks = 3;
        let sender = AccountKey::random(&mut rng);
        initialize_ledger(BLOCK_VERSION, &mut ledger, n_blocks, &sender, &mut rng);

        let (mint_config_tx1, signers) = create_mint_config_tx_and_signers(token_id_1, &mut rng);
        let (mint_config_tx2, _) = create_mint_config_tx_and_signers(token_id_1, &mut rng);
        let (mint_config_tx3, _) = create_mint_config_tx_and_signers(token_id_1, &mut rng);
        let (mint_config_tx4, _) = create_mint_config_tx_and_signers(token_id_1, &mut rng);
        let (mint_config_tx5, _) = create_mint_config_tx_and_signers(token_id_1, &mut rng);
        let (mint_config_tx6, _) = create_mint_config_tx_and_signers(token_id_1, &mut rng);
        let token_id_to_governors = GovernorsMap::try_from_iter(vec![(
            token_id_1,
            SignerSet::new(signers.iter().map(|s| s.public_key()).collect(), 1),
        )])
        .unwrap();
        let mint_tx_manager =
            MintTxManagerImpl::new(ledger, BLOCK_VERSION, token_id_to_governors, logger);

        let mut expected_result = vec![
            (mint_config_tx1.clone(), 100),
            (mint_config_tx2.clone(), 200),
            (mint_config_tx3.clone(), 300),
            (mint_config_tx4.clone(), 400),
            (mint_config_tx5.clone(), 500),
            (mint_config_tx6.clone(), 600),
        ];
        expected_result.sort();
        expected_result.truncate(3);

        assert_eq!(
            mint_tx_manager.combine_mint_config_txs(
                &[
                    (mint_config_tx3.clone(), 3),
                    (mint_config_tx4, 400),
                    (mint_config_tx1.clone(), 1),
                    (mint_config_tx5, 500),
                    (mint_config_tx3, 300),
                    (mint_config_tx2.clone(), 2),
                    (mint_config_tx1.clone(), 100),
                    (mint_config_tx1, 1),
                    (mint_config_tx2, 200),
                    (mint_config_tx6, 600),
                ],
                3
            ),
            Ok(expected_result)
        );
    }
}

#[cfg(test)]
mod mint_tx_tests {
    use super::*;
    use assert_matches::assert_matches;
    use mc_blockchain_types::BlockContents;
    use mc_common::logger::test_with_logger;
    use mc_crypto_keys::Ed25519Pair;
    use mc_crypto_multisig::SignerSet;
    use mc_ledger_db::test_utils::{
        add_block_contents_to_ledger, create_ledger, initialize_ledger,
    };
    use mc_transaction_core::ring_signature::KeyImage;
    use mc_transaction_core_test_utils::{
        create_mint_config_tx_and_signers, create_mint_tx, create_test_tx_out,
        mint_config_tx_to_validated as to_validated, AccountKey,
    };
    use rand::{rngs::StdRng, SeedableRng};
    use std::time::SystemTime;

    const BLOCK_VERSION: BlockVersion = BlockVersion::MAX;

    /// validate_mint_tx accepts a valid mint tx when a single token is
    /// configured.
    #[test_with_logger]
    fn validate_mint_tx_accepts_valid_tx_single_token(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([77u8; 32]);
        let token_id_1 = TokenId::from(1);

        let mut ledger = create_ledger();
        let n_blocks = 3;
        let sender = AccountKey::random(&mut rng);
        initialize_ledger(BLOCK_VERSION, &mut ledger, n_blocks, &sender, &mut rng);

        // Create a mint configuration and append it to the ledger.
        let (mint_config_tx, signers) = create_mint_config_tx_and_signers(token_id_1, &mut rng);

        let block_contents = BlockContents {
            validated_mint_config_txs: vec![to_validated(&mint_config_tx)],
            ..Default::default()
        };
        add_block_contents_to_ledger(&mut ledger, BLOCK_VERSION, block_contents, &mut rng).unwrap();

        // Create MintTxManagerImpl
        let token_id_to_governors = GovernorsMap::try_from_iter(vec![(
            token_id_1,
            SignerSet::new(signers.iter().map(|s| s.public_key()).collect(), 1),
        )])
        .unwrap();
        let mint_tx_manager =
            MintTxManagerImpl::new(ledger, BLOCK_VERSION, token_id_to_governors, logger);

        // Create a valid MintTx signed by the governor.
        let mint_tx = create_mint_tx(
            token_id_1,
            &[Ed25519Pair::from(signers[0].private_key())],
            1,
            &mut rng,
        );

        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("Failed getting the system time")
            .as_millis() as u64;

        assert_eq!(
            mint_tx_manager.validate_mint_tx(&mint_tx, Some(now)),
            Ok(())
        );
    }

    /// validate_mint_tx accepts a valid mint tx when two tokens are configured.
    #[test_with_logger]
    fn validate_mint_tx_accepts_valid_tx_two_tokens(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([78u8; 32]);
        let token_id_1 = TokenId::from(1);
        let token_id_2 = TokenId::from(2);

        let mut ledger = create_ledger();
        let n_blocks = 3;
        let sender = AccountKey::random(&mut rng);
        initialize_ledger(BLOCK_VERSION, &mut ledger, n_blocks, &sender, &mut rng);

        // Create mint configurations and append them to the ledger.
        let (mint_config_tx1, signers1) = create_mint_config_tx_and_signers(token_id_1, &mut rng);
        let (mint_config_tx2, signers2) = create_mint_config_tx_and_signers(token_id_2, &mut rng);

        let block_contents = BlockContents {
            validated_mint_config_txs: vec![
                to_validated(&mint_config_tx1),
                to_validated(&mint_config_tx2),
            ],
            ..Default::default()
        };
        add_block_contents_to_ledger(&mut ledger, BLOCK_VERSION, block_contents, &mut rng).unwrap();

        // Create MintTxManagerImpl
        let token_id_to_governors = GovernorsMap::try_from_iter(vec![
            (
                token_id_1,
                SignerSet::new(signers1.iter().map(|s| s.public_key()).collect(), 1),
            ),
            (
                token_id_2,
                SignerSet::new(signers2.iter().map(|s| s.public_key()).collect(), 1),
            ),
        ])
        .unwrap();
        let mint_tx_manager =
            MintTxManagerImpl::new(ledger, BLOCK_VERSION, token_id_to_governors, logger);

        // Check valid transactions.
        let mint_tx1 = create_mint_tx(
            token_id_1,
            &[Ed25519Pair::from(signers1[0].private_key())],
            1,
            &mut rng,
        );

        assert_eq!(mint_tx_manager.validate_mint_tx(&mint_tx1, None), Ok(()));

        let mint_tx2 = create_mint_tx(
            token_id_2,
            &[
                Ed25519Pair::from(signers2[0].private_key()),
                Ed25519Pair::from(signers2[1].private_key()),
            ],
            1,
            &mut rng,
        );

        assert_eq!(mint_tx_manager.validate_mint_tx(&mint_tx2, None), Ok(()));
    }

    /// validate_mint_tx rejects a mint tx when it cannot be matched with an
    /// active configuration.
    #[test_with_logger]
    fn validate_mint_tx_rejects_tx_when_no_active_configuration_is_found(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([78u8; 32]);
        let token_id_1 = TokenId::from(1);
        let token_id_2 = TokenId::from(2);
        let token_id_3 = TokenId::from(3);

        let mut ledger = create_ledger();
        let n_blocks = 3;
        let sender = AccountKey::random(&mut rng);
        initialize_ledger(BLOCK_VERSION, &mut ledger, n_blocks, &sender, &mut rng);

        // Create mint configurations and append them to the ledger.
        let (mint_config_tx1, signers1) = create_mint_config_tx_and_signers(token_id_1, &mut rng);
        let (mint_config_tx2, signers2) = create_mint_config_tx_and_signers(token_id_2, &mut rng);

        let block_contents = BlockContents {
            validated_mint_config_txs: vec![
                to_validated(&mint_config_tx1),
                to_validated(&mint_config_tx2),
            ],
            ..Default::default()
        };

        add_block_contents_to_ledger(&mut ledger, BLOCK_VERSION, block_contents, &mut rng).unwrap();

        // Create MintTxManagerImpl
        let token_id_to_governors = GovernorsMap::try_from_iter(vec![
            (
                token_id_1,
                SignerSet::new(signers1.iter().map(|s| s.public_key()).collect(), 1),
            ),
            (
                token_id_2,
                SignerSet::new(signers2.iter().map(|s| s.public_key()).collect(), 1),
            ),
        ])
        .unwrap();
        let mint_tx_manager =
            MintTxManagerImpl::new(ledger, BLOCK_VERSION, token_id_to_governors, logger);

        // Sign the wrong signer.
        let mint_tx = create_mint_tx(
            token_id_1,
            &[Ed25519Pair::from(signers2[0].private_key())],
            1,
            &mut rng,
        );

        assert_eq!(
            mint_tx_manager.validate_mint_tx(&mint_tx, None),
            Err(MintTxManagerError::MintValidation(
                MintValidationError::NoMatchingMintConfig
            ))
        );

        // Dont cross the signing threshold (the 4th signer is part of a SigningSet with
        // threshold=2)
        let mint_tx = create_mint_tx(
            token_id_2,
            &[Ed25519Pair::from(signers2[3].private_key())],
            1,
            &mut rng,
        );

        assert_eq!(
            mint_tx_manager.validate_mint_tx(&mint_tx, None),
            Err(MintTxManagerError::MintValidation(
                MintValidationError::NoMatchingMintConfig
            ))
        );

        // An unknown token id
        let mint_tx = create_mint_tx(
            token_id_3,
            &[Ed25519Pair::from(signers2[0].private_key())],
            1,
            &mut rng,
        );

        assert_eq!(
            mint_tx_manager.validate_mint_tx(&mint_tx, None),
            Err(MintTxManagerError::MintValidation(
                MintValidationError::NoMatchingMintConfig
            ))
        );
    }

    /// validate_mint_tx rejects a mint tx that exceeds a specific config mint
    /// limit.
    #[test_with_logger]
    fn validate_mint_tx_refused_over_minting_specific_config(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([77u8; 32]);
        let token_id_1 = TokenId::from(1);

        let mut ledger = create_ledger();
        let n_blocks = 3;
        let sender = AccountKey::random(&mut rng);
        initialize_ledger(BLOCK_VERSION, &mut ledger, n_blocks, &sender, &mut rng);

        // Create a mint configuration and append it to the ledger.
        let (mint_config_tx, signers) = create_mint_config_tx_and_signers(token_id_1, &mut rng);

        let block_contents = BlockContents {
            validated_mint_config_txs: vec![to_validated(&mint_config_tx)],
            ..Default::default()
        };
        add_block_contents_to_ledger(&mut ledger, BLOCK_VERSION, block_contents, &mut rng).unwrap();

        // Create MintTxManagerImpl
        let token_id_to_governors = GovernorsMap::try_from_iter(vec![(
            token_id_1,
            SignerSet::new(signers.iter().map(|s| s.public_key()).collect(), 1),
        )])
        .unwrap();
        let mint_tx_manager =
            MintTxManagerImpl::new(ledger.clone(), BLOCK_VERSION, token_id_to_governors, logger);

        // Create a MintTx that exceeds the mint limit
        let mint_tx = create_mint_tx(
            token_id_1,
            &[Ed25519Pair::from(signers[0].private_key())],
            mint_config_tx.prefix.configs[0].mint_limit + 1,
            &mut rng,
        );

        assert_eq!(
            mint_tx_manager.validate_mint_tx(&mint_tx, None),
            Err(MintTxManagerError::MintValidation(
                MintValidationError::AmountExceedsMintLimit
            ))
        );

        // Append a block that contains a valid MintTx, to test that the allowed
        // minting limit decreases.
        let mint_tx = create_mint_tx(
            token_id_1,
            &[Ed25519Pair::from(signers[0].private_key())],
            mint_config_tx.prefix.configs[0].mint_limit - 1,
            &mut rng,
        );

        assert_eq!(mint_tx_manager.validate_mint_tx(&mint_tx, None), Ok(()));

        let block_contents = BlockContents {
            mint_txs: vec![mint_tx],
            outputs: vec![create_test_tx_out(BLOCK_VERSION, &mut rng)],
            ..Default::default()
        };
        add_block_contents_to_ledger(&mut ledger, BLOCK_VERSION, block_contents, &mut rng).unwrap();

        // Create a MintTx that exceeds the mint limit
        let mint_tx = create_mint_tx(
            token_id_1,
            &[Ed25519Pair::from(signers[0].private_key())],
            2,
            &mut rng,
        );

        assert_eq!(
            mint_tx_manager.validate_mint_tx(&mint_tx, None),
            Err(MintTxManagerError::MintValidation(
                MintValidationError::AmountExceedsMintLimit
            ))
        );

        // Sanity that a MintTx that does not exceed the limit passes validation.
        let mint_tx = create_mint_tx(
            token_id_1,
            &[Ed25519Pair::from(signers[0].private_key())],
            1,
            &mut rng,
        );

        assert_eq!(mint_tx_manager.validate_mint_tx(&mint_tx, None), Ok(()));
    }

    /// validate_mint_tx rejects a mint tx that exceeds the overall mint limit.
    #[test_with_logger]
    fn validate_mint_tx_refused_over_minting_total_limit(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([77u8; 32]);
        let token_id_1 = TokenId::from(1);

        let mut ledger = create_ledger();
        let n_blocks = 3;
        let sender = AccountKey::random(&mut rng);
        initialize_ledger(BLOCK_VERSION, &mut ledger, n_blocks, &sender, &mut rng);

        // Create a mint configuration and append it to the ledger.
        let (mut mint_config_tx, signers) = create_mint_config_tx_and_signers(token_id_1, &mut rng);

        mint_config_tx.prefix.total_mint_limit = mint_config_tx.prefix.configs[0].mint_limit - 1;

        let block_contents = BlockContents {
            validated_mint_config_txs: vec![to_validated(&mint_config_tx)],
            ..Default::default()
        };
        add_block_contents_to_ledger(&mut ledger, BLOCK_VERSION, block_contents, &mut rng).unwrap();

        // Create MintTxManagerImpl
        let token_id_to_governors = GovernorsMap::try_from_iter(vec![(
            token_id_1,
            SignerSet::new(signers.iter().map(|s| s.public_key()).collect(), 1),
        )])
        .unwrap();
        let mint_tx_manager =
            MintTxManagerImpl::new(ledger.clone(), BLOCK_VERSION, token_id_to_governors, logger);

        // Create a MintTx that exceeds the total mint limit
        let mint_tx = create_mint_tx(
            token_id_1,
            &[Ed25519Pair::from(signers[0].private_key())],
            mint_config_tx.prefix.configs[0].mint_limit,
            &mut rng,
        );

        assert_eq!(
            mint_tx_manager.validate_mint_tx(&mint_tx, None),
            Err(MintTxManagerError::MintValidation(
                MintValidationError::AmountExceedsMintLimit
            ))
        );

        // Append a block that contains a valid MintTx, to test that the allowed
        // minting limit decreases.
        let mint_tx = create_mint_tx(
            token_id_1,
            &[Ed25519Pair::from(signers[0].private_key())],
            mint_config_tx.prefix.configs[0].mint_limit - 2,
            &mut rng,
        );

        assert_eq!(mint_tx_manager.validate_mint_tx(&mint_tx, None), Ok(()));

        let block_contents = BlockContents {
            mint_txs: vec![mint_tx],
            outputs: vec![create_test_tx_out(BLOCK_VERSION, &mut rng)],
            ..Default::default()
        };
        add_block_contents_to_ledger(&mut ledger, BLOCK_VERSION, block_contents, &mut rng).unwrap();

        // Create a MintTx that exceeds the mint limit
        let mint_tx = create_mint_tx(
            token_id_1,
            &[Ed25519Pair::from(signers[0].private_key())],
            2,
            &mut rng,
        );

        assert_eq!(
            mint_tx_manager.validate_mint_tx(&mint_tx, None),
            Err(MintTxManagerError::MintValidation(
                MintValidationError::AmountExceedsMintLimit
            ))
        );

        // Sanity that a MintTx that does not exceed the limit passes validation.
        let mint_tx = create_mint_tx(
            token_id_1,
            &[Ed25519Pair::from(signers[0].private_key())],
            1,
            &mut rng,
        );

        assert_eq!(mint_tx_manager.validate_mint_tx(&mint_tx, None), Ok(()));
    }

    /// validate_mint_tx rejects invalid signature.
    #[test_with_logger]
    fn validate_mint_tx_rejects_invalid_signature(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([77u8; 32]);
        let token_id_1 = TokenId::from(1);

        let mut ledger = create_ledger();
        let n_blocks = 3;
        let sender = AccountKey::random(&mut rng);
        initialize_ledger(BLOCK_VERSION, &mut ledger, n_blocks, &sender, &mut rng);

        // Create a mint configuration and append it to the ledger.
        let (mint_config_tx, signers) = create_mint_config_tx_and_signers(token_id_1, &mut rng);

        let block_contents = BlockContents {
            validated_mint_config_txs: vec![to_validated(&mint_config_tx)],
            ..Default::default()
        };
        add_block_contents_to_ledger(&mut ledger, BLOCK_VERSION, block_contents, &mut rng).unwrap();

        // Create MintTxManagerImpl
        let token_id_to_governors = GovernorsMap::try_from_iter(vec![(
            token_id_1,
            SignerSet::new(signers.iter().map(|s| s.public_key()).collect(), 1),
        )])
        .unwrap();
        let mint_tx_manager =
            MintTxManagerImpl::new(ledger, BLOCK_VERSION, token_id_to_governors, logger);

        // Create a valid MintTx signed by the governor.
        let mut mint_tx = create_mint_tx(
            token_id_1,
            &[Ed25519Pair::from(signers[0].private_key())],
            1,
            &mut rng,
        );

        assert_eq!(mint_tx_manager.validate_mint_tx(&mint_tx, None), Ok(()));

        // Now mess with the data so the signature is no longer valid.
        mint_tx.prefix.amount += 1;
        assert_eq!(
            mint_tx_manager.validate_mint_tx(&mint_tx, None),
            Err(MintTxManagerError::MintValidation(
                MintValidationError::NoMatchingMintConfig
            ))
        );
    }

    /// validate_mint_tx rejects a tx with an exceeded tombstone block.
    #[test_with_logger]
    fn validate_mint_tx_rejects_past_tombstone(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([77u8; 32]);
        let token_id_1 = TokenId::from(1);

        let (mint_config_tx, signers) = create_mint_config_tx_and_signers(token_id_1, &mut rng);
        let mint_tx = create_mint_tx(
            token_id_1,
            &[Ed25519Pair::from(signers[0].private_key())],
            1,
            &mut rng,
        );

        let mut ledger = create_ledger();
        // tombstone_block specifies that the tx will get accepted at any block whose
        // index is less than tombstone_block. n_blocks controls how many blocks
        // we create, specifically it will result in blocks with indexes [0, n_blocks).
        // setting n_blocks to tombstone_block - 1 means the transaction will be valid
        // for exactly 1 block, but once that's written it will exceed it. However, we
        // subtract 2 since we also need to add a block for the mint config tx.
        let n_blocks = mint_tx.prefix.tombstone_block - 2;
        let sender = AccountKey::random(&mut rng);
        initialize_ledger(BLOCK_VERSION, &mut ledger, n_blocks, &sender, &mut rng);

        // Append the mint config to the ledger
        let block_contents = BlockContents {
            validated_mint_config_txs: vec![to_validated(&mint_config_tx)],
            ..Default::default()
        };
        add_block_contents_to_ledger(&mut ledger, BLOCK_VERSION, block_contents, &mut rng).unwrap();

        // Create MintTxManagerImpl
        let token_id_to_governors = GovernorsMap::try_from_iter(vec![(
            token_id_1,
            SignerSet::new(signers.iter().map(|s| s.public_key()).collect(), 1),
        )])
        .unwrap();
        let mint_tx_manager =
            MintTxManagerImpl::new(ledger.clone(), BLOCK_VERSION, token_id_to_governors, logger);

        // At first we should succeed since we have not yet exceeded the tombstone
        // block.
        assert_eq!(mint_tx_manager.validate_mint_tx(&mint_tx, None), Ok(()));

        // Append a block to the ledger.
        let block_contents = BlockContents {
            outputs: vec![create_test_tx_out(BLOCK_VERSION, &mut rng)],
            key_images: vec![KeyImage::from(123)],
            ..Default::default()
        };
        add_block_contents_to_ledger(&mut ledger, BLOCK_VERSION, block_contents, &mut rng).unwrap();

        // Try again, we should fail.
        assert_eq!(
            mint_tx_manager.validate_mint_tx(&mint_tx, None),
            Err(MintTxManagerError::MintValidation(
                MintValidationError::TombstoneBlockExceeded
            ))
        );
    }

    /// validate_mint_tx rejects duplicate nonce.
    #[test_with_logger]
    fn validate_mint_tx_rejects_duplicate_nonce(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([77u8; 32]);
        let token_id_1 = TokenId::from(1);

        let mut ledger = create_ledger();
        let n_blocks = 3;
        let sender = AccountKey::random(&mut rng);
        initialize_ledger(BLOCK_VERSION, &mut ledger, n_blocks, &sender, &mut rng);

        // Create a mint configuration and append it to the ledger.
        let (mint_config_tx, signers) = create_mint_config_tx_and_signers(token_id_1, &mut rng);

        let block_contents = BlockContents {
            validated_mint_config_txs: vec![to_validated(&mint_config_tx)],
            ..Default::default()
        };
        add_block_contents_to_ledger(&mut ledger, BLOCK_VERSION, block_contents, &mut rng).unwrap();

        // Create MintTxManagerImpl
        let token_id_to_governors = GovernorsMap::try_from_iter(vec![(
            token_id_1,
            SignerSet::new(signers.iter().map(|s| s.public_key()).collect(), 1),
        )])
        .unwrap();
        let mint_tx_manager =
            MintTxManagerImpl::new(ledger.clone(), BLOCK_VERSION, token_id_to_governors, logger);

        // Create a valid MintTx signed by the governor.
        let mint_tx = create_mint_tx(
            token_id_1,
            &[Ed25519Pair::from(signers[0].private_key())],
            1,
            &mut rng,
        );

        // At first we should succeed since the nonce is not yet in the ledger.
        assert_eq!(mint_tx_manager.validate_mint_tx(&mint_tx, None), Ok(()));

        // Append to the ledger.
        let block_contents = BlockContents {
            outputs: vec![create_test_tx_out(BLOCK_VERSION, &mut rng)],
            mint_txs: vec![mint_tx.clone()],
            ..Default::default()
        };
        add_block_contents_to_ledger(&mut ledger, BLOCK_VERSION, block_contents, &mut rng).unwrap();

        // Try again, we should fail.
        assert_eq!(
            mint_tx_manager.validate_mint_tx(&mint_tx, None),
            Err(MintTxManagerError::MintValidation(
                MintValidationError::NonceAlreadyUsed
            ))
        );
    }

    #[test_with_logger]
    fn mint_tx_rejects_timestamp_too_old(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([77u8; 32]);
        let token_id_1 = TokenId::from(1);

        let mut ledger = create_ledger();
        let n_blocks = 3;
        let sender = AccountKey::random(&mut rng);
        initialize_ledger(BLOCK_VERSION, &mut ledger, n_blocks, &sender, &mut rng);

        // Create a mint configuration and append it to the ledger.
        let (mint_config_tx, signers) = create_mint_config_tx_and_signers(token_id_1, &mut rng);

        let block_contents = BlockContents {
            validated_mint_config_txs: vec![to_validated(&mint_config_tx)],
            ..Default::default()
        };
        add_block_contents_to_ledger(&mut ledger, BLOCK_VERSION, block_contents, &mut rng).unwrap();

        // Create MintTxManagerImpl
        let token_id_to_governors = GovernorsMap::try_from_iter(vec![(
            token_id_1,
            SignerSet::new(signers.iter().map(|s| s.public_key()).collect(), 1),
        )])
        .unwrap();
        let mint_tx_manager =
            MintTxManagerImpl::new(ledger, BLOCK_VERSION, token_id_to_governors, logger);

        // Create a valid MintTx signed by the governor.
        let mint_tx = create_mint_tx(
            token_id_1,
            &[Ed25519Pair::from(signers[0].private_key())],
            1,
            &mut rng,
        );

        // 1970 might be a bit extreme, but we only want to show we hooked up
        // the timestamp validator, not the edge cases of it.
        let timestamp_too_old = 0;

        assert_matches!(
            mint_tx_manager.validate_mint_tx(&mint_tx, Some(timestamp_too_old)),
            Err(MintTxManagerError::Timestamp(_))
        );
    }

    /// combine_mint_txs adequately sorts inputs and disposes of
    /// duplicates.
    #[test_with_logger]
    fn combine_mint_txs_sorts_and_removes_dupe_nonces(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([77u8; 32]);
        let token_id_1 = TokenId::from(1);

        let mut ledger = create_ledger();
        let n_blocks = 3;
        let sender = AccountKey::random(&mut rng);
        initialize_ledger(BLOCK_VERSION, &mut ledger, n_blocks, &sender, &mut rng);

        // Create a mint configuration and append it to the ledger.
        let (mint_config_tx, signers) = create_mint_config_tx_and_signers(token_id_1, &mut rng);

        let block_contents = BlockContents {
            validated_mint_config_txs: vec![to_validated(&mint_config_tx)],
            ..Default::default()
        };
        add_block_contents_to_ledger(&mut ledger, BLOCK_VERSION, block_contents, &mut rng).unwrap();

        // Test txs, each one using a different mint configuration (determined by the
        // signers)
        let mint_txs = vec![
            create_mint_tx(
                token_id_1,
                &[Ed25519Pair::from(signers[0].private_key())],
                1,
                &mut rng,
            ),
            create_mint_tx(
                token_id_1,
                &[Ed25519Pair::from(signers[1].private_key())],
                1,
                &mut rng,
            ),
            create_mint_tx(
                token_id_1,
                &[
                    Ed25519Pair::from(signers[3].private_key()),
                    Ed25519Pair::from(signers[4].private_key()),
                ],
                1,
                &mut rng,
            ),
        ];

        // Create MintTxManagerImpl
        let token_id_to_governors = GovernorsMap::try_from_iter(vec![(
            token_id_1,
            SignerSet::new(signers.iter().map(|s| s.public_key()).collect(), 1),
        )])
        .unwrap();
        let mint_tx_manager =
            MintTxManagerImpl::new(ledger, BLOCK_VERSION, token_id_to_governors, logger);

        let mut expected_result = vec![
            (mint_txs[0].clone(), 100),
            (mint_txs[1].clone(), 200),
            (mint_txs[2].clone(), 300),
        ];
        expected_result.sort();

        assert_eq!(
            mint_tx_manager.combine_mint_txs(
                &[
                    (mint_txs[0].clone(), 10),
                    (mint_txs[0].clone(), 11),
                    (mint_txs[1].clone(), 200),
                    (mint_txs[2].clone(), 31),
                    (mint_txs[1].clone(), 20),
                    (mint_txs[0].clone(), 100),
                    (mint_txs[0].clone(), 12),
                    (mint_txs[2].clone(), 32),
                    (mint_txs[1].clone(), 21),
                    (mint_txs[0].clone(), 13),
                    (mint_txs[1].clone(), 22),
                    (mint_txs[2].clone(), 300),
                ],
                100
            ),
            Ok(expected_result)
        );
    }

    /// combine_mint_txs adequately sorts inputs and disposes of
    /// duplicates.
    #[test_with_logger]
    fn combine_mint_txs_sorts_and_keeps_duplicate_nonces_across_tokens(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([77u8; 32]);

        let token_id_1 = TokenId::from(1);
        let token_id_2 = TokenId::from(2);

        let mut ledger = create_ledger();
        let n_blocks = 3;
        let block_version = BlockVersion::MAX;
        let sender = AccountKey::random(&mut rng);
        initialize_ledger(block_version, &mut ledger, n_blocks, &sender, &mut rng);

        // Create a mint configuration and append it to the ledger.
        let (mint_config_tx, signers) = create_mint_config_tx_and_signers(token_id_1, &mut rng);
        let (mint_config_tx2, signers2) = create_mint_config_tx_and_signers(token_id_2, &mut rng);

        let block_contents = BlockContents {
            validated_mint_config_txs: vec![
                to_validated(&mint_config_tx),
                to_validated(&mint_config_tx2),
            ],
            ..Default::default()
        };

        add_block_contents_to_ledger(&mut ledger, BLOCK_VERSION, block_contents, &mut rng).unwrap();
        let mut rng1: StdRng = SeedableRng::from_seed([77u8; 32]);
        let mint_tx1 = create_mint_tx(
            token_id_1,
            &[Ed25519Pair::from(signers[0].private_key())],
            1,
            &mut rng1,
        );

        let mut rng2: StdRng = SeedableRng::from_seed([77u8; 32]);
        let mint_tx2 = create_mint_tx(
            token_id_2,
            &[Ed25519Pair::from(signers2[0].private_key())],
            1,
            &mut rng2,
        );

        assert_eq!(mint_tx1.prefix.nonce, mint_tx2.prefix.nonce);
        // Test txs, each one using a different mint configuration (determined by the
        // signers)
        let mint_txs = vec![mint_tx1, mint_tx2];

        // Create MintTxManagerImpl
        let token_id_to_governors = GovernorsMap::try_from_iter(vec![
            (
                token_id_1,
                SignerSet::new(signers.iter().map(|s| s.public_key()).collect(), 1),
            ),
            (
                token_id_2,
                SignerSet::new(signers2.iter().map(|s| s.public_key()).collect(), 1),
            ),
        ])
        .unwrap();
        let mint_tx_manager =
            MintTxManagerImpl::new(ledger, BlockVersion::MAX, token_id_to_governors, logger);

        let mut expected_result = vec![(mint_txs[0].clone(), 1000), (mint_txs[1].clone(), 2000)];
        expected_result.sort();

        assert_eq!(
            mint_tx_manager.combine_mint_txs(
                &[
                    (mint_txs[0].clone(), 0),
                    (mint_txs[0].clone(), 3),
                    (mint_txs[1].clone(), 1997),
                    (mint_txs[1].clone(), 1998),
                    (mint_txs[0].clone(), 1000),
                    (mint_txs[0].clone(), 1),
                    (mint_txs[1].clone(), 2000),
                    (mint_txs[0].clone(), 2),
                    (mint_txs[1].clone(), 1999),
                ],
                100
            ),
            Ok(expected_result)
        );
    }

    /// combine_mint_txs only accepts one transaction for each mint
    /// configuration.
    #[test_with_logger]
    fn combine_mint_txs_sorts_and_removes_dupe_configs(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([77u8; 32]);
        let token_id_1 = TokenId::from(1);

        let mut ledger = create_ledger();
        let n_blocks = 3;
        let sender = AccountKey::random(&mut rng);
        initialize_ledger(BLOCK_VERSION, &mut ledger, n_blocks, &sender, &mut rng);

        // Create a mint configuration and append it to the ledger.
        let (mint_config_tx, signers) = create_mint_config_tx_and_signers(token_id_1, &mut rng);

        let block_contents = BlockContents {
            validated_mint_config_txs: vec![to_validated(&mint_config_tx)],
            ..Default::default()
        };
        add_block_contents_to_ledger(&mut ledger, BLOCK_VERSION, block_contents, &mut rng).unwrap();

        // Test txs that have overlapping minting configurations
        let mint_txs = vec![
            create_mint_tx(
                token_id_1,
                &[Ed25519Pair::from(signers[0].private_key())],
                10,
                &mut rng,
            ),
            create_mint_tx(
                token_id_1,
                &[Ed25519Pair::from(signers[1].private_key())],
                20,
                &mut rng,
            ),
            create_mint_tx(
                token_id_1,
                &[
                    Ed25519Pair::from(signers[3].private_key()),
                    Ed25519Pair::from(signers[4].private_key()),
                ],
                30,
                &mut rng,
            ),
            create_mint_tx(
                token_id_1,
                &[Ed25519Pair::from(signers[0].private_key())],
                10,
                &mut rng,
            ),
            create_mint_tx(
                token_id_1,
                &[Ed25519Pair::from(signers[1].private_key())],
                20,
                &mut rng,
            ),
            create_mint_tx(
                token_id_1,
                &[
                    Ed25519Pair::from(signers[3].private_key()),
                    Ed25519Pair::from(signers[4].private_key()),
                ],
                30,
                &mut rng,
            ),
        ];

        // Create MintTxManagerImpl
        let token_id_to_governors = GovernorsMap::try_from_iter(vec![(
            token_id_1,
            SignerSet::new(signers.iter().map(|s| s.public_key()).collect(), 1),
        )])
        .unwrap();
        let mint_tx_manager =
            MintTxManagerImpl::new(ledger, BLOCK_VERSION, token_id_to_governors, logger);

        // The expected result is that we get 3 transactions, one for each
        // configuration. We use the amount to sanity check this.
        let combined = mint_tx_manager
            .combine_mint_txs(
                &[
                    (mint_txs[0].clone(), 10),
                    (mint_txs[1].clone(), 200),
                    (mint_txs[2].clone(), 30),
                    (mint_txs[3].clone(), 400),
                    (mint_txs[4].clone(), 50),
                    (mint_txs[3].clone(), 40),
                    (mint_txs[4].clone(), 500),
                    (mint_txs[5].clone(), 60),
                    (mint_txs[5].clone(), 61),
                    (mint_txs[5].clone(), 600),
                    (mint_txs[0].clone(), 100),
                    (mint_txs[1].clone(), 20),
                    (mint_txs[2].clone(), 300),
                    (mint_txs[2].clone(), 31),
                    (mint_txs[3].clone(), 41),
                    (mint_txs[3].clone(), 42),
                    (mint_txs[4].clone(), 51),
                    (mint_txs[5].clone(), 62),
                ],
                100,
            )
            .unwrap();

        assert_eq!(
            HashSet::from_iter([(10, 100), (20, 200), (30, 300)]),
            HashSet::from_iter(
                combined
                    .iter()
                    .map(|(tx, timestamp)| (tx.prefix.amount, *timestamp))
            )
        );
    }
}
