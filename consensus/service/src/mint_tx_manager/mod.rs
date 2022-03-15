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

use mc_common::{logger::Logger, HashMap, HashSet};
use mc_crypto_keys::Ed25519Public;
use mc_crypto_multisig::SignerSet;
use mc_ledger_db::Ledger;
use mc_transaction_core::{
    mint::{validate_mint_config_tx, MintConfigTx, MintValidationError},
    BlockVersion, TokenId,
};

#[derive(Clone)]
pub struct MintTxManagerImpl<L: Ledger> {
    /// Ledger DB.
    ledger_db: L,

    /// The configured block version.
    block_version: BlockVersion,

    /// A map of token id -> master minters.
    token_id_to_master_minters: HashMap<TokenId, SignerSet<Ed25519Public>>,

    /// Logger.
    logger: Logger,
}

impl<L: Ledger> MintTxManagerImpl<L> {
    pub fn new(
        ledger_db: L,
        block_version: BlockVersion,
        token_id_to_master_minters: HashMap<TokenId, SignerSet<Ed25519Public>>,
        logger: Logger,
    ) -> Self {
        Self {
            ledger_db,
            block_version,
            token_id_to_master_minters,
            logger,
        }
    }
}

impl<L: Ledger> MintTxManager for MintTxManagerImpl<L> {
    /// Validate a MintConfigTx transaction against the current ledger.
    fn validate_mint_config_tx(&self, mint_config_tx: &MintConfigTx) -> MintTxManagerResult<()> {
        // Ensure that we have not seen this transaction before.
        if self
            .ledger_db
            .check_mint_config_tx_nonce(&mint_config_tx.prefix.nonce)?
            .is_some()
        {
            return Err(MintTxManagerError::MintValidation(
                MintValidationError::NonceAlreadyUsed,
            ));
        }

        // Get the master minters for this token id.
        let token_id = TokenId::from(mint_config_tx.prefix.token_id);
        let master_minters = self.token_id_to_master_minters.get(&token_id).ok_or(
            MintTxManagerError::MintValidation(MintValidationError::NoMasterMinters(token_id)),
        )?;

        // Get the current block index.
        let current_block_index = self.ledger_db.num_blocks()? - 1;

        // Perform the actual validation.
        validate_mint_config_tx(
            mint_config_tx,
            current_block_index,
            self.block_version,
            master_minters,
        )?;

        Ok(())
    }

    fn combine_mint_config_txs(
        &self,
        txs: &[MintConfigTx],
        max_elements: usize,
    ) -> MintTxManagerResult<Vec<MintConfigTx>> {
        let mut candidates = txs.to_vec();
        candidates.sort();

        let mut seen_nonces = HashSet::default();
        let (allowed_txs, _rejected_txs) = candidates.into_iter().partition(|tx| {
            if seen_nonces.len() >= max_elements {
                return false;
            }
            if seen_nonces.contains(&tx.prefix.nonce) {
                return false;
            }
            seen_nonces.insert(tx.prefix.nonce.clone());
            true
        });

        Ok(allowed_txs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mc_common::logger::test_with_logger;
    use mc_crypto_multisig::SignerSet;
    use mc_transaction_core::{Block, BlockContents};
    use mc_transaction_core_test_utils::{
        create_ledger, create_mint_config_tx_and_signers, initialize_ledger, AccountKey,
    };
    use rand::{rngs::StdRng, SeedableRng};
    use std::iter::FromIterator;

    /// validate_mint_config_tx accepts a valid mint config tx when only a
    /// single token is configured.
    #[test_with_logger]
    fn validate_mint_config_tx_accepts_valid_tx_single_token(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([77u8; 32]);
        let token_id_1 = TokenId::from(1);

        let mut ledger = create_ledger();
        let n_blocks = 3;
        let block_version = BlockVersion::MAX;
        let sender = AccountKey::random(&mut rng);
        initialize_ledger(block_version, &mut ledger, n_blocks, &sender, &mut rng);

        let (mint_config_tx, signers) = create_mint_config_tx_and_signers(token_id_1, &mut rng);
        let token_id_to_master_minters = HashMap::from_iter(vec![(
            token_id_1,
            SignerSet::new(signers.iter().map(|s| s.public_key()).collect(), 1),
        )]);
        let mint_tx_manager = MintTxManagerImpl::new(
            ledger,
            BlockVersion::MAX,
            token_id_to_master_minters,
            logger,
        );

        assert_eq!(
            mint_tx_manager.validate_mint_config_tx(&mint_config_tx),
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
        let n_blocks = 3;
        let block_version = BlockVersion::MAX;
        let sender = AccountKey::random(&mut rng);
        initialize_ledger(block_version, &mut ledger, n_blocks, &sender, &mut rng);

        let (mint_config_tx1, signers1) = create_mint_config_tx_and_signers(token_id_1, &mut rng);
        let (mint_config_tx2, signers2) = create_mint_config_tx_and_signers(token_id_2, &mut rng);
        let (mint_config_tx3, signers3) = create_mint_config_tx_and_signers(token_id_3, &mut rng);
        let token_id_to_master_minters = HashMap::from_iter(vec![
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
        ]);
        let mint_tx_manager = MintTxManagerImpl::new(
            ledger,
            BlockVersion::MAX,
            token_id_to_master_minters,
            logger,
        );

        assert_eq!(
            mint_tx_manager.validate_mint_config_tx(&mint_config_tx1),
            Ok(())
        );

        assert_eq!(
            mint_tx_manager.validate_mint_config_tx(&mint_config_tx2),
            Ok(())
        );

        assert_eq!(
            mint_tx_manager.validate_mint_config_tx(&mint_config_tx3),
            Ok(())
        );
    }

    /// validate_mint_config_tx rejects a mint config tx with a nonce that
    /// already appears in the ledger.
    #[test_with_logger]
    fn validate_mint_config_tx_rejects_duplicate_nonce(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([77u8; 32]);
        let token_id_1 = TokenId::from(1);

        let mut ledger = create_ledger();
        let n_blocks = 3;
        let block_version = BlockVersion::MAX;
        let sender = AccountKey::random(&mut rng);
        initialize_ledger(block_version, &mut ledger, n_blocks, &sender, &mut rng);

        let (mint_config_tx, signers) = create_mint_config_tx_and_signers(token_id_1, &mut rng);
        let token_id_to_master_minters = HashMap::from_iter(vec![(
            token_id_1,
            SignerSet::new(signers.iter().map(|s| s.public_key()).collect(), 1),
        )]);
        let mint_tx_manager = MintTxManagerImpl::new(
            ledger.clone(),
            BlockVersion::MAX,
            token_id_to_master_minters,
            logger,
        );

        // At first we should succeed since the nonce is not yet in the ledger.
        assert_eq!(
            mint_tx_manager.validate_mint_config_tx(&mint_config_tx),
            Ok(())
        );

        // Append to the ledger.
        let parent_block = ledger.get_block(n_blocks - 1).unwrap();

        let block_contents = BlockContents {
            mint_config_txs: vec![mint_config_tx.clone()],
            ..Default::default()
        };

        let block = Block::new_with_parent(
            BlockVersion::MAX,
            &parent_block,
            &Default::default(),
            &block_contents,
        );

        ledger.append_block(&block, &block_contents, None).unwrap();

        // Try again, we should fail.
        assert_eq!(
            mint_tx_manager.validate_mint_config_tx(&mint_config_tx),
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
        let block_version = BlockVersion::MAX;
        let sender = AccountKey::random(&mut rng);
        initialize_ledger(block_version, &mut ledger, n_blocks, &sender, &mut rng);

        let (_mint_config_tx, signers) = create_mint_config_tx_and_signers(token_id_1, &mut rng);
        let token_id_to_master_minters = HashMap::from_iter(vec![(
            token_id_1,
            SignerSet::new(signers.iter().map(|s| s.public_key()).collect(), 1),
        )]);
        let mint_tx_manager = MintTxManagerImpl::new(
            ledger,
            BlockVersion::MAX,
            token_id_to_master_minters,
            logger,
        );

        let (mint_config_tx2, _signers) = create_mint_config_tx_and_signers(token_id_2, &mut rng);
        assert_eq!(
            mint_tx_manager.validate_mint_config_tx(&mint_config_tx2),
            Err(MintTxManagerError::MintValidation(
                MintValidationError::NoMasterMinters(token_id_2)
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
        let n_blocks = 3;
        let block_version = BlockVersion::MAX;
        let sender = AccountKey::random(&mut rng);
        initialize_ledger(block_version, &mut ledger, n_blocks, &sender, &mut rng);

        let (mut mint_config_tx, signers) = create_mint_config_tx_and_signers(token_id_1, &mut rng);
        let token_id_to_master_minters = HashMap::from_iter(vec![(
            token_id_1,
            SignerSet::new(signers.iter().map(|s| s.public_key()).collect(), 1),
        )]);
        let mint_tx_manager = MintTxManagerImpl::new(
            ledger,
            BlockVersion::MAX,
            token_id_to_master_minters,
            logger,
        );

        mint_config_tx.prefix.tombstone_block += 1;

        assert_eq!(
            mint_tx_manager.validate_mint_config_tx(&mint_config_tx),
            Err(MintTxManagerError::MintValidation(
                MintValidationError::InvalidSignature
            ))
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
        let block_version = BlockVersion::MAX;
        let sender = AccountKey::random(&mut rng);
        initialize_ledger(block_version, &mut ledger, n_blocks, &sender, &mut rng);

        let (mint_config_tx1, signers) = create_mint_config_tx_and_signers(token_id_1, &mut rng);
        let (mint_config_tx2, _) = create_mint_config_tx_and_signers(token_id_1, &mut rng);
        let (mint_config_tx3, _) = create_mint_config_tx_and_signers(token_id_1, &mut rng);
        let (mint_config_tx4, _) = create_mint_config_tx_and_signers(token_id_1, &mut rng);
        let token_id_to_master_minters = HashMap::from_iter(vec![(
            token_id_1,
            SignerSet::new(signers.iter().map(|s| s.public_key()).collect(), 1),
        )]);
        let mint_tx_manager = MintTxManagerImpl::new(
            ledger,
            BlockVersion::MAX,
            token_id_to_master_minters,
            logger,
        );

        let mut expected_result = vec![
            mint_config_tx1.clone(),
            mint_config_tx2.clone(),
            mint_config_tx3.clone(),
            mint_config_tx4.clone(),
        ];
        expected_result.sort();

        assert_eq!(
            mint_tx_manager.combine_mint_config_txs(
                &[
                    mint_config_tx3.clone(),
                    mint_config_tx4.clone(),
                    mint_config_tx1.clone(),
                    mint_config_tx3.clone(),
                    mint_config_tx3.clone(),
                    mint_config_tx2.clone(),
                    mint_config_tx1.clone(),
                    mint_config_tx1.clone(),
                    mint_config_tx2.clone(),
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
        let block_version = BlockVersion::MAX;
        let sender = AccountKey::random(&mut rng);
        initialize_ledger(block_version, &mut ledger, n_blocks, &sender, &mut rng);

        let (mint_config_tx1, signers) = create_mint_config_tx_and_signers(token_id_1, &mut rng);
        let (mint_config_tx2, _) = create_mint_config_tx_and_signers(token_id_1, &mut rng);
        let (mint_config_tx3, _) = create_mint_config_tx_and_signers(token_id_1, &mut rng);
        let (mint_config_tx4, _) = create_mint_config_tx_and_signers(token_id_1, &mut rng);
        let (mint_config_tx5, _) = create_mint_config_tx_and_signers(token_id_1, &mut rng);
        let (mint_config_tx6, _) = create_mint_config_tx_and_signers(token_id_1, &mut rng);
        let token_id_to_master_minters = HashMap::from_iter(vec![(
            token_id_1,
            SignerSet::new(signers.iter().map(|s| s.public_key()).collect(), 1),
        )]);
        let mint_tx_manager = MintTxManagerImpl::new(
            ledger,
            BlockVersion::MAX,
            token_id_to_master_minters,
            logger,
        );

        let mut expected_result = vec![
            mint_config_tx1.clone(),
            mint_config_tx2.clone(),
            mint_config_tx3.clone(),
            mint_config_tx4.clone(),
            mint_config_tx5.clone(),
            mint_config_tx6.clone(),
        ];
        expected_result.sort();
        expected_result.truncate(3);

        assert_eq!(
            mint_tx_manager.combine_mint_config_txs(
                &[
                    mint_config_tx3.clone(),
                    mint_config_tx4.clone(),
                    mint_config_tx1.clone(),
                    mint_config_tx5.clone(),
                    mint_config_tx3.clone(),
                    mint_config_tx2.clone(),
                    mint_config_tx1.clone(),
                    mint_config_tx1.clone(),
                    mint_config_tx2.clone(),
                    mint_config_tx6.clone(),
                ],
                3
            ),
            Ok(expected_result)
        );
    }
}
