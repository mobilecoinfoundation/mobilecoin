// Copyright (c) 2018-2020 MobileCoin Inc.

//! The entity that manages cached transactions on the untrusted side.

use crate::counters;
use failure::Fail;
use mc_attest_enclave_api::{EnclaveMessage, PeerSession};
use mc_common::{
    logger::{log, Logger},
    HashMap, HashSet,
};
use mc_consensus_enclave::{
    ConsensusEnclaveProxy, Error as ConsensusEnclaveError, TxContext, WellFormedEncryptedTx,
    WellFormedTxContext,
};
use mc_crypto_keys::CompressedRistrettoPublic;
use mc_ledger_db::Error as LedgerDbError;
use mc_transaction_core::{
    constants::MAX_TRANSACTIONS_PER_BLOCK,
    ring_signature::KeyImage,
    tx::{TxHash, TxOutMembershipProof},
    validation::{TransactionValidationError, TransactionValidationResult},
    Block, BlockContents, BlockSignature,
};
use mockall::*;
use std::{collections::BTreeSet, iter::FromIterator};

#[derive(Clone, Debug, Fail)]
pub enum TxManagerError {
    #[fail(display = "Enclave error: {}", _0)]
    Enclave(ConsensusEnclaveError),

    #[fail(display = "Transaction validation error: {}", _0)]
    TransactionValidation(TransactionValidationError),

    #[fail(display = "Tx already in cache")]
    AlreadyInCache,

    #[fail(display = "Tx not in cache ({})", _0)]
    NotInCache(TxHash),

    #[fail(display = "Ledger error: {}", _0)]
    LedgerDb(LedgerDbError),
}

impl From<ConsensusEnclaveError> for TxManagerError {
    fn from(err: ConsensusEnclaveError) -> Self {
        if let ConsensusEnclaveError::MalformedTx(transaction_validation_error) = err {
            Self::TransactionValidation(transaction_validation_error)
        } else {
            Self::Enclave(err)
        }
    }
}

impl From<TransactionValidationError> for TxManagerError {
    fn from(err: TransactionValidationError) -> Self {
        Self::TransactionValidation(err)
    }
}

impl From<LedgerDbError> for TxManagerError {
    fn from(err: LedgerDbError) -> Self {
        Self::LedgerDb(err)
    }
}

pub type TxManagerResult<T> = Result<T, TxManagerError>;

struct CacheEntry {
    encrypted_tx: WellFormedEncryptedTx,

    context: WellFormedTxContext,
}

impl CacheEntry {
    pub fn encrypted_tx(&self) -> &WellFormedEncryptedTx {
        &self.encrypted_tx
    }

    pub fn context(&self) -> &WellFormedTxContext {
        &self.context
    }
}

/// Transaction checks performed outside the enclave.
#[automock]
pub trait UntrustedInterfaces: Send {
    /// Performs the untrusted part of the well-formed check.
    /// Returns current block index and membership proofs to be used by
    /// the in-enclave well-formed check on success.
    fn well_formed_check(
        &self,
        highest_indices: &[u64],
        key_images: &[KeyImage],
        output_public_keys: &[CompressedRistrettoPublic],
    ) -> TransactionValidationResult<(u64, Vec<TxOutMembershipProof>)>;

    /// Checks if a transaction is valid (see definition in validators.rs).
    fn is_valid(&self, context: &WellFormedTxContext) -> TransactionValidationResult<()>;

    /// Combines a set of "candidate values" into a "composite value".
    /// This assumes all values are well-formed and safe to append to the ledger individually.
    ///
    /// # Arguments
    /// * `tx_contexts` - "Candidate" transactions. Each is assumed to be individually valid.
    /// * `max_elements` - Maximal number of elements to output.
    ///
    /// Returns a bounded, deterministically-ordered list of transactions that are safe to append to the ledger.
    fn combine(&self, tx_contexts: &[WellFormedTxContext], max_elements: usize) -> Vec<TxHash>;
}

#[automock]
pub trait TxManager: Send {
    /// Insert a well-formed transaction into the cache.
    fn insert_proposed_tx(&mut self, tx_context: TxContext)
        -> TxManagerResult<WellFormedTxContext>;

    /// Remove expired transactions from the cache and return their hashes.
    fn evacuate_expired(&mut self, cur_block: u64) -> HashSet<TxHash>;

    /// Returns the list of hashes inside `tx_hashes` that are not inside the cache.
    fn missing_hashes(&self, tx_hashes: &BTreeSet<TxHash>) -> Vec<TxHash>;

    /// Validate a transaction by it's hash. This checks if by itself this transaction is safe to
    /// append to the ledger.
    fn validate_tx_by_hash(&self, tx_hash: &TxHash) -> TxManagerResult<()>;

    /// Combines the transactions that correspond to the given hashes.
    fn combine_txs_by_hash(&self, tx_hashes: &[TxHash]) -> Vec<TxHash>;

    /// Forms a Block containing the transactions that correspond to the given hashes.
    fn tx_hashes_to_block(
        &self,
        tx_hashes: &[TxHash],
        parent_block: &Block,
    ) -> TxManagerResult<(Block, BlockContents, BlockSignature)>;

    /// Creates a message containing a set of transactions that are encrypted for a peer.
    fn txs_for_peer(
        &self,
        tx_hashes: &[TxHash],
        aad: &[u8],
        peer: &PeerSession,
    ) -> TxManagerResult<EnclaveMessage<PeerSession>>;

    fn get_encrypted_tx_by_hash(&self, tx_hash: &TxHash) -> Option<WellFormedEncryptedTx>;

    fn num_entries(&self) -> usize;
}

pub struct TxManagerImpl<E: ConsensusEnclaveProxy, UI: UntrustedInterfaces> {
    /// Validate and combine functionality provided by an enclave.
    enclave: E,

    /// Validate and combine functionality provided by the untrusted system.
    untrusted: UI,

    /// Logger.
    logger: Logger,

    /// Map of tx hashes to data we hold for each tx.
    cache: HashMap<TxHash, CacheEntry>,
}

impl<E: ConsensusEnclaveProxy, UI: UntrustedInterfaces> TxManagerImpl<E, UI> {
    /// Construct a new TxManager instance.
    pub fn new(enclave: E, untrusted: UI, logger: Logger) -> Self {
        Self {
            enclave,
            untrusted,
            logger,
            cache: HashMap::default(),
        }
    }
}

impl<E: ConsensusEnclaveProxy, UI: UntrustedInterfaces> TxManager for TxManagerImpl<E, UI> {
    /// Insert a new transaction into the cache.
    /// This enforces that the transaction is well-formed.
    fn insert_proposed_tx(
        &mut self,
        tx_context: TxContext,
    ) -> TxManagerResult<WellFormedTxContext> {
        // If already in cache then we're done.
        if let Some(entry) = self.cache.get(&tx_context.tx_hash) {
            self.untrusted.is_valid(entry.context())?;
            return Err(TxManagerError::AlreadyInCache);
        }

        // Start timer for metrics.
        let timer = counters::WELL_FORMED_CHECK_TIME.start_timer();

        // Perform the untrusted part of the well-formed check.
        let (current_block_index, membership_proofs) = self.untrusted.well_formed_check(
            &tx_context.highest_indices,
            &tx_context.key_images,
            &tx_context.output_public_keys,
        )?;

        // Check if tx is well-formed, and if it is get the encrypted copy and context.
        let (well_formed_encrypted_tx, well_formed_tx_context) = self.enclave.tx_is_well_formed(
            tx_context.locally_encrypted_tx,
            current_block_index,
            membership_proofs,
        )?;

        drop(timer);

        log::trace!(
            self.logger,
            "Inserted well-formed transaction request {hash} into cache",
            hash = well_formed_tx_context.tx_hash().to_string(),
        );

        // Store in our cache.

        self.cache.insert(
            *well_formed_tx_context.tx_hash(),
            CacheEntry {
                encrypted_tx: well_formed_encrypted_tx,
                context: well_formed_tx_context.clone(),
            },
        );
        counters::TX_CACHE_NUM_ENTRIES.set(self.cache.len() as i64);

        // Success!
        Ok(well_formed_tx_context)
    }

    /// Remove expired transactions from the cache and return their hashes.
    fn evacuate_expired(&mut self, cur_block: u64) -> HashSet<TxHash> {
        let hashes_before_purge = HashSet::from_iter(self.cache.keys().cloned());

        self.cache
            .retain(|_k, entry| entry.context().tombstone_block() >= cur_block);

        let hashes_after_purge = HashSet::from_iter(self.cache.keys().cloned());
        let purged_hashes = hashes_before_purge
            .difference(&hashes_after_purge)
            .cloned()
            .collect::<HashSet<_>>();
        log::debug!(
            self.logger,
            "cleared {} ({:?}) expired txs, left with {} ({:?})",
            purged_hashes.len(),
            purged_hashes,
            hashes_after_purge.len(),
            hashes_after_purge,
        );

        counters::TX_CACHE_NUM_ENTRIES.set(self.cache.len() as i64);

        purged_hashes
    }

    /// Returns the list of hashes inside `tx_hashes` that are not inside the cache.
    fn missing_hashes(&self, tx_hashes: &BTreeSet<TxHash>) -> Vec<TxHash> {
        let mut missing = Vec::new();
        for tx_hash in tx_hashes {
            if !self.cache.contains_key(tx_hash) {
                missing.push(*tx_hash);
            }
        }
        missing
    }

    /// Validate the transaction corresponding to the given hash.
    fn validate_tx_by_hash(&self, tx_hash: &TxHash) -> TxManagerResult<()> {
        match self.cache.get(tx_hash) {
            None => {
                log::error!(
                    self.logger,
                    "attempting to validate non-existent tx hash {:?}",
                    tx_hash
                );
                Err(TxManagerError::NotInCache(*tx_hash))
            }
            Some(entry) => {
                let _timer = counters::VALIDATE_TX_TIME.start_timer();
                self.untrusted.is_valid(entry.context())?;
                Ok(())
            }
        }
    }

    /// Combine a list of transactions by their hashes and return the list of hashes of
    /// the combined transaction set.
    ///
    /// This will silently ignore non-existent hashes. Our combine methods are allowed to filter
    /// out transactions, so while non-existent hashes should not be fed into this method, they are
    /// not treated as an error.
    fn combine_txs_by_hash(&self, tx_hashes: &[TxHash]) -> Vec<TxHash> {
        let mut tx_contexts = Vec::new();

        // Dedup
        let tx_hashes: HashSet<&TxHash> = tx_hashes.iter().clone().collect();
        for tx_hash in tx_hashes {
            if let Some(entry) = self.cache.get(&tx_hash) {
                tx_contexts.push(entry.context().clone());
            } else {
                log::error!(self.logger, "Ignoring non-existent TxHash {:?}", tx_hash);
            }
        }

        self.untrusted
            .combine(&tx_contexts, MAX_TRANSACTIONS_PER_BLOCK)
    }

    /// Forms a Block containing the transactions that correspond to the given hashes.
    fn tx_hashes_to_block(
        &self,
        tx_hashes: &[TxHash],
        parent_block: &Block,
    ) -> TxManagerResult<(Block, BlockContents, BlockSignature)> {
        let encrypted_txs_with_proofs = tx_hashes
            .iter()
            .map(|tx_hash| {
                let entry = self.cache.get(tx_hash).ok_or_else(|| TxManagerError::NotInCache(*tx_hash))?;

                let (_current_block_index, membership_proofs) = self.untrusted.well_formed_check(
                    entry.context().highest_indices(),
                    entry.context().key_images(),
                    entry.context().output_public_keys(),
                )?;

                Ok((entry.encrypted_tx().clone(), membership_proofs))
            })
            .collect::<Result<Vec<(WellFormedEncryptedTx, Vec<TxOutMembershipProof>)>, TxManagerError>>()?;

        // let num_blocks = self.ledger.num_blocks()?;
        // let parent_block = self.ledger.get_block(num_blocks - 1)?;
        let (block, block_contents, mut signature) = self
            .enclave
            .form_block(&parent_block, &encrypted_txs_with_proofs)?;

        // The enclave cannot provide a timestamp, so this happens in untrusted.
        signature.set_signed_at(chrono::Utc::now().timestamp() as u64);

        Ok((block, block_contents, signature))
    }

    /// Creates a message containing a set of transactions that are encrypted for a peer.
    fn txs_for_peer(
        &self,
        tx_hashes: &[TxHash],
        aad: &[u8],
        peer: &PeerSession,
    ) -> TxManagerResult<EnclaveMessage<PeerSession>> {
        let encrypted_txs: Result<Vec<WellFormedEncryptedTx>, TxManagerError> = {
            tx_hashes
                .iter()
                .map(|tx_hash| {
                    self.cache
                        .get(tx_hash)
                        .map(|entry| entry.encrypted_tx().clone())
                        .ok_or_else(|| TxManagerError::NotInCache(*tx_hash))
                })
                .collect()
        };

        Ok(self.enclave.txs_for_peer(&encrypted_txs?, aad, peer)?)
    }

    /// Get the encrypted transaction corresponding to the given hash.
    fn get_encrypted_tx_by_hash(&self, tx_hash: &TxHash) -> Option<WellFormedEncryptedTx> {
        self.cache
            .get(tx_hash)
            .map(|entry| entry.encrypted_tx().clone())
    }

    fn num_entries(&self) -> usize {
        self.cache.len()
    }
}

#[cfg(test)]
mod tx_manager_tests {
    use super::*;
    use crate::validators::DefaultTxManagerUntrustedInterfaces;
    use mc_common::logger::test_with_logger;
    use mc_consensus_enclave_mock::ConsensusServiceMockEnclave;
    use mc_ledger_db::Ledger;
    use mc_transaction_core_test_utils::{
        create_ledger, create_transaction, initialize_ledger, AccountKey,
    };
    use rand::{rngs::StdRng, SeedableRng};

    #[test_with_logger]
    // Should return Ok when a well-formed Tx is inserted.
    fn test_insert_proposed_tx_ok(logger: Logger) {
        let tx_context = TxContext::default();

        let mut mock_untrusted = MockUntrustedInterfaces::new();
        // Untrusted's well-formed check should be called once each time insert_propose_tx is called.
        mock_untrusted
            .expect_well_formed_check()
            .times(1)
            .return_const(Ok((0, vec![])));

        // The enclave's well-formed check also ought to be called, and should return Ok.
        let mock_enclave = ConsensusServiceMockEnclave::default();

        let mut tx_manager = TxManagerImpl::new(mock_enclave, mock_untrusted, logger.clone());
        assert!(tx_manager.insert_proposed_tx(tx_context.clone()).is_ok());
        assert_eq!(tx_manager.cache.len(), 1);
    }

    #[test_with_logger]
    #[ignore]
    // Should return Ok when a well-formed Tx is re-inserted.
    fn test_insert_proposed_tx_reinsert_ok(_logger: Logger) {
        unimplemented!()
    }

    #[test_with_logger]
    // Should return return an error when a not well-formed Tx is inserted.
    fn test_insert_proposed_tx_error(logger: Logger) {
        let tx_context = TxContext::default();

        let mut mock_untrusted = MockUntrustedInterfaces::new();
        // Untrusted's well-formed check should be called once each time insert_propose_tx is called.
        mock_untrusted
            .expect_well_formed_check()
            .times(1)
            .return_const(Err(TransactionValidationError::ContainsSpentKeyImage));

        // This should not be called.
        let mock_enclave = ConsensusServiceMockEnclave::default();

        let mut tx_manager = TxManagerImpl::new(mock_enclave, mock_untrusted, logger.clone());
        assert!(tx_manager.insert_proposed_tx(tx_context.clone()).is_err());
        assert_eq!(tx_manager.cache.len(), 0);
    }

    #[test_with_logger]
    fn test_hashes_to_block(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([77u8; 32]);
        let sender = AccountKey::random(&mut rng);
        let mut ledger = create_ledger();
        let n_blocks = 3;
        initialize_ledger(&mut ledger, n_blocks, &sender, &mut rng);
        let num_blocks = ledger.num_blocks().unwrap();
        let parent_block = ledger.get_block(num_blocks - 1).unwrap();
        let mut tx_manager = TxManagerImpl::new(
            ConsensusServiceMockEnclave::default(),
            DefaultTxManagerUntrustedInterfaces::new(ledger),
            logger.clone(),
        );

        // Generate three transactions and populate the cache with them.
        // Generate a fourth transaction that does not go into the cache.
        let mut transactions = {
            let mut rng: StdRng = SeedableRng::from_seed([77u8; 32]);
            let sender = AccountKey::random(&mut rng);
            let mut ledger = create_ledger();
            let n_blocks = 3;
            initialize_ledger(&mut ledger, n_blocks, &sender, &mut rng);
            let block_contents = ledger.get_block_contents(n_blocks - 1).unwrap();
            let tx_out = block_contents.outputs[0].clone();

            let recipient = AccountKey::random(&mut rng);
            let tx1 = create_transaction(
                &mut ledger,
                &tx_out,
                &sender,
                &recipient.default_subaddress(),
                n_blocks + 1,
                &mut rng,
            );

            let recipient = AccountKey::random(&mut rng);
            let tx2 = create_transaction(
                &mut ledger,
                &tx_out,
                &sender,
                &recipient.default_subaddress(),
                n_blocks + 1,
                &mut rng,
            );

            let recipient = AccountKey::random(&mut rng);
            let tx3 = create_transaction(
                &mut ledger,
                &tx_out,
                &sender,
                &recipient.default_subaddress(),
                n_blocks + 1,
                &mut rng,
            );

            let recipient = AccountKey::random(&mut rng);
            let tx4 = create_transaction(
                &mut ledger,
                &tx_out,
                &sender,
                &recipient.default_subaddress(),
                n_blocks + 1,
                &mut rng,
            );

            vec![tx1, tx2, tx3, tx4]
        };

        let client_tx_zero = transactions.pop().unwrap();
        let client_tx_one = transactions.pop().unwrap();
        let client_tx_two = transactions.pop().unwrap();
        let client_tx_three = transactions.pop().unwrap();

        let hash_tx_zero = *tx_manager
            .insert_proposed_tx(ConsensusServiceMockEnclave::tx_to_tx_context(
                &client_tx_zero,
            ))
            .unwrap()
            .tx_hash();

        let hash_tx_one = *tx_manager
            .insert_proposed_tx(ConsensusServiceMockEnclave::tx_to_tx_context(
                &client_tx_one,
            ))
            .unwrap()
            .tx_hash();

        let hash_tx_two = *tx_manager
            .insert_proposed_tx(ConsensusServiceMockEnclave::tx_to_tx_context(
                &client_tx_two,
            ))
            .unwrap()
            .tx_hash();

        let hash_tx_three = client_tx_three.tx_hash();

        // Attempting to assemble a block with a non-existent hash should fail
        assert!(tx_manager
            .tx_hashes_to_block(&[hash_tx_two, hash_tx_three], &parent_block)
            .is_err());

        // Attempting to assemble a block with a duplicate transaction should fail.
        // TODO: The logic for actually making sure of this lives inside the Enclave, so it cannot
        // currently be tested here.
        // assert!(tx_manager
        //     .tx_hashes_to_block(&vec![hash_tx_zero, hash_tx_one, hash_tx_zero])
        //     .is_err());

        // Attempting to assemble a block with a duplicate and a missing transaction should fail
        // TODO: The logic for actually making sure of this lives inside the Enclave, so it cannot
        // currently be tested here.
        // assert!(tx_manager
        //     .tx_hashes_to_block(&vec![hash_tx_zero, hash_tx_zero, hash_tx_three])
        //     .is_err());

        // Attempting to assemble a block without duplicates or missing transactions should
        // succeed.
        let (block, block_contents, _signature) = tx_manager
            .tx_hashes_to_block(&[hash_tx_zero, hash_tx_one], &parent_block)
            .expect("failed assembling block");
        assert_eq!(
            client_tx_zero.prefix.outputs[0].public_key,
            block_contents.outputs[0].public_key
        );
        assert_eq!(
            client_tx_one.prefix.outputs[0].public_key,
            block_contents.outputs[1].public_key
        );

        // The ledger was previously initialized with 3 blocks.
        assert_eq!(block.index, 3);
    }
}
