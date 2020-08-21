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
    ConsensusEnclave, Error as ConsensusEnclaveError, TxContext, WellFormedEncryptedTx,
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
use std::{
    collections::BTreeSet,
    iter::FromIterator,
    sync::{Mutex, MutexGuard},
};

#[cfg(test)]
use mockall::*;
use std::sync::Arc;

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

    context: Arc<WellFormedTxContext>,
}

impl CacheEntry {
    pub fn encrypted_tx(&self) -> &WellFormedEncryptedTx {
        &self.encrypted_tx
    }

    pub fn context(&self) -> &Arc<WellFormedTxContext> {
        &self.context
    }
}

/// The untrusted (i.e. non-enclave) part of validating and combining transactions.
#[cfg_attr(test, automock)]
pub trait UntrustedInterfaces: Send + Sync {
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
    fn combine(&self, tx_contexts: &[Arc<WellFormedTxContext>], max_elements: usize)
        -> Vec<TxHash>;
}

pub struct TxManager<E: ConsensusEnclave, UI: UntrustedInterfaces> {
    /// Enclave.
    enclave: E,

    /// Application-specific custom interfaces for the untrusted part of validation/combining of
    /// values.
    untrusted: UI,

    /// Well-formed transactions, keyed by hash.
    cache: Mutex<HashMap<TxHash, CacheEntry>>,

    /// Logger.
    logger: Logger,
}

impl<E: ConsensusEnclave, UI: UntrustedInterfaces> TxManager<E, UI> {
    /// Construct a new TxManager instance.
    pub fn new(enclave: E, untrusted: UI, logger: Logger) -> Self {
        Self {
            enclave,
            untrusted,
            logger,
            cache: Mutex::new(HashMap::default()),
        }
    }

    /// Insert a transaction into the cache. The transaction must be well-formed.
    pub fn insert(&self, tx_context: TxContext) -> TxManagerResult<TxHash> {
        {
            let cache = self.lock_cache();
            if let Some(entry) = cache.get(&tx_context.tx_hash) {
                // The transaction has already been checked and is in the cache.
                return Ok(entry.context.tx_hash().clone());
            }
        }

        // Start timer for metrics.
        let timer = counters::WELL_FORMED_CHECK_TIME.start_timer();

        // Perform the untrusted part of the well-formed check.
        let (current_block_index, membership_proofs) = self.untrusted.well_formed_check(
            &tx_context.highest_indices,
            &tx_context.key_images,
            &tx_context.output_public_keys,
        )?;

        // Check if tx is well-formed, and if it is get the encrypted copy and context for us
        // to store.
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

        let tx_hash = *well_formed_tx_context.tx_hash();

        let entry = CacheEntry {
            encrypted_tx: well_formed_encrypted_tx,
            context: Arc::new(well_formed_tx_context),
        };

        // Store in our cache.
        {
            let mut cache = self.lock_cache();
            cache.insert(tx_hash, entry);
            counters::TX_CACHE_NUM_ENTRIES.set(cache.len() as i64);
        }

        // Success!
        Ok(tx_hash)
    }

    /// Remove expired transactions from the cache and return their hashes.
    pub fn remove_expired(&self, cur_block: u64) -> HashSet<TxHash> {
        let mut cache = self.lock_cache();

        let hashes_before_purge = HashSet::from_iter(cache.keys().cloned());

        cache.retain(|_k, entry| entry.context().tombstone_block() >= cur_block);

        let hashes_after_purge = HashSet::from_iter(cache.keys().cloned());
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

        counters::TX_CACHE_NUM_ENTRIES.set(cache.len() as i64);

        purged_hashes
    }

    /// Returns true if the cache contains the transaction.
    #[allow(dead_code)]
    fn contains(&self, tx_hash: &TxHash) -> bool {
        let cache = self.lock_cache();
        cache.contains_key(tx_hash)
    }

    /// Returns the list of hashes inside `tx_hashes` that are not inside the cache.
    /// TODO: remove this.
    pub fn missing_hashes(&self, tx_hashes: &BTreeSet<TxHash>) -> Vec<TxHash> {
        let mut missing = Vec::new();
        let cache = self.lock_cache();
        for tx_hash in tx_hashes {
            if !cache.contains_key(tx_hash) {
                missing.push(*tx_hash);
            }
        }
        missing
    }

    pub fn num_entries(&self) -> usize {
        self.lock_cache().len()
    }

    /// Check if a transaction, by itself, is safe to append to the current ledger.
    pub fn validate(&self, tx_hash: &TxHash) -> TxManagerResult<()> {
        let cache = self.lock_cache();
        match cache.get(tx_hash) {
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

    /// Combines the transactions that correspond to the given hashes.
    pub fn combine(&self, tx_hashes: &[TxHash]) -> Vec<TxHash> {
        // Dedup
        let tx_hashes: HashSet<&TxHash> = tx_hashes.iter().clone().collect();
        let mut tx_contexts = Vec::new();

        let cache = self.lock_cache();
        for tx_hash in tx_hashes {
            if let Some(entry) = cache.get(&tx_hash) {
                tx_contexts.push(entry.context().clone());
            } else {
                log::error!(self.logger, "Ignoring non-existent TxHash {:?}", tx_hash);
            }
        }

        self.untrusted
            .combine(&tx_contexts, MAX_TRANSACTIONS_PER_BLOCK)
    }

    /// Forms a Block containing the transactions that correspond to the given hashes.
    pub fn tx_hashes_to_block(
        &self,
        tx_hashes: &[TxHash],
        parent_block: &Block,
    ) -> TxManagerResult<(Block, BlockContents, BlockSignature)> {
        let cache = self.lock_cache();
        let encrypted_txs_with_proofs = tx_hashes
            .iter()
            .map(|tx_hash| {
                let entry = cache.get(tx_hash).ok_or_else(|| TxManagerError::NotInCache(*tx_hash))?;

                let (_current_block_index, membership_proofs) = self.untrusted.well_formed_check(
                    entry.context().highest_indices(),
                    entry.context().key_images(),
                    entry.context().output_public_keys(),
                )?;

                Ok((entry.encrypted_tx().clone(), membership_proofs))
            })
            .collect::<Result<Vec<(WellFormedEncryptedTx, Vec<TxOutMembershipProof>)>, TxManagerError>>()?;

        let (block, block_contents, mut signature) = self
            .enclave
            .form_block(&parent_block, &encrypted_txs_with_proofs)?;

        // The enclave cannot provide a timestamp, so this happens in untrusted.
        signature.set_signed_at(chrono::Utc::now().timestamp() as u64);

        Ok((block, block_contents, signature))
    }

    /// Creates a message containing a set of transactions that are encrypted for a peer.
    pub fn encrypt_for_peer(
        &self,
        tx_hashes: &[TxHash],
        aad: &[u8],
        peer: &PeerSession,
    ) -> TxManagerResult<EnclaveMessage<PeerSession>> {
        let encrypted_txs: Result<Vec<WellFormedEncryptedTx>, TxManagerError> = {
            let cache = self.lock_cache();
            tx_hashes
                .iter()
                .map(|tx_hash| {
                    cache
                        .get(tx_hash)
                        .map(|entry| entry.encrypted_tx().clone())
                        .ok_or_else(|| TxManagerError::NotInCache(*tx_hash))
                })
                .collect()
        };

        Ok(self.enclave.txs_for_peer(&encrypted_txs?, aad, peer)?)
    }

    pub fn get_encrypted_tx_by_hash(&self, tx_hash: &TxHash) -> Option<WellFormedEncryptedTx> {
        self.lock_cache()
            .get(tx_hash)
            .map(|entry| entry.encrypted_tx().clone())
    }

    fn lock_cache(&self) -> MutexGuard<HashMap<TxHash, CacheEntry>> {
        self.cache.lock().expect("lock poisoned")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validators::DefaultTxManagerUntrustedInterfaces;
    use mc_common::logger::test_with_logger;
    use mc_consensus_enclave_mock::{
        ConsensusServiceMockEnclave, Error as EnclaveError, MockConsensusEnclave,
    };
    use mc_ledger_db::Ledger;
    use mc_transaction_core_test_utils::{
        create_ledger, create_transaction, initialize_ledger, AccountKey,
    };
    use rand::{rngs::StdRng, SeedableRng};

    #[test_with_logger]
    // Should return Ok when a well-formed Tx is (re)-inserted.
    fn test_insert_ok(logger: Logger) {
        let tx_context = TxContext::default();
        let tx_hash = tx_context.tx_hash;

        let mut mock_untrusted = MockUntrustedInterfaces::new();
        // Untrusted's well-formed check should be called once each time insert_propose_tx is called.
        mock_untrusted
            .expect_well_formed_check()
            .times(1)
            .return_const(Ok((0, vec![])));

        // The enclave's well-formed check also ought to be called, and should return Ok.
        let mut mock_enclave = MockConsensusEnclave::new();

        let well_formed_encrypted_tx = WellFormedEncryptedTx::default();
        let well_formed_tx_context = WellFormedTxContext::new(
            0,
            tx_hash.clone(),
            Default::default(),
            Default::default(),
            Default::default(),
            Default::default(),
        );

        mock_enclave
            .expect_tx_is_well_formed()
            .times(1)
            .return_const(Ok((well_formed_encrypted_tx, well_formed_tx_context)));

        let tx_manager = TxManager::new(mock_enclave, mock_untrusted, logger.clone());
        assert_eq!(tx_manager.num_entries(), 0);

        assert!(tx_manager.insert(tx_context.clone()).is_ok());
        assert_eq!(tx_manager.num_entries(), 1);
        assert!(tx_manager.contains(&tx_hash));

        // Re-inserting should also be Ok.
        assert!(tx_manager.insert(tx_context.clone()).is_ok());
        assert_eq!(tx_manager.num_entries(), 1);
        assert!(tx_manager.contains(&tx_hash));
    }

    #[test_with_logger]
    // Should return return an error when a not well-formed Tx is inserted.
    // Here, the untrusted system says the Tx is not well-formed.
    fn test_insert_error_untrusted(logger: Logger) {
        let tx_context = TxContext::default();

        let mut mock_untrusted = MockUntrustedInterfaces::new();
        // Untrusted's well-formed check should be called once each time insert_propose_tx is called.
        mock_untrusted
            .expect_well_formed_check()
            .times(1)
            .return_const(Err(TransactionValidationError::ContainsSpentKeyImage));

        // This should not be called.
        let mock_enclave = MockConsensusEnclave::new();

        let tx_manager = TxManager::new(mock_enclave, mock_untrusted, logger.clone());
        assert!(tx_manager.insert(tx_context.clone()).is_err());
        assert_eq!(tx_manager.num_entries(), 0);
    }

    #[test_with_logger]
    // Should return return an error when a not well-formed Tx is inserted.
    // Here, the enclave says the Tx is not well-formed.
    fn test_insert_error_trusted(logger: Logger) {
        let tx_context = TxContext::default();

        let mut mock_untrusted = MockUntrustedInterfaces::new();
        // Untrusted's well-formed check should be called once each time insert_propose_tx is called.
        mock_untrusted
            .expect_well_formed_check()
            .times(1)
            .return_const(Ok((0, vec![])));

        // This should be called, and return an error.
        let mut mock_enclave = MockConsensusEnclave::new();
        mock_enclave
            .expect_tx_is_well_formed()
            .times(1)
            .return_const(Err(EnclaveError::Signature));

        let tx_manager = TxManager::new(mock_enclave, mock_untrusted, logger.clone());
        assert!(tx_manager.insert(tx_context.clone()).is_err());
        assert_eq!(tx_manager.num_entries(), 0);
    }

    #[test_with_logger]
    // Should remove all transactions that have expired by the given slot.
    fn test_remove_expired(logger: Logger) {
        let mock_untrusted = MockUntrustedInterfaces::new();
        let mock_enclave = MockConsensusEnclave::new();
        let tx_manager = TxManager::new(mock_enclave, mock_untrusted, logger.clone());

        // Fill the cache with entries that have different tombstone blocks.
        for tombstone_block in 10..24 {
            let context = WellFormedTxContext::new(
                Default::default(),
                TxHash([tombstone_block as u8; 32]),
                tombstone_block,
                Default::default(),
                Default::default(),
                Default::default(),
            );

            let cache_entry = CacheEntry {
                encrypted_tx: Default::default(),
                context: Arc::new(context.clone()),
            };

            tx_manager
                .cache
                .lock()
                .unwrap()
                .insert(context.tx_hash().clone(), cache_entry);
        }

        assert_eq!(tx_manager.num_entries(), 14);

        {
            // By block index 10, none have expired.
            let removed = tx_manager.remove_expired(10);
            assert_eq!(removed.len(), 0);
            assert_eq!(tx_manager.num_entries(), 14);
        }

        {
            // By block index 15, some have expired.
            let removed = tx_manager.remove_expired(15);
            assert_eq!(removed.len(), 5);
            assert_eq!(tx_manager.num_entries(), 9);
        }

        {
            // By block index 24, all have expired.
            let removed = tx_manager.remove_expired(24);
            assert_eq!(removed.len(), 9);
            assert_eq!(tx_manager.num_entries(), 0);
        }
    }

    #[test_with_logger]
    fn test_hashes_to_block(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([77u8; 32]);
        let sender = AccountKey::random(&mut rng);
        let mut ledger = create_ledger();
        let n_blocks = 3;
        initialize_ledger(&mut ledger, n_blocks, &sender, &mut rng);

        let num_blocks = ledger.num_blocks().expect("Ledger must contain a block.");
        let parent_block = ledger.get_block(num_blocks - 1).unwrap();

        let tx_manager = TxManager::new(
            ConsensusServiceMockEnclave::default(),
            DefaultTxManagerUntrustedInterfaces::new(ledger.clone()),
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

        let hash_tx_zero = tx_manager
            .insert(ConsensusServiceMockEnclave::tx_to_tx_context(
                &client_tx_zero,
            ))
            .unwrap();

        let hash_tx_one = tx_manager
            .insert(ConsensusServiceMockEnclave::tx_to_tx_context(
                &client_tx_one,
            ))
            .unwrap();

        let hash_tx_two = tx_manager
            .insert(ConsensusServiceMockEnclave::tx_to_tx_context(
                &client_tx_two,
            ))
            .unwrap();

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
        // TODO: Right now this relies on ConsensusServiceMockEnclave::form_block
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
