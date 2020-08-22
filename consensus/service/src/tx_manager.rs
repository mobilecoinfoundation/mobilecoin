// Copyright (c) 2018-2020 MobileCoin Inc.

//! TxManager maps operations on transaction hashes to in-enclave operations on the corresponding transactions.
//!
//! Internally, TxManager maintains a collection of (encrypted) transactions that have been found
//! to be well-formed. These can be thought of as the "working set" of transactions that the consensus service
//! may operate on.

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
use std::sync::{Mutex, MutexGuard};

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
    /// An encrypted transaction that has been found to be well-formed.
    encrypted_tx: WellFormedEncryptedTx,

    /// Context exposed by the enclave about this transaction.
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
    fn is_valid(&self, context: Arc<WellFormedTxContext>) -> TransactionValidationResult<()>;

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
                return Ok(*entry.context.tx_hash());
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
    ///
    /// # Arguments
    /// * `block_index` - Current block index.
    pub fn remove_expired(&self, block_index: u64) -> HashSet<TxHash> {
        let mut cache = self.lock_cache();

        let (expired, retained): (HashMap<_, _>, HashMap<_, _>) = cache
            .drain()
            .partition(|(_, entry)| entry.context().tombstone_block() < block_index);

        cache.extend(retained.into_iter());

        log::debug!(
            self.logger,
            "Removed {} expired transactions, retained {}",
            expired.len(),
            cache.len(),
        );

        counters::TX_CACHE_NUM_ENTRIES.set(cache.len() as i64);

        expired.into_iter().map(|(tx_hash, _)| tx_hash).collect()
    }

    /// Returns the list of hashes inside `tx_hashes` that are not inside the cache.
    pub fn missing_hashes<T>(&self, tx_hashes: &T) -> Vec<TxHash>
    where
        for<'a> &'a T: IntoIterator<Item = &'a TxHash>,
    {
        let cache = self.lock_cache();
        tx_hashes
            .into_iter()
            .filter(|tx_hash| !cache.contains_key(tx_hash))
            .cloned()
            .collect()
    }

    pub fn num_entries(&self) -> usize {
        self.lock_cache().len()
    }

    /// Validate the transaction corresponding to the given hash against the current ledger.
    pub fn validate(&self, tx_hash: &TxHash) -> TxManagerResult<()> {
        let context_opt = {
            let cache = self.lock_cache();
            cache.get(tx_hash).map(|entry| entry.context.clone())
        };

        if let Some(context) = context_opt {
            let _timer = counters::VALIDATE_TX_TIME.start_timer();
            self.untrusted.is_valid(context)?;
            Ok(())
        } else {
            log::error!(
                self.logger,
                "attempting to validate non-existent tx hash {:?}",
                tx_hash
            );
            Err(TxManagerError::NotInCache(*tx_hash))
        }
    }

    /// Combines the transactions that correspond to the given hashes.
    pub fn combine(&self, tx_hashes: &[TxHash]) -> TxManagerResult<Vec<TxHash>> {
        let tx_contexts: Vec<Arc<WellFormedTxContext>> = {
            let cache = self.lock_cache();
            let res: TxManagerResult<Vec<_>> = tx_hashes
                .iter()
                .map(|tx_hash| {
                    cache
                        .get(tx_hash)
                        .map(|entry| entry.context().clone())
                        .ok_or(TxManagerError::NotInCache(*tx_hash))
                })
                .collect();
            res?
        };

        Ok(self
            .untrusted
            .combine(&tx_contexts, MAX_TRANSACTIONS_PER_BLOCK))
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
    ///
    /// # Arguments
    /// * `tx_hashes` - transaction hashes.
    /// * `aad` - Additional authenticated data.
    /// * `peer` - Recipient of the encrypted message.
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

    /// Get the encrypted transaction corresponding to the given hash.
    pub fn get_encrypted_tx(&self, tx_hash: &TxHash) -> Option<WellFormedEncryptedTx> {
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
        assert!(tx_manager.lock_cache().contains_key(&tx_hash));

        // Re-inserting should also be Ok.
        assert!(tx_manager.insert(tx_context.clone()).is_ok());
        assert_eq!(tx_manager.num_entries(), 1);
        assert!(tx_manager.lock_cache().contains_key(&tx_hash));
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
    // Should return Ok if the transaction is in the cache and is valid.
    fn test_validate_ok(logger: Logger) {
        let tx_context = TxContext::default();

        let mut mock_untrusted = MockUntrustedInterfaces::new();

        // Untrusted's validate check should be called and return Ok.
        mock_untrusted
            .expect_is_valid()
            .times(1)
            .return_const(Ok(()));

        // The enclave is not called because its checks are "well-formed-ness" checks.
        let mock_enclave = MockConsensusEnclave::new();

        let tx_manager = TxManager::new(mock_enclave, mock_untrusted, logger.clone());

        // Add this transaction to the cache.
        let cache_entry = CacheEntry {
            encrypted_tx: Default::default(),
            context: Arc::new(Default::default()),
        };
        tx_manager
            .cache
            .lock()
            .unwrap()
            .insert(tx_context.tx_hash.clone(), cache_entry);

        assert!(tx_manager.validate(&tx_context.tx_hash).is_ok());
    }

    #[test_with_logger]
    // Should return Err if the transaction is not in the cache.
    fn test_validate_err_not_in_cache(logger: Logger) {
        let tx_context = TxContext::default();

        // The method should return before calling untrusted.
        let mock_untrusted = MockUntrustedInterfaces::new();

        // The enclave is not called because its checks are "well-formed-ness" checks.
        let mock_enclave = MockConsensusEnclave::new();

        let tx_manager = TxManager::new(mock_enclave, mock_untrusted, logger.clone());
        match tx_manager.validate(&tx_context.tx_hash) {
            Err(TxManagerError::NotInCache(_)) => {} // This is expected.
            _ => panic!(),
        }
    }

    #[test_with_logger]
    // Should return Err if the transaction is in the cache (i.e., well-formed) but not valid.
    fn test_validate_err_not_valid(logger: Logger) {
        let tx_context = TxContext::default();

        // The method should return before calling untrusted.
        let mut mock_untrusted = MockUntrustedInterfaces::new();

        // Untrusted's validate check should be called and return Err.
        mock_untrusted
            .expect_is_valid()
            .times(1)
            .return_const(Err(TransactionValidationError::ContainsSpentKeyImage));

        // The enclave is not called because its checks are "well-formed-ness" checks.
        let mock_enclave = MockConsensusEnclave::new();

        let tx_manager = TxManager::new(mock_enclave, mock_untrusted, logger.clone());

        // Add this transaction to the cache.
        let cache_entry = CacheEntry {
            encrypted_tx: Default::default(),
            context: Arc::new(Default::default()),
        };
        tx_manager
            .cache
            .lock()
            .unwrap()
            .insert(tx_context.tx_hash.clone(), cache_entry);

        match tx_manager.validate(&tx_context.tx_hash) {
            Err(TxManagerError::TransactionValidation(
                TransactionValidationError::ContainsSpentKeyImage,
            )) => {} // This is expected.
            _ => panic!(),
        }
    }

    #[test_with_logger]
    // Should return Ok if the transactions are in the cache.
    fn test_combine_ok(logger: Logger) {
        let tx_hashes: Vec<_> = (0..10).map(|i| TxHash([i as u8; 32])).collect();

        let mut mock_untrusted = MockUntrustedInterfaces::new();
        let expected: Vec<_> = tx_hashes.iter().take(5).cloned().collect();
        mock_untrusted
            .expect_combine()
            .times(1)
            .return_const(expected.clone());

        let mock_enclave = MockConsensusEnclave::new();
        let tx_manager = TxManager::new(mock_enclave, mock_untrusted, logger.clone());

        // Add transactions to the cache.
        for tx_hash in &tx_hashes {
            let context = WellFormedTxContext::new(
                Default::default(),
                tx_hash.clone(),
                Default::default(),
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
        assert_eq!(tx_manager.num_entries(), tx_hashes.len());

        // // TODO: combine should return a Result.
        // assert_eq!(tx_manager.combine(&tx_hashes), expected);
        //
        match tx_manager.combine(&tx_hashes) {
            Ok(combined) => assert_eq!(combined, expected),
            _ => panic!(),
        }
    }

    #[test_with_logger]
    #[ignore]
    // Should return Err if any transaction is not in the cache.
    fn test_combine_err_not_in_cache(_logger: Logger) {
        // TODO: combine should return a Result.
        unimplemented!()
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

    #[test_with_logger]
    // Should call enclave.txs_for_peer
    fn test_encrypt_for_peer_ok(logger: Logger) {
        let mock_untrusted = MockUntrustedInterfaces::new();
        let mut mock_enclave = MockConsensusEnclave::new();

        // This should be called to perform the encryption.
        mock_enclave
            .expect_txs_for_peer()
            .times(1)
            .return_const(Ok(EnclaveMessage::default()));

        let tx_manager = TxManager::new(mock_enclave, mock_untrusted, logger.clone());

        // Add transactions to the cache.
        let tx_hashes: Vec<_> = (0..10).map(|i| TxHash([i as u8; 32])).collect();
        for tx_hash in &tx_hashes {
            let context = WellFormedTxContext::new(
                Default::default(),
                tx_hash.clone(),
                Default::default(),
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
        assert_eq!(tx_manager.num_entries(), tx_hashes.len());

        let aad = "Additional authenticated data";
        let peer = PeerSession::default();
        assert!(tx_manager
            .encrypt_for_peer(&tx_hashes, aad.as_bytes(), &peer)
            .is_ok());
    }

    #[test_with_logger]
    // Should return an error if any transaction is not in the cache.
    fn test_encrypt_for_peer_err_not_in_cache(logger: Logger) {
        let mock_untrusted = MockUntrustedInterfaces::new();
        let mock_enclave = MockConsensusEnclave::new();

        let tx_manager = TxManager::new(mock_enclave, mock_untrusted, logger.clone());
        assert_eq!(tx_manager.num_entries(), 0);

        let tx_hashes: Vec<_> = (0..10).map(|i| TxHash([i as u8; 32])).collect();
        let aad = "Additional authenticated data";
        let peer = PeerSession::default();
        match tx_manager.encrypt_for_peer(&tx_hashes, aad.as_bytes(), &peer) {
            Err(TxManagerError::NotInCache(_)) => {} // This is expected.
            _ => panic!(),
        }
    }

    #[test_with_logger]
    // Should return an error if enclave.txs_for_peer returns an error.
    fn test_encrypt_for_peer_err_enclave_error(logger: Logger) {
        let mock_untrusted = MockUntrustedInterfaces::new();
        let mut mock_enclave = MockConsensusEnclave::new();

        // This should be called and should return an error.
        mock_enclave
            .expect_txs_for_peer()
            .times(1)
            .return_const(Err(EnclaveError::Signature));

        let tx_manager = TxManager::new(mock_enclave, mock_untrusted, logger.clone());

        // Add transactions to the cache.
        let tx_hashes: Vec<_> = (0..10).map(|i| TxHash([i as u8; 32])).collect();
        for tx_hash in &tx_hashes {
            let context = WellFormedTxContext::new(
                Default::default(),
                tx_hash.clone(),
                Default::default(),
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
        assert_eq!(tx_manager.num_entries(), tx_hashes.len());

        let aad = "Additional authenticated data";
        let peer = PeerSession::default();

        match tx_manager.encrypt_for_peer(&tx_hashes, aad.as_bytes(), &peer) {
            Err(TxManagerError::Enclave(EnclaveError::Signature)) => {} // This is expected.
            _ => panic!(),
        }
    }

    #[test_with_logger]
    // Should return cache_entry.encrypted_tx if it is in the cache.
    fn test_get_encrypted_tx(logger: Logger) {
        let mock_untrusted = MockUntrustedInterfaces::new();
        let mock_enclave = MockConsensusEnclave::new();
        let tx_manager = TxManager::new(mock_enclave, mock_untrusted, logger.clone());

        // Add a transaction to the cache.
        let cache_entry = CacheEntry {
            encrypted_tx: WellFormedEncryptedTx(vec![1, 2, 3]),
            context: Default::default(),
        };

        let tx_hash = TxHash([1u8; 32]);
        tx_manager
            .cache
            .lock()
            .unwrap()
            .insert(tx_hash.clone(), cache_entry);

        // Get something that is in the cache.
        assert_eq!(
            tx_manager.get_encrypted_tx(&tx_hash),
            Some(WellFormedEncryptedTx(vec![1, 2, 3]))
        );

        // Get something that is not in the cache.
        assert_eq!(tx_manager.get_encrypted_tx(&TxHash([88u8; 32])), None);
    }

    #[test_with_logger]
    // Should return the number of elements in the cache.
    fn test_get_num_entries(logger: Logger) {
        let mock_untrusted = MockUntrustedInterfaces::new();
        let mock_enclave = MockConsensusEnclave::new();
        let tx_manager = TxManager::new(mock_enclave, mock_untrusted, logger.clone());

        // Initially, the cache is empty.
        assert_eq!(tx_manager.num_entries(), 0);

        // Add transactions to the cache.
        let tx_hashes: Vec<_> = (0..10).map(|i| TxHash([i as u8; 32])).collect();
        for tx_hash in &tx_hashes {
            let context = WellFormedTxContext::new(
                Default::default(),
                tx_hash.clone(),
                Default::default(),
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
        assert_eq!(tx_manager.num_entries(), tx_hashes.len());
    }
}
