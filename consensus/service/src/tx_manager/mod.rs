// Copyright (c) 2018-2021 The MobileCoin Foundation

//! TxManager maps operations on transaction hashes to in-enclave operations on
//! the corresponding transactions.
//!
//! Internally, TxManager maintains a collection of (encrypted) transactions
//! that have been found to be well-formed. These can be thought of as the
//! "working set" of transactions that the consensus service may operate on.

use crate::counters;
use mc_attest_enclave_api::{EnclaveMessage, PeerSession};
use mc_common::{
    logger::{log, Logger},
    HashMap, HashSet,
};
use mc_consensus_enclave::{
    ConsensusEnclave, TxContext, WellFormedEncryptedTx, WellFormedTxContext,
};
use mc_transaction_core::{
    constants::MAX_TRANSACTIONS_PER_BLOCK,
    tx::{TxHash, TxOutMembershipProof},
    Block, BlockContents, BlockSignature,
};
use std::sync::{Arc, Mutex, MutexGuard};

mod error;
mod tx_manager_trait;
mod untrusted_interfaces;

pub use error::{TxManagerError, TxManagerResult};
pub use tx_manager_trait::TxManager;
pub use untrusted_interfaces::UntrustedInterfaces;

#[cfg(test)]
pub use tx_manager_trait::MockTxManager;

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

#[derive(Clone)]
pub struct TxManagerImpl<E: ConsensusEnclave + Send, UI: UntrustedInterfaces + Send> {
    /// Enclave.
    enclave: E,

    /// Application-specific custom interfaces for the untrusted part of
    /// validation/combining of values.
    untrusted: UI,

    /// Well-formed transactions, keyed by hash.
    cache: Arc<Mutex<HashMap<TxHash, CacheEntry>>>,

    /// Logger.
    logger: Logger,
}

impl<E: ConsensusEnclave + Send, UI: UntrustedInterfaces + Send> TxManagerImpl<E, UI> {
    /// Construct a new TxManager instance.
    pub fn new(enclave: E, untrusted: UI, logger: Logger) -> Self {
        Self {
            enclave,
            untrusted,
            logger,
            cache: Arc::new(Mutex::new(HashMap::default())),
        }
    }

    /// Performs the untrusted and enclave parts of the well-formed checks.
    /// If the transaction is well-formed, returns a new CacheEntry that may be
    /// added to the cache.
    fn is_well_formed(&self, tx_context: TxContext) -> TxManagerResult<CacheEntry> {
        let _metrics_timer = counters::WELL_FORMED_CHECK_TIME.start_timer();

        // The untrusted part of the well-formed check.
        let (current_block_index, highest_index_proofs) =
            self.untrusted.well_formed_check(&tx_context)?;

        // The enclave part of the well-formed check.
        let (well_formed_encrypted_tx, well_formed_tx_context) = self.enclave.tx_is_well_formed(
            tx_context.locally_encrypted_tx,
            current_block_index,
            highest_index_proofs,
        )?;

        Ok(CacheEntry {
            encrypted_tx: well_formed_encrypted_tx,
            context: Arc::new(well_formed_tx_context),
        })
    }

    fn lock_cache(&self) -> MutexGuard<HashMap<TxHash, CacheEntry>> {
        self.cache.lock().expect("Lock poisoned")
    }
}

impl<E: ConsensusEnclave + Send, UI: UntrustedInterfaces + Send> TxManager
    for TxManagerImpl<E, UI>
{
    /// Insert a transaction into the cache. The transaction must be
    /// well-formed.
    fn insert(&self, tx_context: TxContext) -> TxManagerResult<TxHash> {
        let tx_hash = tx_context.tx_hash;

        {
            let cache = self.lock_cache();
            if let Some(entry) = cache.get(&tx_context.tx_hash) {
                // The transaction is well-formed and is in the cache.
                return Ok(*entry.context.tx_hash());
            }
        }

        let new_entry = self.is_well_formed(tx_context)?;

        {
            let mut cache = self.lock_cache();
            cache.insert(tx_hash, new_entry);
            counters::TX_CACHE_NUM_ENTRIES.set(cache.len() as i64);
        }

        log::trace!(
            self.logger,
            "Cached well-formed transaction {hash}",
            hash = tx_hash.to_string(),
        );

        Ok(tx_hash)
    }

    /// Remove expired transactions from the cache and return their hashes.
    ///
    /// # Arguments
    /// * `block_index` - Current block index.
    fn remove_expired(&self, block_index: u64) -> HashSet<TxHash> {
        let mut expired = HashSet::<TxHash>::default();

        let mut cache = self.lock_cache();

        // find the expired entries and remove them, storing their keys in expired,
        // without destroying or re-allocating the cache
        cache.retain(|key, entry| -> bool {
            if entry.context().tombstone_block() <= block_index {
                expired.insert(*key);
                false
            } else {
                true
            }
        });

        counters::TX_CACHE_NUM_ENTRIES.set(cache.len() as i64);

        log::debug!(
            self.logger,
            "Removed {} expired transactions, retained {}",
            expired.len(),
            cache.len(),
        );

        expired
    }

    /// Returns true if the cache contains the corresponding transaction.
    fn contains(&self, tx_hash: &TxHash) -> bool {
        self.lock_cache().contains_key(tx_hash)
    }

    /// Number of cached entries.
    fn num_entries(&self) -> usize {
        self.lock_cache().len()
    }

    /// Validate the transaction corresponding to the given hash against the
    /// current ledger.
    fn validate(&self, tx_hash: &TxHash) -> TxManagerResult<()> {
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
            Err(TxManagerError::NotInCache(vec![*tx_hash]))
        }
    }

    /// Combines the transactions that correspond to the given hashes.
    fn combine(&self, tx_hashes: &[TxHash]) -> TxManagerResult<Vec<TxHash>> {
        let tx_hashes: HashSet<&TxHash> = tx_hashes.iter().clone().collect(); // Dedup

        let tx_contexts: TxManagerResult<Vec<Arc<WellFormedTxContext>>> = {
            let cache = self.lock_cache();

            // Split `tx_hashes` into a list of found hashes and missing ones. This allows
            // us to return an error with the entire list of missing hashes.
            let (entries, not_found) = tx_hashes
                .iter()
                .map(|tx_hash| {
                    cache
                        .get(tx_hash)
                        .map_or_else(|| (*tx_hash, None), |entry| (*tx_hash, Some(entry)))
                })
                .partition::<Vec<_>, _>(|(_tx_hash, result)| result.is_some());

            // If we are missing any hashes, return error.
            if !not_found.is_empty() {
                let not_found_tx_hashes =
                    not_found.into_iter().map(|(tx_hash, _)| *tx_hash).collect();
                return Err(TxManagerError::NotInCache(not_found_tx_hashes));
            }

            // Collect tx contexts.
            Ok(entries
                .into_iter()
                .map(|(_tx_hash, entry)| entry.unwrap().context().clone())
                .collect())
        };

        // Perform the combine operation.
        Ok(self
            .untrusted
            .combine(&tx_contexts?, MAX_TRANSACTIONS_PER_BLOCK))
    }

    /// Forms a Block containing the transactions that correspond to the given
    /// hashes.
    ///
    /// # Arguments
    /// * `tx_hashes` - Hashes of well-formed transactions that are valid w.r.t.
    ///   te current ledger.
    /// * `parent_block` - The last block written to the ledger.
    fn tx_hashes_to_block(
        &self,
        tx_hashes: &[TxHash],
        parent_block: &Block,
    ) -> TxManagerResult<(Block, BlockContents, BlockSignature)> {
        let cache = self.lock_cache();

        // Split `tx_hashes` into a list of found hashes and missing ones. This allows
        // us to return an error with the entire list of missing hashes.
        let (entries, not_found) = tx_hashes
            .iter()
            .map(|tx_hash| {
                cache
                    .get(tx_hash)
                    .map_or_else(|| (*tx_hash, None), |entry| (*tx_hash, Some(entry)))
            })
            .partition::<Vec<_>, _>(|(_tx_hash, result)| result.is_some());

        // If we are missing any hashes, return error.
        if !not_found.is_empty() {
            let not_found_tx_hashes = not_found.into_iter().map(|(tx_hash, _)| tx_hash).collect();
            return Err(TxManagerError::NotInCache(not_found_tx_hashes));
        }

        // Proceed with forming the block.
        let encrypted_txs_with_proofs = entries
            .into_iter()
            .map(|(_tx_hash, entry)| {
                let entry = entry.unwrap();
                // Highest indices proofs must be w.r.t. the current ledger.
                // Recreating them here is a crude way to ensure that.
                let highest_index_proofs: Vec<_> = self
                    .untrusted
                    .get_tx_out_proof_of_memberships(entry.context.highest_indices())?;

                Ok((entry.encrypted_tx().clone(), highest_index_proofs))
            })
            .collect::<Result<Vec<(WellFormedEncryptedTx, Vec<TxOutMembershipProof>)>, TxManagerError>>()?;

        let (block, block_contents, mut signature) = self
            .enclave
            .form_block(&parent_block, &encrypted_txs_with_proofs)?;

        // The enclave cannot provide a timestamp, so this happens in untrusted.
        signature.set_signed_at(chrono::Utc::now().timestamp() as u64);

        Ok((block, block_contents, signature))
    }

    /// Creates a message containing a set of transactions that are encrypted
    /// for a peer.
    ///
    /// # Arguments
    /// * `tx_hashes` - transaction hashes.
    /// * `aad` - Additional authenticated data.
    /// * `peer` - Recipient of the encrypted message.
    fn encrypt_for_peer(
        &self,
        tx_hashes: &[TxHash],
        aad: &[u8],
        peer: &PeerSession,
    ) -> TxManagerResult<EnclaveMessage<PeerSession>> {
        // Split `tx_hashes` into a list of found hashes and missing ones. This allows
        // us to return an error with the entire list of missing hashes.
        let (encrypted_txs, not_found) = {
            let cache = self.lock_cache();
            tx_hashes
                .iter()
                .map(|tx_hash| {
                    cache.get(tx_hash).map_or_else(
                        || (*tx_hash, None),
                        |entry| (*tx_hash, Some(entry.encrypted_tx().clone())),
                    )
                })
                .partition::<Vec<_>, _>(|(_tx_hash, result)| result.is_some())
        };

        // If we are missing any hashes, return error.
        if !not_found.is_empty() {
            let not_found_tx_hashes = not_found.into_iter().map(|(tx_hash, _)| tx_hash).collect();
            return Err(TxManagerError::NotInCache(not_found_tx_hashes));
        }

        // Proceed with producing encrypted txs for the given peer.
        let encrypted_txs: Vec<_> = encrypted_txs
            .into_iter()
            .map(|(_, result)| result.unwrap())
            .collect();

        Ok(self.enclave.txs_for_peer(&encrypted_txs, aad, peer)?)
    }

    /// Get the encrypted transaction corresponding to the given hash.
    fn get_encrypted_tx(&self, tx_hash: &TxHash) -> Option<WellFormedEncryptedTx> {
        self.lock_cache()
            .get(tx_hash)
            .map(|entry| entry.encrypted_tx().clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        tx_manager::untrusted_interfaces::MockUntrustedInterfaces,
        validators::DefaultTxManagerUntrustedInterfaces,
    };
    use mc_common::logger::test_with_logger;
    use mc_consensus_enclave_mock::{
        ConsensusServiceMockEnclave, Error as EnclaveError, MockConsensusEnclave,
    };
    use mc_crypto_keys::{Ed25519Public, Ed25519Signature};
    use mc_ledger_db::Ledger;
    use mc_transaction_core::validation::TransactionValidationError;
    use mc_transaction_core_test_utils::{
        create_ledger, create_transaction, initialize_ledger, AccountKey,
    };
    use rand::{rngs::StdRng, SeedableRng};

    #[test_with_logger]
    // Should return Ok when a well-formed Tx is inserted.
    fn test_insert_ok(logger: Logger) {
        let tx_context = TxContext::default();
        let tx_hash = tx_context.tx_hash;

        let mut mock_untrusted = MockUntrustedInterfaces::new();
        // Untrusted's well-formed check should be called once each time
        // insert_propose_tx is called.
        mock_untrusted
            .expect_well_formed_check()
            .times(1)
            .return_const(Ok((0, vec![])));

        // The enclave's well-formed check also ought to be called, and should return
        // Ok.
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

        let tx_manager = TxManagerImpl::new(mock_enclave, mock_untrusted, logger.clone());
        assert_eq!(tx_manager.num_entries(), 0);

        assert!(tx_manager.insert(tx_context.clone()).is_ok());
        assert_eq!(tx_manager.num_entries(), 1);
        assert!(tx_manager.lock_cache().contains_key(&tx_hash));
    }

    #[test_with_logger]
    // Should return Ok when a well-formed Tx is re-inserted.
    fn test_reinsert_ok(logger: Logger) {
        let tx_context = TxContext::default();
        let tx_hash = tx_context.tx_hash;

        let mut mock_untrusted = MockUntrustedInterfaces::new();
        // Untrusted's well-formed check should be called once each time
        // insert_propose_tx is called.
        mock_untrusted
            .expect_well_formed_check()
            .times(1)
            .return_const(Ok((0, vec![])));

        // The enclave's well-formed check also ought to be called, and should return
        // Ok.
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

        let tx_manager = TxManagerImpl::new(mock_enclave, mock_untrusted, logger.clone());
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
        // Untrusted's well-formed check should be called once each time
        // insert_propose_tx is called.
        mock_untrusted
            .expect_well_formed_check()
            .times(1)
            .return_const(Err(TransactionValidationError::ContainsSpentKeyImage));

        // This should not be called.
        let mock_enclave = MockConsensusEnclave::new();

        let tx_manager = TxManagerImpl::new(mock_enclave, mock_untrusted, logger.clone());
        assert!(tx_manager.insert(tx_context.clone()).is_err());
        assert_eq!(tx_manager.num_entries(), 0);
    }

    #[test_with_logger]
    // Should return return an error when a not well-formed Tx is inserted.
    // Here, the enclave says the Tx is not well-formed.
    fn test_insert_error_trusted(logger: Logger) {
        let tx_context = TxContext::default();

        let mut mock_untrusted = MockUntrustedInterfaces::new();
        // Untrusted's well-formed check should be called once each time
        // insert_propose_tx is called.
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

        let tx_manager = TxManagerImpl::new(mock_enclave, mock_untrusted, logger.clone());
        assert!(tx_manager.insert(tx_context.clone()).is_err());
        assert_eq!(tx_manager.num_entries(), 0);
    }

    #[test_with_logger]
    // Should remove all transactions that have expired by the given slot.
    fn test_remove_expired(logger: Logger) {
        let mock_untrusted = MockUntrustedInterfaces::new();
        let mock_enclave = MockConsensusEnclave::new();
        let tx_manager = TxManagerImpl::new(mock_enclave, mock_untrusted, logger.clone());

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
            // By block index 9, none have expired.
            let removed = tx_manager.remove_expired(9);
            assert_eq!(removed.len(), 0);
            assert_eq!(tx_manager.num_entries(), 14);
        }

        {
            // By block index 10, one has expired.
            let removed = tx_manager.remove_expired(10);
            assert_eq!(removed.len(), 1);
            assert_eq!(tx_manager.num_entries(), 13);
        }

        {
            // By block index 15, some have expired.
            let removed = tx_manager.remove_expired(15);
            assert_eq!(removed.len(), 5);
            assert_eq!(tx_manager.num_entries(), 8);
        }

        {
            // By block index 24, all have expired.
            let removed = tx_manager.remove_expired(24);
            assert_eq!(removed.len(), 8);
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

        let tx_manager = TxManagerImpl::new(mock_enclave, mock_untrusted, logger.clone());

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

        let tx_manager = TxManagerImpl::new(mock_enclave, mock_untrusted, logger.clone());
        match tx_manager.validate(&tx_context.tx_hash) {
            Err(TxManagerError::NotInCache(_)) => {} // This is expected.
            _ => panic!(),
        }
    }

    #[test_with_logger]
    // Should return Err if the transaction is in the cache (i.e., well-formed) but
    // not valid.
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

        let tx_manager = TxManagerImpl::new(mock_enclave, mock_untrusted, logger.clone());

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
        let tx_manager = TxManagerImpl::new(mock_enclave, mock_untrusted, logger.clone());

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

        match tx_manager.combine(&tx_hashes) {
            Ok(combined) => assert_eq!(combined, expected),
            _ => panic!(),
        }
    }

    #[test_with_logger]
    // Should return Err if any transaction is not in the cache.
    fn test_combine_err_not_in_cache(logger: Logger) {
        let n_transactions = 10;
        let tx_hashes: Vec<_> = (0..n_transactions).map(|i| TxHash([i as u8; 32])).collect();

        // UntrustedInterfaces should not be called.
        let mock_untrusted = MockUntrustedInterfaces::new();

        // ConsensusEnclave should not be called.
        let mock_enclave = MockConsensusEnclave::new();
        let tx_manager = TxManagerImpl::new(mock_enclave, mock_untrusted, logger.clone());

        // Add some transactions, but not all, to the cache.
        for tx_hash in &tx_hashes[2..] {
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

        match tx_manager.combine(&tx_hashes) {
            Ok(_combined) => panic!(),
            _ => {} // This is expected.
        }
    }

    // TODO: tx_hashed_to_block should provide correct proofs for highest indices

    #[test_with_logger]
    // Should return correct block when all transactions are in the cache.
    fn test_hashes_to_block_ok(logger: Logger) {
        let tx_hashes = vec![TxHash([7u8; 32]), TxHash([44u8; 32]), TxHash([3u8; 32])];
        let parent_block = Block::new_origin_block(&vec![]);

        let mut mock_untrusted = MockUntrustedInterfaces::new();

        let highest_index_proofs = vec![
            TxOutMembershipProof::new(1, 2, vec![]),
            TxOutMembershipProof::new(3, 4, vec![]),
        ];
        // Should get "highest index proofs" once per transaction.
        mock_untrusted
            .expect_get_tx_out_proof_of_memberships()
            .times(tx_hashes.len())
            .return_const(Ok(highest_index_proofs));

        let mut mock_enclave = MockConsensusEnclave::new();
        let expected_block = Block::new_origin_block(&vec![]);
        let expected_block_contents = BlockContents::new(vec![], vec![]);
        // The enclave does not set the signed_at field.
        let expected_block_signature =
            BlockSignature::new(Ed25519Signature::default(), Ed25519Public::default(), 0);

        mock_enclave.expect_form_block().times(1).return_const(Ok((
            expected_block.clone(),
            expected_block_contents.clone(),
            expected_block_signature.clone(),
        )));

        let tx_manager = TxManagerImpl::new(mock_enclave, mock_untrusted, logger);

        // All transactions must be in the cache.
        for tx_hash in &tx_hashes {
            let cache_entry = CacheEntry {
                encrypted_tx: Default::default(),
                context: Arc::new(Default::default()),
            };
            tx_manager.lock_cache().insert(*tx_hash, cache_entry);
        }

        match tx_manager.tx_hashes_to_block(&tx_hashes, &parent_block) {
            Ok((block, block_contents, block_signature)) => {
                assert_eq!(block, expected_block);
                assert_eq!(block_contents, expected_block_contents);
                // The signed_at field of the signature should be non-zero.
                assert!(block_signature.signed_at() > 0);
            }
            Err(e) => panic!("Unexpected error {:?}", e),
        }
    }

    #[test_with_logger]
    // Should return TxManagerError::NotInCache if any transactions are not in the
    // cache.
    fn test_hashes_to_block_missing_hashes(logger: Logger) {
        let tx_manager = TxManagerImpl::new(
            MockConsensusEnclave::new(),
            MockUntrustedInterfaces::new(),
            logger,
        );

        let mut tx_hashes = vec![TxHash([7u8; 32]), TxHash([44u8; 32]), TxHash([3u8; 32])];
        let parent_block = Block::new_origin_block(&vec![]);

        // Add three transactions to the cache.
        for tx_hash in &tx_hashes {
            let cache_entry = CacheEntry {
                encrypted_tx: Default::default(),
                context: Arc::new(Default::default()),
            };
            tx_manager.lock_cache().insert(*tx_hash, cache_entry);
        }

        // This transaction is not in the cache.
        let not_in_cache = TxHash([66u8; 32]);
        tx_hashes.insert(2, not_in_cache.clone());

        match tx_manager.tx_hashes_to_block(&tx_hashes, &parent_block) {
            Ok((_block, _block_contents, _block_signature)) => {
                panic!();
            }
            Err(TxManagerError::NotInCache(hashes)) => {
                // This is expected.
                assert_eq!(hashes, vec![not_in_cache]);
            }
            Err(e) => panic!("Unexpected error {:?}", e),
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

        let tx_manager = TxManagerImpl::new(
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
        // TODO: The logic for actually making sure of this lives inside the Enclave, so
        // it cannot currently be tested here.
        // assert!(tx_manager
        //     .tx_hashes_to_block(&vec![hash_tx_zero, hash_tx_one, hash_tx_zero])
        //     .is_err());

        // Attempting to assemble a block with a duplicate and a missing transaction
        // should fail TODO: The logic for actually making sure of this lives
        // inside the Enclave, so it cannot currently be tested here.
        // assert!(tx_manager
        //     .tx_hashes_to_block(&vec![hash_tx_zero, hash_tx_zero, hash_tx_three])
        //     .is_err());

        // Attempting to assemble a block without duplicates or missing transactions
        // should succeed.
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

        let tx_manager = TxManagerImpl::new(mock_enclave, mock_untrusted, logger.clone());

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

        let tx_manager = TxManagerImpl::new(mock_enclave, mock_untrusted, logger.clone());
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

        let tx_manager = TxManagerImpl::new(mock_enclave, mock_untrusted, logger.clone());

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
        let tx_manager = TxManagerImpl::new(mock_enclave, mock_untrusted, logger.clone());

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
        let tx_manager = TxManagerImpl::new(mock_enclave, mock_untrusted, logger.clone());

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
