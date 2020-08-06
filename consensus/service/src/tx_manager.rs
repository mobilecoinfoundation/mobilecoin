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
use mockall::*;
use std::collections::BTreeSet;

#[derive(Clone, Debug, Fail)]
pub enum TxManagerError {
    #[fail(display = "Enclave error: {}", _0)]
    Enclave(ConsensusEnclaveError),

    #[fail(display = "Transaction validation error: {}", _0)]
    TransactionValidation(TransactionValidationError),

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
    /// Insert a transaction into the cache. The transaction must be well-formed.
    fn insert(&mut self, tx_context: TxContext) -> TxManagerResult<WellFormedTxContext>;

    /// Remove expired transactions from the cache and return their hashes.
    fn remove_expired(&mut self, block_index: u64) -> HashSet<TxHash>;

    /// Returns the list of hashes inside `tx_hashes` that are not inside the cache.
    fn missing_hashes(&self, tx_hashes: &BTreeSet<TxHash>) -> Vec<TxHash>;

    /// Check if a transaction, by itself, is safe to append to the current ledger.
    fn validate(&self, tx_hash: &TxHash) -> TxManagerResult<()>;

    /// Combines the transactions that correspond to the given hashes.
    fn combine(&self, tx_hashes: &[TxHash]) -> Vec<TxHash>;

    /// Forms a Block containing the transactions that correspond to the given hashes.
    fn tx_hashes_to_block(
        &self,
        tx_hashes: &[TxHash],
        parent_block: &Block,
    ) -> TxManagerResult<(Block, BlockContents, BlockSignature)>;

    /// Creates a message containing a set of transactions that are encrypted for a peer.
    fn encrypt_for_peer(
        &self,
        tx_hashes: &[TxHash],
        aad: &[u8],
        peer: &PeerSession,
    ) -> TxManagerResult<EnclaveMessage<PeerSession>>;

    /// Get the locally encrypted transaction corresponding to the given hash.
    fn get_encrypted_tx(&self, tx_hash: &TxHash) -> Option<WellFormedEncryptedTx>;

    /// The number of cached entries.
    fn num_entries(&self) -> usize;
}

pub struct TxManagerImpl<E: ConsensusEnclave + Send, UI: UntrustedInterfaces> {
    /// Validate and combine functionality provided by an enclave.
    enclave: E,

    /// Validate and combine functionality provided by the untrusted system.
    untrusted: UI,

    /// Logger.
    logger: Logger,

    /// Well-formed transactions, keyed by hash.
    well_formed_cache: HashMap<TxHash, CacheEntry>,
}

impl<E: ConsensusEnclave + Send, UI: UntrustedInterfaces> TxManagerImpl<E, UI> {
    /// Construct a new TxManager instance.
    pub fn new(enclave: E, untrusted: UI, logger: Logger) -> Self {
        Self {
            enclave,
            untrusted,
            logger,
            well_formed_cache: HashMap::default(),
        }
    }
}

impl<E: ConsensusEnclave + Send, UI: UntrustedInterfaces> TxManager for TxManagerImpl<E, UI> {
    /// Insert a transaction into the cache. The transaction must be well-formed.
    fn insert(&mut self, tx_context: TxContext) -> TxManagerResult<WellFormedTxContext> {
        if let Some(entry) = self.well_formed_cache.get(&tx_context.tx_hash) {
            // The transaction has already been checked and is in the cache.
            return Ok(entry.context.clone());
        }

        // Start timer for metrics.
        let timer = counters::WELL_FORMED_CHECK_TIME.start_timer();

        // The untrusted part of the well-formed check.
        let (current_block_index, membership_proofs) = self.untrusted.well_formed_check(
            &tx_context.highest_indices,
            &tx_context.key_images,
            &tx_context.output_public_keys,
        )?;

        // The enclave part of the well-formed check.
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

        self.well_formed_cache.insert(
            *well_formed_tx_context.tx_hash(),
            CacheEntry {
                encrypted_tx: well_formed_encrypted_tx,
                context: well_formed_tx_context.clone(),
            },
        );
        counters::TX_CACHE_NUM_ENTRIES.set(self.well_formed_cache.len() as i64);
        Ok(well_formed_tx_context)
    }

    /// Remove expired transactions.
    fn remove_expired(&mut self, block_index: u64) -> HashSet<TxHash> {
        let (expired, retained): (HashMap<_, _>, HashMap<_, _>) = self
            .well_formed_cache
            .drain()
            .partition(|(_, entry)| entry.context().tombstone_block() < block_index);

        self.well_formed_cache = retained;

        log::debug!(
            self.logger,
            "Removed {} expired transactions, left with {}",
            expired.len(),
            self.well_formed_cache.len(),
        );

        counters::TX_CACHE_NUM_ENTRIES.set(self.well_formed_cache.len() as i64);

        expired.into_iter().map(|(tx_hash, _)| tx_hash).collect()
    }

    /// Returns the list of hashes inside `tx_hashes` that are not inside the cache.
    fn missing_hashes(&self, tx_hashes: &BTreeSet<TxHash>) -> Vec<TxHash> {
        let mut missing = Vec::new();
        for tx_hash in tx_hashes {
            if !self.well_formed_cache.contains_key(tx_hash) {
                missing.push(*tx_hash);
            }
        }
        missing
    }

    /// Validate the transaction corresponding to the given hash.
    fn validate(&self, tx_hash: &TxHash) -> TxManagerResult<()> {
        match self.well_formed_cache.get(tx_hash) {
            Some(entry) => {
                let _timer = counters::VALIDATE_TX_TIME.start_timer();
                self.untrusted.is_valid(entry.context())?;
                Ok(())
            }
            None => Err(TxManagerError::NotInCache(*tx_hash)),
        }
    }

    /// Combine a list of transactions by their hashes and return the list of hashes of
    /// the combined transaction set.
    ///
    /// This will silently ignore non-existent hashes. Our combine methods are allowed to filter
    /// out transactions, so while non-existent hashes should not be fed into this method, they are
    /// not treated as an error.
    fn combine(&self, tx_hashes: &[TxHash]) -> Vec<TxHash> {
        let mut tx_contexts = Vec::new();

        // Dedup
        let tx_hashes: HashSet<&TxHash> = tx_hashes.iter().clone().collect();
        for tx_hash in tx_hashes {
            if let Some(entry) = self.well_formed_cache.get(&tx_hash) {
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
                let entry = self.well_formed_cache.get(tx_hash).ok_or_else(|| TxManagerError::NotInCache(*tx_hash))?;

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
    fn encrypt_for_peer(
        &self,
        tx_hashes: &[TxHash],
        aad: &[u8],
        peer: &PeerSession,
    ) -> TxManagerResult<EnclaveMessage<PeerSession>> {
        let encrypted_txs: Result<Vec<WellFormedEncryptedTx>, TxManagerError> = {
            tx_hashes
                .iter()
                .map(|tx_hash| {
                    self.well_formed_cache
                        .get(tx_hash)
                        .map(|entry| entry.encrypted_tx().clone())
                        .ok_or_else(|| TxManagerError::NotInCache(*tx_hash))
                })
                .collect()
        };

        Ok(self.enclave.txs_for_peer(&encrypted_txs?, aad, peer)?)
    }

    /// Get the encrypted transaction corresponding to the given hash.
    fn get_encrypted_tx(&self, tx_hash: &TxHash) -> Option<WellFormedEncryptedTx> {
        self.well_formed_cache
            .get(tx_hash)
            .map(|entry| entry.encrypted_tx().clone())
    }

    /// The number of cached entries.
    fn num_entries(&self) -> usize {
        self.well_formed_cache.len()
    }
}

#[cfg(test)]
mod tx_manager_tests {
    use super::*;
    use crate::validators::DefaultTxManagerUntrustedInterfaces;
    use mc_attest_core::{IasNonce, Quote, QuoteNonce, Report, TargetInfo, VerificationReport};
    use mc_attest_enclave_api::{
        ClientAuthRequest, ClientAuthResponse, ClientSession, EnclaveMessage, PeerAuthRequest,
        PeerAuthResponse, PeerSession,
    };
    use mc_common::{logger::test_with_logger, ResponderId};
    use mc_consensus_enclave::{Error as EnclaveError, LocallyEncryptedTx, SealedBlockSigningKey};
    use mc_consensus_enclave_mock::ConsensusServiceMockEnclave;
    use mc_crypto_keys::{Ed25519Public, X25519Public};
    use mc_ledger_db::Ledger;
    use mc_sgx_report_cache_api::{Error as SgxReportError, ReportableEnclave};
    use mc_transaction_core_test_utils::{
        create_ledger, create_transaction, initialize_ledger, AccountKey,
    };
    use rand::{rngs::StdRng, SeedableRng};

    // ConsensusEnclave inherits from ReportableEnclave, so the traits have to be re-typed here.
    // Splitting the traits apart might help because TxManager only uses a few of these functions.
    mock! {
        Enclave {}
        trait ConsensusEnclave {
            fn enclave_init(
                &self,
                self_peer_id: &ResponderId,
                self_client_id: &ResponderId,
                sealed_key: &Option<SealedBlockSigningKey>,
            ) -> Result<(SealedBlockSigningKey, Vec<String>), EnclaveError>;

            fn get_identity(&self) -> Result<X25519Public, EnclaveError>;

            fn get_signer(&self) -> Result<Ed25519Public, EnclaveError>;

            fn client_accept(&self, req: ClientAuthRequest) -> Result<(ClientAuthResponse, ClientSession), EnclaveError>;

            fn client_close(&self, channel_id: ClientSession) -> Result<(), EnclaveError>;

            fn client_discard_message(&self, msg: EnclaveMessage<ClientSession>) -> Result<(), EnclaveError>;

            fn peer_init(&self, peer_id: &ResponderId) -> Result<PeerAuthRequest, EnclaveError>;

            fn peer_accept(&self, req: PeerAuthRequest) -> Result<(PeerAuthResponse, PeerSession), EnclaveError>;

            fn peer_connect(&self, peer_id: &ResponderId, res: PeerAuthResponse) -> Result<PeerSession, EnclaveError>;

            fn peer_close(&self, channel_id: &PeerSession) -> Result<(), EnclaveError>;

            fn client_tx_propose(&self, msg: EnclaveMessage<ClientSession>) -> Result<TxContext, EnclaveError>;

            fn peer_tx_propose(&self, msg: EnclaveMessage<PeerSession>) -> Result<Vec<TxContext>, EnclaveError>;

            fn tx_is_well_formed(
                &self,
                locally_encrypted_tx: LocallyEncryptedTx,
                block_index: u64,
                proofs: Vec<TxOutMembershipProof>,
            ) -> Result<(WellFormedEncryptedTx, WellFormedTxContext), EnclaveError>;

            fn txs_for_peer(
                &self,
                encrypted_txs: &[WellFormedEncryptedTx],
                aad: &[u8],
                peer: &PeerSession,
            ) -> Result<EnclaveMessage<PeerSession>, EnclaveError>;

            fn form_block(
                &self,
                parent_block: &Block,
                txs: &[(WellFormedEncryptedTx, Vec<TxOutMembershipProof>)],
            ) -> Result<(Block, BlockContents, BlockSignature), EnclaveError>;
        }

        trait ReportableEnclave {
            fn new_ereport(&self, qe_info: TargetInfo) -> Result<(Report, QuoteNonce), SgxReportError>;

            fn verify_quote(&self, quote: Quote, qe_report: Report) -> Result<IasNonce, SgxReportError>;

            fn verify_ias_report(&self, ias_report: VerificationReport) -> Result<(), SgxReportError>;

            fn get_ias_report(&self) -> Result<VerificationReport, SgxReportError>;
        }
    }

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
        let mut mock_enclave = MockEnclave::new();

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

        let mut tx_manager = TxManagerImpl::new(mock_enclave, mock_untrusted, logger.clone());
        assert_eq!(tx_manager.well_formed_cache.len(), 0);

        assert!(tx_manager.insert(tx_context.clone()).is_ok());
        assert_eq!(tx_manager.well_formed_cache.len(), 1);
        assert!(tx_manager.well_formed_cache.contains_key(&tx_hash));

        // Re-inserting should also be Ok.
        assert!(tx_manager.insert(tx_context.clone()).is_ok());
        assert_eq!(tx_manager.well_formed_cache.len(), 1);
        assert!(tx_manager.well_formed_cache.contains_key(&tx_hash));
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
        let mock_enclave = MockEnclave::new();

        let mut tx_manager = TxManagerImpl::new(mock_enclave, mock_untrusted, logger.clone());
        assert!(tx_manager.insert(tx_context.clone()).is_err());
        assert_eq!(tx_manager.well_formed_cache.len(), 0);
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
        let mut mock_enclave = MockEnclave::new();
        mock_enclave
            .expect_tx_is_well_formed()
            .times(1)
            .return_const(Err(EnclaveError::Signature));

        let mut tx_manager = TxManagerImpl::new(mock_enclave, mock_untrusted, logger.clone());
        assert!(tx_manager.insert(tx_context.clone()).is_err());
        assert_eq!(tx_manager.well_formed_cache.len(), 0);
    }

    #[test_with_logger]
    // Should remove all transactions that have expired by the given slot.
    fn test_remove_expired(logger: Logger) {
        let mock_untrusted = MockUntrustedInterfaces::new();
        let mock_enclave = MockEnclave::new();
        let mut tx_manager = TxManagerImpl::new(mock_enclave, mock_untrusted, logger.clone());

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
                context: context.clone(),
            };

            tx_manager
                .well_formed_cache
                .insert(context.tx_hash().clone(), cache_entry);
        }

        assert_eq!(tx_manager.well_formed_cache.len(), 14);

        {
            // By block index 10, none have expired.
            let removed = tx_manager.remove_expired(10);
            assert_eq!(removed.len(), 0);
            assert_eq!(tx_manager.well_formed_cache.len(), 14);
        }

        {
            // By block index 15, some have expired.
            let removed = tx_manager.remove_expired(15);
            assert_eq!(removed.len(), 5);
            assert_eq!(tx_manager.well_formed_cache.len(), 9);
        }

        {
            // By block index 24, all have expired.
            let removed = tx_manager.remove_expired(24);
            assert_eq!(removed.len(), 9);
            assert_eq!(tx_manager.well_formed_cache.len(), 0);
        }
    }

    // TODO: missing_hashes

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
        let mock_enclave = MockEnclave::new();

        let mut tx_manager = TxManagerImpl::new(mock_enclave, mock_untrusted, logger.clone());

        // Add this transaction to the cache.
        let cache_entry = CacheEntry {
            encrypted_tx: Default::default(),
            context: Default::default(),
        };
        tx_manager
            .well_formed_cache
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
        let mock_enclave = MockEnclave::new();

        let tx_manager = TxManagerImpl::new(mock_enclave, mock_untrusted, logger.clone());
        // TODO: should be a not in cache error.
        assert!(tx_manager.validate(&tx_context.tx_hash).is_err());
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
        let mock_enclave = MockEnclave::new();

        let mut tx_manager = TxManagerImpl::new(mock_enclave, mock_untrusted, logger.clone());

        // Add this transaction to the cache.
        let cache_entry = CacheEntry {
            encrypted_tx: Default::default(),
            context: Default::default(),
        };
        tx_manager
            .well_formed_cache
            .insert(tx_context.tx_hash.clone(), cache_entry);

        // TODO: should be a transaction validation error.
        assert!(tx_manager.validate(&tx_context.tx_hash).is_err());
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

        let mock_enclave = MockEnclave::new();
        let mut tx_manager = TxManagerImpl::new(mock_enclave, mock_untrusted, logger.clone());

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
                context: context.clone(),
            };

            tx_manager
                .well_formed_cache
                .insert(context.tx_hash().clone(), cache_entry);
        }
        assert_eq!(tx_manager.well_formed_cache.len(), tx_hashes.len());

        // TODO: combine should return a Result.
        assert_eq!(tx_manager.combine(&tx_hashes), expected);
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
            .insert(ConsensusServiceMockEnclave::tx_to_tx_context(
                &client_tx_zero,
            ))
            .unwrap()
            .tx_hash();

        let hash_tx_one = *tx_manager
            .insert(ConsensusServiceMockEnclave::tx_to_tx_context(
                &client_tx_one,
            ))
            .unwrap()
            .tx_hash();

        let hash_tx_two = *tx_manager
            .insert(ConsensusServiceMockEnclave::tx_to_tx_context(
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

    // TODO: encrypt_for_peer

    // TODO: get_encrypted_tx

    // TODO: num_entries
}
