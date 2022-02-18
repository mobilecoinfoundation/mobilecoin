// Copyright (c) 2018-2021 The MobileCoin Foundation

use crate::error::{Error, Result, TxOutMatchingError};
use core::{
    cmp::{max, min},
    convert::TryFrom,
    result::Result as StdResult,
};
use displaydoc::Display;
use mc_account_keys::{AccountKey, PublicAddress, CHANGE_SUBADDRESS_INDEX};
use mc_common::{
    logger::{log, Logger},
    HashMap,
};
use mc_crypto_keys::RistrettoPublic;
use mc_fog_api::{fog_common, ledger};
use mc_fog_ledger_connection::{
    Error as LedgerConnectionError, FogBlockGrpcClient, FogKeyImageGrpcClient,
    KeyImageResultExtension,
};
use mc_fog_types::{
    common,
    view::{FogTxOut, FogTxOutMetadata, TxOutRecord},
    BlockCount,
};
use mc_fog_view_connection::FogViewGrpcClient;
use mc_fog_view_protocol::{FogViewConnection, UserPrivate, UserRngSet};
use mc_transaction_core::{
    get_tx_out_shared_secret,
    onetime_keys::{recover_onetime_private_key, recover_public_subaddress_spend_key},
    ring_signature::KeyImage,
    tx::TxOut,
    BlockIndex,
};
use mc_transaction_std::MemoType;
use mc_util_telemetry::{telemetry_static_key, tracer, Key, TraceContextExt, Tracer};
use std::collections::{BTreeMap, HashSet};

mod memo_handler;
pub use memo_handler::{MemoHandler, MemoHandlerError};

/// Maximum number of inputs in a transaction
const MAX_INPUTS: usize = mc_transaction_core::constants::MAX_INPUTS as usize;

/// Maximum number of key images we will query fog about in a single query
/// This limit may be imposed by various factors:
/// * grpc request size limits (64k / 32 bytes = ~2000)
/// * enclave maximums
/// * anything else?
///
/// Here it is set rather conservatively to avoid overloading a single fog
/// ledger instance.
const MAX_KEY_IMAGES_PER_QUERY: usize = 100;

/// Telemetry: Number of txos returned from query.
const TELEMETRY_NUM_TXOS_KEY: Key = telemetry_static_key!("num-txos");

/// Highest subaddress index we support.
/// If TxOut's are found which belong to us but at an unsupported subaddress
/// index, this will be detected, and a "SubaddressNotFound" error will be
/// returned, and the client will not spend this TxOut, and the balance of this
/// account will not reflect such TxOut's. This has to cover at least the
/// default and change subaddress indexes.
const MAX_SUBADDRESS_INDEX: u64 = CHANGE_SUBADDRESS_INDEX;

/// This object keeps track of all TxOut's that are known to be ours, and which
/// have been spent. It allows to check the current balance of the account, and
/// to find suitable inputs for a new transaction.
///
/// Given network connections to fog view and fog ledger, it can poll for new
/// balance data.
#[derive(Clone)]
pub struct CachedTxData {
    /// The account key we are tracking tx data for.
    account_key: AccountKey,
    /// The UserRngSet. This is state related to conducting the fog-view
    /// protocol, which produces TxOut objects. The rng_set also exposes the
    /// `num_blocks()` value which tells us to what block we are guaranteed to
    /// have all of the user's TxOuts
    rng_set: UserRngSet,
    /// The collection of OwnedTxOuts, keyed by the global index.
    ///
    /// These are TxOuts that we have found, that we know are ours, by view-key
    /// scanning them. These TxOuts come either from fog-view, or from
    /// downloading blocks from untrusted fog-ledger, or possibly another
    /// source. These TxOuts may already have been spent or not, determined
    /// by `status` field.
    owned_tx_outs: BTreeMap<u64, OwnedTxOut>,
    /// Represents how fresh our information about unspent key images is.
    ///
    /// Invariant:
    /// self.key_image_data_completness is less or equal to the block count
    /// number for any owned transaction with NotSpent(block_count) status
    ///
    /// When computing balances, we take the min of this with the rng_set
    /// num_blocks value and try to target that time for computing the
    /// balance, because then we know we have all the transactions up to that
    /// point, and we know that we have complete information about whether
    /// those transactions were spent up to that point.
    key_image_data_completeness: BlockCount,
    /// The latest global txo count that we have heard about.
    /// This is used in the client for sampling mixins.
    ///
    /// TODO: This only takes into account the key image server responses,
    /// but might ideally take into account fog view server responses as well.
    /// However, that would require a change that would conflict with SQL PR.
    latest_global_txo_count: u64,
    /// The latest block version that we have heard about.
    /// This is used by the transaction builder to target the correct block
    /// version.
    latest_block_version: u32,
    /// A memo handler which attempts to decrypt memos and validate them
    memo_handler: MemoHandler,
    /// A pre-calculated map of subaddress public spend key to subaddress index.
    spsk_to_index: HashMap<RistrettoPublic, u64>,
    /// BlockRanges that Fog View has reported as missed, that we have not yet
    /// completely downloaded.
    missed_block_ranges: Vec<common::BlockRange>,
    /// A logger object
    logger: Logger,
}

impl CachedTxData {
    /// Create a new CachedTxData object
    pub fn new(account_key: AccountKey, address_book: Vec<PublicAddress>, logger: Logger) -> Self {
        let spsk_to_index = (0..=MAX_SUBADDRESS_INDEX)
            .map(|index| (*account_key.subaddress(index).spend_public_key(), index))
            .collect();

        Self {
            account_key,
            rng_set: UserRngSet::default(),
            owned_tx_outs: Default::default(),
            key_image_data_completeness: BlockCount::MAX,
            latest_global_txo_count: 0,
            latest_block_version: 1,
            memo_handler: MemoHandler::new(address_book, logger.clone()),
            spsk_to_index,
            missed_block_ranges: Vec::new(),
            logger,
        }
    }

    /// Get the last processed memo
    pub fn get_last_memo(&self) -> &StdResult<Option<MemoType>, MemoHandlerError> {
        self.memo_handler.get_last_memo()
    }

    /// Get the num_blocks value that we can compute balances for.
    /// This is the minimum of all the sources of data that we have from
    /// different servers.
    ///
    /// Note: Missed Blocks are not implemented in the paykit at this revision,
    /// the implementation would have to keep track of if there are any blocks
    /// that fog view told us about that we have to download and scan, and
    /// then we would have to track if we did that. Then this `min`
    /// expression would also take the min of outstanding missed blocks.
    pub fn get_num_blocks(&self) -> BlockCount {
        let missing_block_limit = self
            .missed_block_ranges
            .iter()
            .map(|block_range| BlockCount::from(block_range.start_block + 1))
            .min()
            .unwrap_or(BlockCount::MAX);
        *[
            self.rng_set.get_highest_processed_block_count(),
            self.key_image_data_completeness,
            missing_block_limit,
        ]
        .iter()
        .min()
        .unwrap()
    }

    /// Get the latest_global_txo_count.
    ///
    /// This can be the largest global_txo_count value
    /// that we are aware of, and helps to ensure that when sampling RingCT
    /// mixins, we make requests that are in-bounds.
    pub fn get_global_txo_count(&self) -> u64 {
        self.latest_global_txo_count
    }

    /// Get the latest_block_version
    ///
    /// This is the latest value of block_version known to be in the blockchain.
    /// Note that this may not be a valid block version according to our copy
    /// of mc-transaction-core.
    pub fn get_latest_block_version(&self) -> u32 {
        self.latest_block_version
    }

    /// Helper function: Compute the set of Txos contributing to the balance,
    /// not known to be spent at all.
    /// These can be used creating transaction input sets.
    #[allow(clippy::nonminimal_bool)]
    fn get_unspent_txos(&self) -> Vec<&OwnedTxOut> {
        let num_blocks = self.get_num_blocks();
        assert!(num_blocks <= self.key_image_data_completeness);
        self.owned_tx_outs
            .values()
            .filter(|our_txo|
                our_txo.block_index < u64::from(num_blocks) &&
                    match our_txo.status {
                        KeyImageStatus::SpentAt(_) => false,
                        KeyImageStatus::NotSpent(not_spent_as_of) => {
                            assert!(
                                our_txo.block_index < u64::from(not_spent_as_of),
                                "the not_spent_as_of value should be >= the block index"
                            );
                            assert!(
                                self.key_image_data_completeness <= not_spent_as_of,
                                "invariant violated, key_image_data_completeness is supposed to be the min of all of these values"
                            );
                            true
                        }
            })
            .collect::<Vec<_>>()
    }

    /// Compute our current balance
    ///
    /// Returns (balance, block_count)
    /// where balance is the correct balance when the ledger has exactly
    /// block_count blocks
    #[allow(clippy::nonminimal_bool)]
    pub fn get_balance(&self) -> (u64, BlockCount) {
        let num_blocks = self.get_num_blocks();
        assert!(
            self.key_image_data_completeness >= num_blocks,
            "invariant was violated"
        );
        // Note: This is slightly different from `self.get_unspent_txos().fold`.
        // The difference is that when computing a balance to show the user,
        // we want to compute a balance that was definitely consistent with some
        // specific point in the blockchain.
        //
        // However, this means that sometimes we will show a transaction as contributing
        // to the balance even if we know it is later spent.
        // This can happen if we only have TxOut's up to block 10 but we have key image
        // data up to block 12. Such a transaction is then NOT selected by
        // get_unspent_txos, because we know that building a new transaction
        // using that as an input would fail when we submit.
        //
        // Because of this it is possible that get_balance returns a particular balance,
        // but get_transaction_inputs for that balance subsequently fails with
        // "Insufficient Funds". In this case you should get balance again
        // and try again.
        log::trace!(
            self.logger,
            "computing balance at num_blocks = {}",
            num_blocks
        );
        let balance = self
            .owned_tx_outs
            .values()
            .filter(|our_txo| {
                let result = our_txo.block_index < u64::from(num_blocks)
                    && match our_txo.status {
                        KeyImageStatus::SpentAt(spent_at) => {
                            assert!(
                                our_txo.block_index < spent_at,
                                "txo was spent before it appeared"
                            );
                            // Allow to contribute to the balance if it is spent after the range we are computing
                            // a balance during, but not during that range
                            spent_at >= u64::from(num_blocks)
                        }
                        KeyImageStatus::NotSpent(not_spent_as_of) => {
                            assert!(
                                our_txo.block_index < u64::from(not_spent_as_of),
                                "the not_spent_as_of value should be > the block index"
                            );
                            assert!(
                                self.key_image_data_completeness <= not_spent_as_of,
                                "invariant violated, key_image_data_completeness is supposed to be the min of all of these values"
                            );
                            true
                        }
                    };
                log::trace!(self.logger, "{}: global_index {} block_index {} value {} status {}", result, our_txo.global_index, our_txo.block_index, our_txo.value, our_txo.status);
                result
            })
            .fold(0u64, |running_balance, our_txo| {
                running_balance + our_txo.value
            });
        log::trace!(
            self.logger,
            "Computed balance: {}, num_blocks {}",
            balance,
            num_blocks
        );
        (balance, num_blocks)
    }

    /// Collect transaction inputs for a transaction
    ///
    /// This ONLY picks transactions that are part of the most recent balance
    /// check, and are not known to be spent at any time.
    ///
    /// Arguments:
    /// * An amount (u64), with any fee included.
    /// * A maximum number of inputs to include in this transaction. The number
    ///   should be based on dividing the user-provided fee by the base-fee
    ///   according to the scaling. This argument will be clamped to
    ///   mc_transaction_core::constants::MAX_INPUTS.
    ///
    /// Returns:
    /// * A collection of our unspent transactions that add up to at least this
    ///   value,
    /// * Error::Insufficient if there are insufficient funds
    /// * Error::WalletCompactingNeeded if there are enough funds, but not
    ///   enough large TxOuts to pay for the transaction without going over /the
    ///   maximum inputs limit. This error code includes a recommended size for
    ///   a self-payment that will consume the oldest small transactions (not
    ///   including fee for self-payment). If the oldest small transactions
    ///   don't add up to at least the fee, then this self-payment is not
    ///   actually economical to perform, and you should wait until the fee is
    ///   lower.
    pub fn get_transaction_inputs(
        &self,
        amount: u64,
        max_inputs: usize,
    ) -> Result<Vec<OwnedTxOut>> {
        // All transactions that we could choose to use as an input
        let available = self.get_unspent_txos();

        let tx_values: Vec<_> = available.iter().map(|txo| txo.value).collect();

        let selected = input_selection_heuristic(&tx_values, amount, max_inputs)?;

        Ok(selected
            .into_iter()
            .map(|idx| available[idx].clone())
            .collect())
    }

    /// Consume new TxOutRecords, checking if they belong to us.
    ///
    /// New TxOuts may come from downloading ledger material, or from fog view.
    /// This function confirms that they belong to us ("view key matching")
    /// and then adds them to the cache, sorting the cache and deduplicating it
    /// as well.
    pub fn consume_new_txo_records<Iter: Iterator<Item = TxOutRecord>>(
        &mut self,
        records: Iter,
    ) -> Vec<TxOutMatchingError> {
        let mut errors = Vec::new();

        for record in records {
            match OwnedTxOut::new(record, &self.account_key, &self.spsk_to_index) {
                Ok(otxo) => {
                    // Insert into owned_tx_outs
                    log::trace!(
                        self.logger,
                        "Found new txo: global_index {}, block_index {}, value {}",
                        otxo.global_index,
                        otxo.block_index,
                        otxo.value
                    );
                    let maybe_prev = self.owned_tx_outs.insert(otxo.global_index, otxo.clone());
                    if let Some(prev) = maybe_prev {
                        log::debug!(
                            self.logger,
                            "Saw {}'th tx out a second time",
                            otxo.global_index
                        );
                        if prev.value != otxo.value {
                            log::warn!(self.logger, "Got two different values after view key scanning new and old versions of {}'th tx_out", otxo.global_index);
                        }
                    }
                    // Keep the invariant of key_image_data_completeness working
                    match otxo.status {
                        KeyImageStatus::SpentAt(_) => panic!("should be unreachable"),
                        KeyImageStatus::NotSpent(as_of) => {
                            // It's okay for this number to get smaller, as long as num_blocks
                            // doesn't get smaller
                            self.key_image_data_completeness =
                                min(self.key_image_data_completeness, as_of);
                        }
                    }
                    // Handle memo
                    self.memo_handler
                        .handle_memo(&otxo.tx_out, &self.account_key);
                }
                Err(err) => {
                    errors.push(err);
                }
            }
        }

        errors
    }

    /// Poll for new txo data, given fog view connection object
    ///
    /// This is called when doing a balance check. Returns the number of txos
    /// discovered.
    pub fn poll_fog_for_txos(
        &mut self,
        fog_view_client: &mut FogViewGrpcClient,
        fog_block_client: &mut FogBlockGrpcClient,
    ) -> Result<usize> {
        let old_rng_num_blocks = self.rng_set.get_highest_processed_block_count();
        // Do the fog view protocol, log any errors, and consume any new transactions

        let (mut txo_records, new_missed_block_ranges, errors) =
            fog_view_client.poll(&mut self.rng_set, &UserPrivate::from(&self.account_key));

        log::trace!(
            self.logger,
            "polling fog returned {} txo records",
            txo_records.len()
        );

        log::trace!(
            self.logger,
            "after polling fog view, view protocol num_blocks changed: {} -> {}",
            old_rng_num_blocks,
            self.rng_set.get_highest_processed_block_count()
        );

        for err in errors {
            log::error!(self.logger, "Fog view protocol error: {}", err);
        }

        log::debug!(
            self.logger,
            "Adding {} missed blocks ranges to the missed block ranges queue",
            new_missed_block_ranges.len(),
        );

        for missed_block_range in &new_missed_block_ranges {
            log::trace!(
                self.logger,
                "Missed Block start: {}, end: {}",
                missed_block_range.start_block,
                missed_block_range.end_block,
            );
        }

        self.missed_block_ranges.extend(new_missed_block_ranges);
        let fog_common_block_ranges: Vec<fog_common::BlockRange> = self
            .missed_block_ranges
            .iter()
            .map(fog_common::BlockRange::from)
            .collect::<Vec<_>>();
        match fog_block_client.get_missed_block_ranges(fog_common_block_ranges) {
            Ok(block_response) => {
                let tx_out_records_from_missed_blocks: Vec<TxOutRecord> =
                    self.create_tx_out_records(&block_response);
                txo_records.extend(tx_out_records_from_missed_blocks);
                let updated_missed_block_ranges =
                    CachedTxData::calculate_updated_missed_block_ranges(
                        &self.missed_block_ranges,
                        &block_response.blocks.into_vec(),
                    );
                self.missed_block_ranges = updated_missed_block_ranges;
            }
            Err(err) => {
                log::error!(
                    self.logger,
                    "Fog Ledger retrieving BlockResponse from missed block ranges error: {}",
                    err
                );
            }
        };

        let num_txos = txo_records.len();
        if !txo_records.is_empty() {
            for rec in &txo_records {
                if rec.block_index < u64::from(old_rng_num_blocks) {
                    log::error!(self.logger, "Fog view gave us Txo Records which are from blocks which should not have new Txos from us. This may indicate incorrect balance computations. block_index = {}, previous value of num_blocks = {}, new value of num_blocks = {}", rec.block_index, old_rng_num_blocks, self.rng_set.get_highest_processed_block_count());
                }
            }

            let errors = self.consume_new_txo_records(txo_records.into_iter());
            for err in errors {
                // Note: this could be caused by a griefing attack, but isn't normally expected
                log::warn!(
                    self.logger,
                    "View key scanning failed, fog gave us a TXO that wasn't ours: {}",
                    err
                );
            }
        }
        Ok(num_txos)
    }

    /// Determines the new missed block ranges given the blocks that are
    /// retrieved in the BlockData object.
    fn calculate_updated_missed_block_ranges(
        missed_block_ranges: &[common::BlockRange],
        block_data: &[ledger::BlockData],
    ) -> Vec<common::BlockRange> {
        // Transforms the missed BlockRanges into a set of missed block
        // indices.
        let mut missed_block_indices =
            CachedTxData::create_missed_block_indices(missed_block_ranges);

        for block_datum in block_data {
            missed_block_indices.remove(&block_datum.index);
        }

        // Sort the indices in order to create the fewest amount of block
        // ranges possible in the iteration step below.
        let mut missed_block_indices_sorted: Vec<u64> =
            missed_block_indices.into_iter().collect::<Vec<_>>();
        missed_block_indices_sorted.sort_unstable();

        let mut updated_missed_block_ranges: Vec<common::BlockRange> = Vec::new();

        if missed_block_indices_sorted.is_empty() {
            return updated_missed_block_ranges;
        }

        if missed_block_indices_sorted.len() == 1 {
            let first_block_index = missed_block_indices_sorted[0];
            updated_missed_block_ranges.push(common::BlockRange {
                start_block: first_block_index,
                end_block: first_block_index + 1,
            });
            return updated_missed_block_ranges;
        }

        let mut start_block_index = missed_block_indices_sorted[0];
        let mut i: usize = 0;
        // This loop looks at each adjacent pair in the vector and checks if
        // they differ by more than 1.
        while i + 1 < missed_block_indices_sorted.len() {
            let first_block_index = missed_block_indices_sorted[i];
            let second_block_index = missed_block_indices_sorted[i + 1];
            // We've found a gap in indices, so the current range is complete
            // and should be added.
            if second_block_index - first_block_index > 1 {
                let block_range = common::BlockRange {
                    start_block: start_block_index,
                    end_block: first_block_index + 1,
                };
                updated_missed_block_ranges.push(block_range);
                start_block_index = second_block_index;
            }

            i += 1;
        }

        let last_block_index = missed_block_indices_sorted.last().unwrap();
        let last_block_range = common::BlockRange {
            start_block: start_block_index,
            end_block: last_block_index + 1,
        };

        updated_missed_block_ranges.push(last_block_range);

        updated_missed_block_ranges
    }

    fn create_missed_block_indices(missed_block_ranges: &[common::BlockRange]) -> HashSet<u64> {
        let mut missed_block_indices: HashSet<u64> = HashSet::new();
        for missed_block_range in missed_block_ranges {
            for missed_block_index in missed_block_range.start_block..missed_block_range.end_block {
                missed_block_indices.insert(missed_block_index);
            }
        }

        missed_block_indices
    }

    // Converts a ledger::BlockResponses to a Vec<TxOutRecord>.
    fn create_tx_out_records(&self, block_response: &ledger::BlockResponse) -> Vec<TxOutRecord> {
        let mut tx_out_records: Vec<TxOutRecord> = Vec::new();

        for block_data in &block_response.blocks {
            let number_of_tx_outs_in_block = block_data.outputs.len() as u64;
            let first_tx_out_global_index =
                block_data.global_txo_count - number_of_tx_outs_in_block;

            for (i, external_tx_out) in block_data.outputs.iter().enumerate() {
                match TxOut::try_from(external_tx_out) {
                    Ok(tx_out) => {
                        let fog_tx_out: FogTxOut = FogTxOut::from(&tx_out);

                        let fog_tx_out_metadata: FogTxOutMetadata = FogTxOutMetadata {
                            global_index: first_tx_out_global_index + i as u64,
                            block_index: block_data.index,
                            timestamp: block_data.timestamp,
                        };

                        let tx_out_record: TxOutRecord =
                            TxOutRecord::new(fog_tx_out, fog_tx_out_metadata);
                        // Try to create an OwnedTxOut. If this fails, and it
                        // will fail for the majority of TxOutRecords from these
                        // missed blocks, then view key scanning failed, which
                        // means that the user doesn't own this TxOut. Do this
                        // here before adding it to the returned TxOutRecord
                        // vector to prevent unnecssary logs to be emitted when
                        // the TxOutRecords are consumed.
                        if OwnedTxOut::new(
                            tx_out_record.clone(),
                            &self.account_key,
                            &self.spsk_to_index,
                        )
                        .is_ok()
                        {
                            tx_out_records.push(tx_out_record);
                        }
                    }
                    Err(error) => {
                        log::warn!(
                            self.logger,
                            "TxOut could not be created from external.TxOut: {}",
                            error
                        );
                    }
                }
            }
        }

        tx_out_records
    }

    /// Poll for new key image data, given fog key image connection object
    ///
    /// This is called when doing a balance check
    /// This may be called after poll_fog_for_txos, so that we can ask about any
    /// new key images returned by that call
    pub fn poll_fog_for_key_images(
        &mut self,
        key_image_client: &mut FogKeyImageGrpcClient,
    ) -> Result<()> {
        // Helper: Make a temporary map from key images to global indices for
        // the Txos that we will query about.
        //
        // Note: In a production paykit, you likely should handle the possibility
        // that two different TxOut's have the same KeyImage. We didn't do that here,
        // so there would be some wonky behavior if it happened.
        // TxOut public keys are enforced to be unique by consensus, but it is
        // technically possible that the key image repeats.
        // But it requires that clients are not using real entropy to build Txs,
        // it could only occur maliciously, if at all. (Maybe it is intractable
        // to do this if the public keys are different, without finding a hash
        // collision?)
        //
        // Note that only one of the two TxOuts will actually be spendable if this
        // happens, so it might be a good idea to simply ignore the one of
        // lesser value. Then this would be handled in the
        // consume_new_txo_records function.
        let mut key_image_to_global_index: HashMap<KeyImage, u64> = Default::default();

        let key_images = self
            .owned_tx_outs
            .values()
            .filter_map(|otxo| match otxo.status {
                KeyImageStatus::NotSpent(_) => {
                    let prev = key_image_to_global_index.insert(otxo.key_image, otxo.global_index);
                    if let Some(global_index) = prev {
                        log::warn!(
                            self.logger,
                            "Key image appeared twice among our tx outs: global indices {} and {}",
                            global_index,
                            otxo.global_index
                        );
                        None
                    } else {
                        Some(otxo.key_image)
                    }
                }
                _ => None,
            })
            .collect::<Vec<_>>();

        // Split up key images queries into several requests if there are a lot of key
        // images
        for key_images in key_images.chunks(MAX_KEY_IMAGES_PER_QUERY) {
            match key_image_client.check_key_images(key_images) {
                Ok(response) => {
                    self.latest_global_txo_count =
                        core::cmp::max(self.latest_global_txo_count, response.global_txo_count);
                    // Note: latest_block_version is only increasing on the block chain, since
                    // the network enforces that each block version is at least as large as its
                    // parent. However, the client could talk to ledger servers
                    // that are ahead and then to ledger servers that are
                    // behind. Putting a max here on the client side helps
                    // protect the client from being "poisoned" by talking to a ledger server that
                    // is behind, and having a subsequent Tx fail validation.
                    self.latest_block_version =
                        core::cmp::max(self.latest_block_version, response.latest_block_version);
                    for result in response.results.iter() {
                        if let Some(global_index) = key_image_to_global_index.get(&result.key_image)
                        {
                            let otxo = self
                                .owned_tx_outs
                                .get_mut(global_index)
                                .expect("global index did not actually correspond to a txo");

                            match result.status() {
                                Err(err) => {
                                    log::error!(
                                        self.logger,
                                        "Server-side key image error: {}",
                                        err
                                    );
                                }
                                Ok(Some(spent_at)) => {
                                    match otxo.status {
                                        KeyImageStatus::SpentAt(_) => panic!(
                                            "We were not supposed to ask about already spent txo's"
                                        ),
                                        KeyImageStatus::NotSpent(not_spent_as_of) => {
                                            if spent_at < u64::from(not_spent_as_of) {
                                                log::error!(self.logger, "Inconsistency from server -- we earlier learned that a Txo was not spent as of {}, but now we have learned that it was spent at {}", not_spent_as_of, spent_at);
                                            }
                                        }
                                    };
                                    otxo.status = KeyImageStatus::SpentAt(spent_at);
                                }
                                Ok(None) => {
                                    match &mut otxo.status {
                                        KeyImageStatus::SpentAt(_) => panic!(
                                            "We were not supposed to ask about already spent txo's"
                                        ),
                                        KeyImageStatus::NotSpent(not_spent_as_of) => {
                                            // Update our information about when this Txo was spent
                                            // by If the
                                            // new information older than the old information,
                                            // don't discard the old information
                                            *not_spent_as_of = max(
                                                *not_spent_as_of,
                                                BlockCount::from(response.num_blocks),
                                            );
                                        }
                                    };
                                }
                            };
                        } else {
                            log::error!(
                                self.logger,
                                "Server told us about key images that we didn't ask about"
                            );
                        }
                    }
                }
                Err(err @ LedgerConnectionError::Connection(_, _)) => {
                    log::info!(self.logger, "Check key images failed due to {}", err);
                    return Err(err.into());
                }
                Err(e) => {
                    return Err(Error::LedgerConnection(e));
                }
            };
        }

        // Recompute the key_image_data_completeness value.
        // In principle we could avoid scanning all the transactions again.
        // It's maybe a little simpler to do it in a separate loop at the end.
        //
        // Note: It's okay to have earliest_not_spent_as_of take the value of u64::MAX
        // if there are no unspent txos.
        // We only need to ensure that num_blocks does not go backwards
        self.key_image_data_completeness =
            self.owned_tx_outs
                .values()
                .fold(BlockCount::MAX, |prev_min, otxo| match otxo.status {
                    KeyImageStatus::SpentAt(_) => prev_min,
                    KeyImageStatus::NotSpent(not_spent_as_of) => min(prev_min, not_spent_as_of),
                });

        Ok(())
    }

    /// Poll for txos and then key images, with some appropriate debug logging
    pub fn poll_fog(
        &mut self,
        fog_view_client: &mut FogViewGrpcClient,
        key_image_client: &mut FogKeyImageGrpcClient,
        fog_block_client: &mut FogBlockGrpcClient,
    ) -> Result<()> {
        let old_num_blocks = self.get_num_blocks();
        let old_key_image_data_completeness = self.key_image_data_completeness;
        let old_rng_num_blocks = self.rng_set.get_highest_processed_block_count();

        let tracer = tracer!();

        tracer.in_span("poll_fog_for_txos", |cx| -> Result<()> {
            let num_txos = self.poll_fog_for_txos(fog_view_client, fog_block_client)?;
            cx.span()
                .set_attribute(TELEMETRY_NUM_TXOS_KEY.i64(num_txos as i64));

            Ok(())
        })?;

        tracer.in_span("poll_fog_for_key_images", |_cx| -> Result<()> {
            self.poll_fog_for_key_images(key_image_client)?;
            Ok(())
        })?;

        let new_num_blocks = self.get_num_blocks();

        log::trace!(self.logger, "After polling fog num_blocks changed: {} -> {}, key_image_data_completeness changed: {} -> {}, rng_num_blocks changed: {} -> {}", old_num_blocks, new_num_blocks, old_key_image_data_completeness, self.key_image_data_completeness, old_rng_num_blocks, self.rng_set.get_highest_processed_block_count());
        if old_num_blocks > new_num_blocks {
            log::warn!(self.logger, "After polling fog, num_blocks went backwards! This should not normally happen. num_blocks changed: {} -> {}, key_image_data_completeness changed: {} -> {}, rng_num_blocks changed: {} -> {}", old_num_blocks, new_num_blocks, old_key_image_data_completeness, self.key_image_data_completeness, old_rng_num_blocks, self.rng_set.get_highest_processed_block_count());
        }
        Ok(())
    }

    /// Get debug balance information (to help debug a wrong balance
    /// computation)
    pub fn debug_balance(&mut self) -> String {
        let mut lines = Vec::new();
        lines.push(format!(
            "num_blocks = {}, key_image_data_completeness = {}, rng_set_num_blocks = {}\n",
            self.get_num_blocks(),
            self.key_image_data_completeness,
            self.rng_set.get_highest_processed_block_count()
        ));
        lines.push(format!(
            "num tx_outs = {}, num rngs = {}\n",
            self.owned_tx_outs.len(),
            self.rng_set.get_rngs().len()
        ));
        for owned_tx_out in self.owned_tx_outs.values() {
            lines.push(format!("{:?}\n", owned_tx_out));
        }
        lines.join("\n")
    }
}

/// A status held by a key image -- it can either be spent in a certain block,
/// or known not to be spent as of a certain block.
///
/// The default status, if we have no other information, is that it is not spent
/// as of the block in which it is created. This is because it is impossible to
/// spend a TxOut in the same block that creates it.
#[derive(Copy, Clone, Debug, Display)]
pub enum KeyImageStatus {
    /// SpentAt({0})
    SpentAt(BlockIndex),
    /// NotSpent({0})
    NotSpent(BlockCount),
}

/// A TxOutRecord which has been matched successfully against our account key.
///
/// This is a helper struct for CachedTxData.
/// Several fields like key_image and value are cached so that they do not need
/// to be recomputed.
#[derive(Debug, Clone)]
pub struct OwnedTxOut {
    /// The global index of this tx_out
    pub global_index: u64,
    /// The block in which this tx_out appeared
    pub block_index: BlockIndex,
    /// The tx_out that we recovered from the view server, or from view-key
    /// scanning a missed block.
    pub tx_out: TxOut,
    /// The value of the TxOut, computed when we matched this tx_out
    /// successfully against our account key.
    pub value: u64,
    // The subaddress index this tx_out was sent to.
    pub subaddress_index: u64,
    /// The key image that we computed when matching this tx_out against our
    /// account key.
    pub key_image: KeyImage,
    /// The status of the key image, which we learn by querying key image
    /// server. This is either `spent_at(index)` or
    /// `not_spent_as_of(count)`.
    pub status: KeyImageStatus,
}

impl OwnedTxOut {
    /// Try to decrypt a TxOutRecord by view-key matching it, producing an
    /// OwnedTxOut or an error
    pub fn new(
        rec: TxOutRecord,
        account_key: &AccountKey,
        spsk_to_index: &HashMap<RistrettoPublic, u64>,
    ) -> StdResult<Self, TxOutMatchingError> {
        // Reconstitute FogTxOut from the "flattened" data in TxOutRecord
        let fog_tx_out = rec.get_fog_tx_out()?;

        // Reconstute TxOut from FogTxOut and our view private key
        let tx_out = fog_tx_out.try_recover_tx_out(account_key.view_private_key())?;

        // This is view key scanning part, getting the value fails if view-key scanning
        // fails
        let decompressed_tx_pub = RistrettoPublic::try_from(&tx_out.public_key)?;
        let shared_secret =
            get_tx_out_shared_secret(account_key.view_private_key(), &decompressed_tx_pub);
        let (value, _blinding) = tx_out.amount.get_value(&shared_secret)?;

        // Calculate the subaddress spend public key for tx_out.
        let tx_out_target_key = RistrettoPublic::try_from(&tx_out.target_key)?;
        let tx_public_key = RistrettoPublic::try_from(&tx_out.public_key)?;

        let subaddress_spk = recover_public_subaddress_spend_key(
            account_key.view_private_key(),
            &tx_out_target_key,
            &tx_public_key,
        );
        let subaddress_index = spsk_to_index
            .get(&subaddress_spk)
            .ok_or(TxOutMatchingError::SubaddressNotFound)?;

        // This is the part where we compute the key image from the one-time private key
        let onetime_private_key = recover_onetime_private_key(
            &decompressed_tx_pub,
            account_key.view_private_key(),
            &account_key.subaddress_spend_private(*subaddress_index),
        );
        let key_image = KeyImage::from(&onetime_private_key);

        // The default status of a key image is that it isn't spent as of the block
        // in which it appeared
        let status = KeyImageStatus::NotSpent(BlockCount::from(rec.block_index + 1));

        Ok(Self {
            global_index: rec.tx_out_global_index,
            block_index: rec.block_index,
            tx_out,
            key_image,
            value,
            subaddress_index: *subaddress_index,
            status,
        })
    }
}

/// Implementation detail: Input selection heuristic
///
/// The input selection heuristic chooses which of our Txos to use as inputs to
/// meet a target amount, based on their relative ages and values.
///
/// There are several competing concerns:
/// - There is a network-wide maximum number of inputs to a transaction, so
///   possibly not all inputs can be used
/// - The number of inputs may depend on the fee and fee-scaling rule
/// - In cryptonote, older inputs are generally harder to conceal than younger
///   inputs, so we usually want to prefer to spend our older inputs until they
///   get even older
/// - We want to opportunistically compact the user's wallet over time so that
///   wallet-compaction transactions are not usually needed.
/// - If wallet-compaction transactions are needed, we offer guidance as to what
///   is the best way to compact the wallet.
///
/// As a heuristic, we attempt to spend the oldest tx outs that we can
/// while still achieving the required amount and not exceeding the max inputs
/// limit. We stop once we hit the required amount.
///
/// Note that another paykit may not use the same heuristic, there
/// are many valid solutions.
///
/// Arguments:
/// * tx_values: an array of u64 transaction values
/// * amount: the target amount, including the fee
/// * max_inputs: the maximum number of inputs we can use, which the caller may
///   compute based on the fee This is clamped to
///   mc_transaction_core::constants::MAX_INPUTS
///
/// Returns:
/// * The indices to use to build the transaction
/// * Or, an error indicating that there are insufficient funds or that wallet
///   compaction is needed
fn input_selection_heuristic(
    tx_values: impl AsRef<[u64]>,
    amount: u64,
    max_inputs: usize,
) -> StdResult<Vec<usize>, InputSelectionError> {
    let tx_values = tx_values.as_ref();
    let max_inputs = min(max_inputs, MAX_INPUTS);

    // Check if we have enough funds considering all transactions
    if tx_values.iter().sum::<u64>() < amount {
        return Err(InputSelectionError::InsufficientFunds);
    }

    // We know we have enough funds now, but we also have to take into account
    // the MAX_INPUTS limit. We would also like to favor spending the earlier
    // transactions if at all possible, because we want the wallet to naturally
    // consolidate itself so that the user doesn't typically have to pay fees to
    // compact it.
    //
    // We use a dynamic programming approach:
    //
    // We want to find for every i, the most valuable collection of j transactions
    // from among the i+1 ... of the available list, for values of j from 0 to
    // MAX_INPUTS. Once we have this list, we can then consider the earliest
    // transactions first, and consider if it is possible to include them while
    // achieving the amount.
    //
    // dp_table[i][j] := maximum sum of not more than j transaction values chosen
    // from available[i..]
    //
    // The table can be filled iteratively by working with largest values of i
    // first, and smallest values of j first. For convenience, the matrix has an
    // extra row and column which are initialized to zeroes and never changed,
    // to simplify boundary conditions.
    //
    // This is a linear-time algorithm if MAX_INPUTS is constant.
    let dp_table = {
        // For convenience, we have available.len() + 1 rows instead, and the last row
        // is zeros, which reduces case analysis.
        let mut dp_table: Vec<[u64; MAX_INPUTS + 1]> =
            vec![Default::default(); tx_values.len() + 1];

        // for every row from 0..available.len()
        for i in (0..tx_values.len()).rev() {
            // The best value for 0 transactions is 0, so we iterate from j to MAX_INPUTS
            // and set dp_table[i][j+1].
            for j in 0..MAX_INPUTS {
                // The best value for j+1 transactions chosen from available[i..] is obtained
                // either
                // * use the i'th transaction and j transactions from available[(i+1)..], or
                // * don't use the i'th transaction, and use j+1 transactions from
                //   available[(i+1)..].
                //
                // The former term is tx_values[i] + dp_table[i+1][j],
                // The latter term is dp_table[i+1][j+1],
                let val: u64 = max(tx_values[i] + dp_table[i + 1][j], dp_table[i + 1][j + 1]);
                dp_table[i][j + 1] = val;
            }
        }

        dp_table
    };

    if dp_table[0][max_inputs] < amount {
        // We have enough money but not without exceeding max_inputs
        // Recommend to make the largest self-payment possible to extend our range the
        // next time we try. If user passed less than 3 inputs, then choose at
        // least three.
        return Err(InputSelectionError::WalletCompactingNeeded(
            dp_table[0][max(max_inputs, 3)],
        ));
    }

    // Now greedily take the earliest transactions that we can while still achieving
    // target amount. result is the collection that we will return, and value is
    // its running value
    let mut result = Vec::with_capacity(max_inputs);
    let mut value = 0u64;
    for idx in 0..tx_values.len() {
        // If no remaining amount is needed, we're done
        if value >= amount {
            // Correctness:
            // If this assert fails, then in the previous pass, the assert
            // `result.len() < max_inputs` would have had to fail.
            assert!(result.len() <= max_inputs, "invariant was violated");
            return Ok(result);
        }

        // Correctness:
        // In the first pass through the loop where result.len == max_inputs,
        // we must have pushed a value into `result` in the previous pass,
        // when previously result.len() was max_inputs - 1.
        // This means that the test below passed.
        // But dp_table[_][0] == 0, so we actually had
        // value + available[idx].value >= amount
        //
        // Since we also added available[idx].value to value,
        // this means that in the next pass through the loop, value >= amount,
        // so we exited, rather than reaching this assert.
        assert!(result.len() < max_inputs, "invariant was violated");

        // Include this txo in the result, unless including it will
        // cause us not to hit the amount before running out of input slots.
        if value + tx_values[idx] + dp_table[idx + 1][max_inputs - result.len() - 1] >= amount {
            result.push(idx);
            value += tx_values[idx];
        }
    }

    // Correctness:
    // If this assert fails, then earlier assert `result.len() < max_inputs` would
    // have had to fail.
    assert!(result.len() <= max_inputs, "invariant was violated");
    // Correctness:
    // If this assert fails, then the test `dp_table[0][max_inputs] < amount` would
    // have failed, and we would have exited with "wallet compacting needed".
    // This is the point of the dp algorithm.
    assert!(value >= amount, "invariant was violated");
    Ok(result)
}

/// InputSelection error is an error that can go wrong when selecting inputs.
/// This error implements Eq and PartialEq unlike fog_sample_paykit::Error,
/// which makes it work with assert_eq! for tests.
/// fog_sample_paykit::Error cannot do this because grpcio and
/// mc_transaction_std Error's don't implement Eq.
#[derive(Debug, Display, Eq, PartialEq)]
enum InputSelectionError {
    /// Insufficient Funds
    InsufficientFunds,
    /// Wallet Compacting is needed, recommend self-payment in the amount {0}
    WalletCompactingNeeded(u64),
}

impl From<InputSelectionError> for Error {
    fn from(src: InputSelectionError) -> Error {
        match src {
            InputSelectionError::InsufficientFunds => Error::InsufficientFunds,
            InputSelectionError::WalletCompactingNeeded(val) => Error::WalletCompactingNeeded(val),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn input_selection_heuristic_3_inputs() {
        let inputs: Vec<u64> = vec![1, 1, 1, 4, 9, 1, 1, 1, 19, 2, 1];

        assert_eq!(input_selection_heuristic(&inputs, 1, 3), Ok(vec![0]));
        assert_eq!(input_selection_heuristic(&inputs, 2, 3), Ok(vec![0, 1]));
        assert_eq!(input_selection_heuristic(&inputs, 3, 3), Ok(vec![0, 1, 2]));
        assert_eq!(input_selection_heuristic(&inputs, 4, 3), Ok(vec![0, 1, 3]));
        assert_eq!(input_selection_heuristic(&inputs, 5, 3), Ok(vec![0, 1, 3]));
        assert_eq!(input_selection_heuristic(&inputs, 6, 3), Ok(vec![0, 1, 3]));
        assert_eq!(input_selection_heuristic(&inputs, 7, 3), Ok(vec![0, 1, 4]));
        assert_eq!(input_selection_heuristic(&inputs, 8, 3), Ok(vec![0, 1, 4]));
        assert_eq!(input_selection_heuristic(&inputs, 9, 3), Ok(vec![0, 1, 4]));
        assert_eq!(input_selection_heuristic(&inputs, 10, 3), Ok(vec![0, 1, 4]));
        assert_eq!(input_selection_heuristic(&inputs, 11, 3), Ok(vec![0, 1, 4]));
        assert_eq!(input_selection_heuristic(&inputs, 12, 3), Ok(vec![0, 1, 8]));
        assert_eq!(input_selection_heuristic(&inputs, 13, 3), Ok(vec![0, 1, 8]));
        assert_eq!(input_selection_heuristic(&inputs, 14, 3), Ok(vec![0, 1, 8]));
        assert_eq!(input_selection_heuristic(&inputs, 15, 3), Ok(vec![0, 1, 8]));
        assert_eq!(input_selection_heuristic(&inputs, 16, 3), Ok(vec![0, 1, 8]));
        assert_eq!(input_selection_heuristic(&inputs, 17, 3), Ok(vec![0, 1, 8]));
        assert_eq!(input_selection_heuristic(&inputs, 18, 3), Ok(vec![0, 1, 8]));
        assert_eq!(input_selection_heuristic(&inputs, 19, 3), Ok(vec![0, 1, 8]));
        assert_eq!(input_selection_heuristic(&inputs, 20, 3), Ok(vec![0, 1, 8]));
        assert_eq!(input_selection_heuristic(&inputs, 21, 3), Ok(vec![0, 1, 8]));
        assert_eq!(input_selection_heuristic(&inputs, 22, 3), Ok(vec![0, 3, 8]));
        assert_eq!(input_selection_heuristic(&inputs, 23, 3), Ok(vec![0, 3, 8]));
        assert_eq!(input_selection_heuristic(&inputs, 24, 3), Ok(vec![0, 3, 8]));
        assert_eq!(input_selection_heuristic(&inputs, 25, 3), Ok(vec![0, 4, 8]));
        assert_eq!(input_selection_heuristic(&inputs, 26, 3), Ok(vec![0, 4, 8]));
        assert_eq!(input_selection_heuristic(&inputs, 27, 3), Ok(vec![0, 4, 8]));
        assert_eq!(input_selection_heuristic(&inputs, 28, 3), Ok(vec![0, 4, 8]));
        assert_eq!(input_selection_heuristic(&inputs, 29, 3), Ok(vec![0, 4, 8]));
        assert_eq!(input_selection_heuristic(&inputs, 30, 3), Ok(vec![3, 4, 8]));
        assert_eq!(input_selection_heuristic(&inputs, 31, 3), Ok(vec![3, 4, 8]));
        assert_eq!(input_selection_heuristic(&inputs, 32, 3), Ok(vec![3, 4, 8]));
        assert_eq!(
            input_selection_heuristic(&inputs, 33, 3),
            Err(InputSelectionError::WalletCompactingNeeded(32))
        );
        assert_eq!(
            input_selection_heuristic(&inputs, 34, 3),
            Err(InputSelectionError::WalletCompactingNeeded(32))
        );
        assert_eq!(
            input_selection_heuristic(&inputs, 40, 3),
            Err(InputSelectionError::WalletCompactingNeeded(32))
        );
        assert_eq!(
            input_selection_heuristic(&inputs, 41, 3),
            Err(InputSelectionError::WalletCompactingNeeded(32))
        );
        assert_eq!(
            input_selection_heuristic(&inputs, 42, 3),
            Err(InputSelectionError::InsufficientFunds)
        );
    }

    #[test]
    fn input_selection_heuristic_4_inputs() {
        let inputs: Vec<u64> = vec![1, 1, 1, 4, 9, 1, 1, 1, 19, 2, 1];
        assert_eq!(input_selection_heuristic(&inputs, 1, 4), Ok(vec![0]));
        assert_eq!(input_selection_heuristic(&inputs, 2, 4), Ok(vec![0, 1]));
        assert_eq!(input_selection_heuristic(&inputs, 3, 4), Ok(vec![0, 1, 2]));
        assert_eq!(
            input_selection_heuristic(&inputs, 4, 4),
            Ok(vec![0, 1, 2, 3])
        );
        assert_eq!(
            input_selection_heuristic(&inputs, 5, 4),
            Ok(vec![0, 1, 2, 3])
        );
        assert_eq!(
            input_selection_heuristic(&inputs, 6, 4),
            Ok(vec![0, 1, 2, 3])
        );
        assert_eq!(
            input_selection_heuristic(&inputs, 7, 4),
            Ok(vec![0, 1, 2, 3])
        );
        assert_eq!(
            input_selection_heuristic(&inputs, 8, 4),
            Ok(vec![0, 1, 2, 4])
        );
        assert_eq!(
            input_selection_heuristic(&inputs, 9, 4),
            Ok(vec![0, 1, 2, 4])
        );
        assert_eq!(
            input_selection_heuristic(&inputs, 10, 4),
            Ok(vec![0, 1, 2, 4])
        );
        assert_eq!(
            input_selection_heuristic(&inputs, 11, 4),
            Ok(vec![0, 1, 2, 4])
        );
        assert_eq!(
            input_selection_heuristic(&inputs, 12, 4),
            Ok(vec![0, 1, 2, 4])
        );
        assert_eq!(
            input_selection_heuristic(&inputs, 13, 4),
            Ok(vec![0, 1, 2, 8])
        );
        assert_eq!(
            input_selection_heuristic(&inputs, 14, 4),
            Ok(vec![0, 1, 2, 8])
        );
        assert_eq!(
            input_selection_heuristic(&inputs, 15, 4),
            Ok(vec![0, 1, 2, 8])
        );
        assert_eq!(
            input_selection_heuristic(&inputs, 16, 4),
            Ok(vec![0, 1, 2, 8])
        );
        assert_eq!(
            input_selection_heuristic(&inputs, 17, 4),
            Ok(vec![0, 1, 2, 8])
        );
        assert_eq!(
            input_selection_heuristic(&inputs, 18, 4),
            Ok(vec![0, 1, 2, 8])
        );
        assert_eq!(
            input_selection_heuristic(&inputs, 19, 4),
            Ok(vec![0, 1, 2, 8])
        );
        assert_eq!(
            input_selection_heuristic(&inputs, 20, 4),
            Ok(vec![0, 1, 2, 8])
        );
        assert_eq!(
            input_selection_heuristic(&inputs, 21, 4),
            Ok(vec![0, 1, 2, 8])
        );
        assert_eq!(
            input_selection_heuristic(&inputs, 22, 4),
            Ok(vec![0, 1, 2, 8])
        );
        assert_eq!(
            input_selection_heuristic(&inputs, 23, 4),
            Ok(vec![0, 1, 3, 8])
        );
        assert_eq!(
            input_selection_heuristic(&inputs, 24, 4),
            Ok(vec![0, 1, 3, 8])
        );
        assert_eq!(
            input_selection_heuristic(&inputs, 25, 4),
            Ok(vec![0, 1, 3, 8])
        );
        assert_eq!(
            input_selection_heuristic(&inputs, 26, 4),
            Ok(vec![0, 1, 4, 8])
        );
        assert_eq!(
            input_selection_heuristic(&inputs, 27, 4),
            Ok(vec![0, 1, 4, 8])
        );
        assert_eq!(
            input_selection_heuristic(&inputs, 28, 4),
            Ok(vec![0, 1, 4, 8])
        );
        assert_eq!(
            input_selection_heuristic(&inputs, 29, 4),
            Ok(vec![0, 1, 4, 8])
        );
        assert_eq!(
            input_selection_heuristic(&inputs, 30, 4),
            Ok(vec![0, 1, 4, 8])
        );
        assert_eq!(
            input_selection_heuristic(&inputs, 31, 4),
            Ok(vec![0, 3, 4, 8])
        );
        assert_eq!(
            input_selection_heuristic(&inputs, 32, 4),
            Ok(vec![0, 3, 4, 8])
        );
        assert_eq!(
            input_selection_heuristic(&inputs, 33, 4),
            Ok(vec![0, 3, 4, 8])
        );
        assert_eq!(
            input_selection_heuristic(&inputs, 34, 4),
            Ok(vec![3, 4, 8, 9])
        );
        assert_eq!(
            input_selection_heuristic(&inputs, 35, 4),
            Err(InputSelectionError::WalletCompactingNeeded(34))
        );
        assert_eq!(
            input_selection_heuristic(&inputs, 36, 4),
            Err(InputSelectionError::WalletCompactingNeeded(34))
        );
        assert_eq!(
            input_selection_heuristic(&inputs, 37, 4),
            Err(InputSelectionError::WalletCompactingNeeded(34))
        );
        assert_eq!(
            input_selection_heuristic(&inputs, 40, 4),
            Err(InputSelectionError::WalletCompactingNeeded(34))
        );
        assert_eq!(
            input_selection_heuristic(&inputs, 41, 4),
            Err(InputSelectionError::WalletCompactingNeeded(34))
        );
        assert_eq!(
            input_selection_heuristic(&inputs, 42, 4),
            Err(InputSelectionError::InsufficientFunds)
        );
    }

    #[test]
    fn calculate_updated_missed_block_ranges_empty_missed_block_ranges_returns_empty_vector() {
        let empty_missed_block_ranges = vec![];
        let empty_block_data = vec![];

        let updated_missed_block_ranges = CachedTxData::calculate_updated_missed_block_ranges(
            &empty_missed_block_ranges,
            &empty_block_data,
        );

        assert!(updated_missed_block_ranges.is_empty())
    }

    #[test]
    fn calculate_updated_missed_block_ranges_all_block_indices_retrieved_returns_empty_vector() {
        let first_index: u64 = 0;
        let final_index: u64 = 4;
        let missed_block_range = common::BlockRange::new(first_index, final_index + 1);
        let missed_block_ranges = vec![missed_block_range];

        let mut block_data = vec![];
        for index in first_index..final_index + 1 {
            let mut block_datum = ledger::BlockData::new();
            block_datum.index = index;
            block_data.push(block_datum);
        }

        let updated_missed_block_ranges =
            CachedTxData::calculate_updated_missed_block_ranges(&missed_block_ranges, &block_data);

        assert!(updated_missed_block_ranges.is_empty())
    }

    #[test]
    fn calculate_updated_missed_block_ranges_one_missed_index_returns_one_block_range() {
        let first_index: u64 = 134;
        let final_index: u64 = 134;
        let missed_block_range = common::BlockRange::new(first_index, final_index + 1);
        let missed_block_ranges = vec![missed_block_range];

        let block_data = vec![];

        let updated_missed_block_ranges =
            CachedTxData::calculate_updated_missed_block_ranges(&missed_block_ranges, &block_data);

        assert_eq!(updated_missed_block_ranges.len(), 1);
        let updated_missed_block_range = &updated_missed_block_ranges[0];
        assert_eq!(updated_missed_block_range.start_block, first_index);
        assert_eq!(updated_missed_block_range.end_block, final_index + 1);
    }

    #[test]
    fn calculate_updated_missed_block_ranges_all_block_indices_not_retrieved_returns_one_block_range(
    ) {
        let first_index: u64 = 0;
        let final_index: u64 = 4;
        let missed_block_range = common::BlockRange::new(first_index, final_index + 1);
        let missed_block_ranges = vec![missed_block_range];
        let block_data = vec![];

        let updated_missed_block_ranges =
            CachedTxData::calculate_updated_missed_block_ranges(&missed_block_ranges, &block_data);

        assert_eq!(updated_missed_block_ranges.len(), 1);
        let updated_missed_block_range = &updated_missed_block_ranges[0];
        assert_eq!(updated_missed_block_range.start_block, 0);
        assert_eq!(updated_missed_block_range.end_block, 5);
    }

    #[test]
    fn calculate_updated_missed_block_ranges_does_not_cover_all_indices_returns_block_range_with_indices(
    ) {
        let first_index: u64 = 2;
        let final_index: u64 = 6;
        let missed_block_range = common::BlockRange::new(first_index, final_index + 1);
        let missed_block_ranges = vec![missed_block_range];

        let mut block_data = vec![];
        for index in first_index..final_index - 1 {
            let mut block_datum = ledger::BlockData::new();
            block_datum.index = index;
            block_data.push(block_datum);
        }

        let updated_missed_block_ranges =
            CachedTxData::calculate_updated_missed_block_ranges(&missed_block_ranges, &block_data);

        assert_eq!(updated_missed_block_ranges.len(), 1);
        let updated_missed_block_range = &updated_missed_block_ranges[0];
        assert_eq!(updated_missed_block_range.start_block, final_index - 1);
        assert_eq!(updated_missed_block_range.end_block, final_index + 1);
    }

    #[test]
    fn calculate_updated_missed_block_ranges_multiple_indices_returns_block_range_with_indices() {
        let indices = vec![(5, 11), (34, 40), (1, 3)];
        let mut missed_block_ranges = Vec::new();

        for (start_block, end_block) in indices.iter() {
            let missed_block_range = common::BlockRange::new(*start_block, *end_block);
            missed_block_ranges.push(missed_block_range);
        }

        let retrieved_block_indices = vec![5, 6, 7, 8, 35, 38, 39, 40, 1, 2];
        let mut block_data = vec![];
        for index in retrieved_block_indices {
            let mut block_datum = ledger::BlockData::new();
            block_datum.index = index;
            block_data.push(block_datum);
        }

        let updated_missed_block_ranges =
            CachedTxData::calculate_updated_missed_block_ranges(&missed_block_ranges, &block_data);

        assert_eq!(updated_missed_block_ranges.len(), 3);

        let first_updated_missed_block_range = &updated_missed_block_ranges[0];
        assert_eq!(first_updated_missed_block_range.start_block, 9);
        assert_eq!(first_updated_missed_block_range.end_block, 11);

        let second_updated_missed_block_range = &updated_missed_block_ranges[1];
        assert_eq!(second_updated_missed_block_range.start_block, 34);
        assert_eq!(second_updated_missed_block_range.end_block, 35);

        let third_updated_missed_block_range = &updated_missed_block_ranges[2];
        assert_eq!(third_updated_missed_block_range.start_block, 36);
        assert_eq!(third_updated_missed_block_range.end_block, 38);
    }

    #[test]
    fn calculate_updated_missed_block_ranges_two_disjoint_indices_not_retrieved_returns_two_block_ranges(
    ) {
        let first_index: u64 = 0;
        let final_index: u64 = 10;
        let missed_block_range = common::BlockRange::new(first_index, final_index + 1);
        let missed_block_ranges = vec![missed_block_range];
        let mut block_data = vec![];

        let first_unretrieved_index = 3;
        let second_unretrieved_index = 7;

        for index in first_index..final_index + 1 {
            if index == first_unretrieved_index || index == second_unretrieved_index {
                continue;
            }
            let mut block_datum = ledger::BlockData::new();
            block_datum.index = index;
            block_data.push(block_datum);
        }

        let updated_missed_block_ranges =
            CachedTxData::calculate_updated_missed_block_ranges(&missed_block_ranges, &block_data);

        assert_eq!(updated_missed_block_ranges.len(), 2);

        let first_updated_missed_block_range = &updated_missed_block_ranges[0];
        assert_eq!(first_updated_missed_block_range.start_block, 3);
        assert_eq!(first_updated_missed_block_range.end_block, 4);

        let second_updated_missed_block_range = &updated_missed_block_ranges[1];
        assert_eq!(second_updated_missed_block_range.start_block, 7);
        assert_eq!(second_updated_missed_block_range.end_block, 8);
    }
}
