// Copyright (c) 2018-2023 The MobileCoin Foundation

//! LedgerSyncService provides a mechanism for synchronizing a local ledger with
//! the network. It uses consensus nodes as the source of truth for blocks, and
//! then a pluggable [`TransactionsFetcher`] object for fetching actual
//! transaction data.

use crate::{
    BlockMetadataProvider, LedgerSync, LedgerSyncError, NetworkState, PassThroughMetadataProvider,
    TransactionsFetcher,
};
use mc_blockchain_types::{compute_block_id, Block, BlockData, BlockID, BlockIndex};
use mc_common::{
    logger::{log, Logger},
    trace_time, ResponderId,
};
use mc_connection::{
    BlockchainConnection, Connection, ConnectionManager, RetryableBlockchainConnection,
};
use mc_ledger_db::Ledger;
use mc_transaction_core::ring_signature::KeyImage;
use mc_util_telemetry::{
    block_span_builder, telemetry_static_key, tracer, Context, Key, Span, TraceContextExt, Tracer,
};
use mc_util_uri::ConnectionUri;
use retry::delay::Fibonacci;
use std::{
    cmp::min,
    collections::{BTreeMap, HashMap, HashSet},
    sync::{Arc, Condvar, Mutex},
    thread,
    time::{Duration, Instant, SystemTime},
};

/// Maximal amount to allow for getting block and transaction data.
const DEFAULT_GET_BLOCKS_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_GET_BLOCK_CONTENTS_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximal amount of concurrent get_block_contents calls to allow.
const MAX_CONCURRENT_GET_BLOCK_CONTENTS_CALLS: usize = 50;

/// Telemetry metadata: number of blocks appended to the local ledger.
const TELEMETRY_NUM_BLOCKS_APPENDED: Key = telemetry_static_key!("num-blocks-appended");

const MAX_SLEEP_INTERVAL: Duration = Duration::from_secs(60);

pub struct LedgerSyncService<
    L: Ledger,
    BC: BlockchainConnection + 'static,
    TF: TransactionsFetcher + 'static,
    BMP: BlockMetadataProvider = PassThroughMetadataProvider,
> {
    ledger: L,
    manager: ConnectionManager<BC>,
    transactions_fetcher: Arc<TF>,
    /// Timeout for network requests.
    get_blocks_timeout: Duration,
    get_block_contents_timeout: Duration,
    metadata_provider: BMP,
    logger: Logger,
}

impl<L: Ledger, BC: BlockchainConnection + 'static, TF: TransactionsFetcher + 'static>
    LedgerSyncService<L, BC, TF>
{
    /// Creates a new LdegerSyncService.
    pub fn new(
        ledger: L,
        manager: ConnectionManager<BC>,
        transactions_fetcher: TF,
        logger: Logger,
    ) -> Self {
        Self::with_metadata_provider(
            PassThroughMetadataProvider {},
            ledger,
            manager,
            transactions_fetcher,
            logger,
        )
    }
}

impl<
        L: Ledger,
        BC: BlockchainConnection + 'static,
        TF: TransactionsFetcher + 'static,
        BMP: BlockMetadataProvider,
    > LedgerSyncService<L, BC, TF, BMP>
{
    pub fn with_metadata_provider(
        metadata_provider: BMP,
        ledger: L,
        manager: ConnectionManager<BC>,
        transactions_fetcher: TF,
        logger: Logger,
    ) -> Self {
        assert!(
            ledger
                .num_blocks()
                .expect("Failed getting number of blocks in ledger")
                > 0
        );

        Self {
            ledger,
            manager,
            transactions_fetcher: Arc::new(transactions_fetcher),
            metadata_provider,
            get_blocks_timeout: DEFAULT_GET_BLOCKS_TIMEOUT,
            get_block_contents_timeout: DEFAULT_GET_BLOCK_CONTENTS_TIMEOUT,
            logger,
        }
    }

    /// Identifies Blocks that are potentially safe to append to the local
    /// ledger.
    ///
    /// A block is "potentially safe" if it is part of a chain of blocks rooted
    /// on the highest block in the local ledger, and if a sufficient set of
    /// peers agree on the block. In order to be fully "safe", we must
    /// verify the block hashes from the full set of transactions
    /// corresponding to that block.
    ///
    /// This method is potentially costly: it queries blocks from all peers. It
    /// should not be performed unless it has been determined that the local
    /// ledger is out of sync.
    ///
    /// # Arguments
    /// * `network_state` - Current state of the network, used to determine if
    ///   we're behind.
    /// * `limit` - number of blocks that will be queried and evaluated.
    ///
    /// Returns a "sufficient" set of peers to sync from, the BlockIndex of the
    /// last block to sync, and consecutive "potentially safe" Blocks.
    fn get_potentially_safe_blocks(
        &mut self,
        network_state: &impl NetworkState,
        limit: u32,
    ) -> Option<(Vec<ResponderId>, BlockIndex, Vec<Block>)> {
        trace_time!(self.logger, "get_potentially_safe_blocks");

        let next_block_index: BlockIndex = self.ledger.num_blocks().unwrap();
        let last_block = self.ledger.get_block(next_block_index - 1).unwrap();
        log::debug!(
            self.logger,
            "Getting blocks [{}, {}) from peers",
            next_block_index,
            next_block_index + limit as BlockIndex
        );

        let node_to_blocks: HashMap<ResponderId, Vec<Block>> = get_blocks(
            &self.manager,
            last_block,
            limit,
            self.get_blocks_timeout,
            &self.logger,
        );

        for (responder_id, blocks) in &node_to_blocks {
            log::debug!(
                self.logger,
                "Received {} blocks from node {}",
                blocks.len(),
                responder_id
            );
        }

        let grouping: BTreeMap<BlockIndex, HashMap<BlockID, HashSet<ResponderId>>> =
            group_by_block(&node_to_blocks);

        // If sync_target is Some, it indicates that the local ledger should attempt to
        // be synced from the given nodes, up to and including the Block with
        // the given BlockID in BlockIndex.
        let mut sync_target: Option<(BlockIndex, BlockID, Vec<ResponderId>)> = None;

        // Iterate over groupings, starting with the highest block index.
        // Starting with the highest block index is a greedy strategy, and should be
        // more efficient in the normal case where all nodes agree, or when a
        // new ledger must download a large number of blocks.
        'outer: for (block_index, block_id_to_nodes) in grouping.iter().rev() {
            for (block_id, responder_ids) in block_id_to_nodes.iter() {
                if network_state.is_blocking_and_quorum(responder_ids) {
                    // It should be possible to sync with these nodes up to `block_id` at
                    // `block_index`.
                    //
                    // Note: in the event of a network fork, there may be multiple distinct sets of
                    // nodes that could be chosen here. Arbitrarily, we take the first such set of
                    // nodes.
                    let node_vec: Vec<ResponderId> = responder_ids.iter().cloned().collect();
                    sync_target = Some((*block_index, block_id.clone(), node_vec));
                    break 'outer;
                }
            }
        }

        // Return None if no blocks are available.
        let (sync_to_block_index, _block_id, responder_ids) = sync_target?;

        // All nodes in `responder_ids` should have the same blocks up to
        // `sync_to_block_index`. Copy those blocks from one of the nodes.
        if let Some(responder_id) = responder_ids.first() {
            if let Some(blocks) = node_to_blocks.get(responder_id) {
                let blocks_to_sync: Vec<Block> = blocks
                    .iter()
                    .filter(|block| block.index <= sync_to_block_index)
                    .cloned()
                    .collect();
                Some((responder_ids.clone(), sync_to_block_index, blocks_to_sync))
            } else {
                log::error!(
                    self.logger,
                    "No blocks for peer {:?} in sync_target?",
                    responder_id
                );
                None
            }
        } else {
            log::error!(self.logger, "responder_ids in sync_target is empty?!");
            None
        }
    }

    /// Append safe blocks to the local ledger.
    fn append_safe_blocks(&mut self, blocks: &[BlockData]) -> Result<(), LedgerSyncError> {
        log::info!(
            self.logger,
            "Appending {} blocks to ledger, which currently has {} blocks",
            blocks.len(),
            self.ledger
                .num_blocks()
                .expect("failed getting number of blocks"),
        );
        mc_common::trace_time!(self.logger, "Appended {} blocks to ledger", blocks.len());

        for block_data in blocks {
            let append_block_start = SystemTime::now();
            let metadata = self.metadata_provider.get_metadata(block_data);
            // TODO: Propagate downloaded block signature if the metadata/AVR can verify it.
            self.ledger.append_block(
                block_data.block(),
                block_data.contents(),
                None,
                metadata.as_ref(),
            )?;
            let append_block_end = SystemTime::now();

            // HACK: `append_block` reports a span but does not tie it to a specific
            // block-derived trace ID. This is useful, since this allows the
            // repeated append_block calls to be grouped under the parent
            // span of append_safe_blocks.
            // However, we also want to know when various services have appended a specific
            // block as part of the block-level trace, so to work around that we
            // are recording another span that is purposefully not tied
            // to the current tracing context, but instead uses a fresh context so that it
            // could be tied to the block trace.
            {
                // This is what detaches us from the parent context created by the caller of
                // `append_safe_blocks`.
                let _ctx = Context::new().attach();
                let tracer = tracer!();
                let block_index = block_data.block().index;
                let mut span = block_span_builder(&tracer, "append_block", block_index)
                    .with_start_time(append_block_start)
                    .with_end_time(append_block_end)
                    .start(&tracer);
                span.end_with_timestamp(append_block_end);
            }
        }

        Ok(())
    }
}

impl<
        NS: NetworkState + Send + Sync + 'static,
        L: Ledger,
        BC: BlockchainConnection + 'static,
        TF: TransactionsFetcher + 'static,
        BMP: BlockMetadataProvider,
    > LedgerSync<NS> for LedgerSyncService<L, BC, TF, BMP>
{
    /// Returns true if the local ledger is behind the network's consensus view
    /// of the ledger.
    fn is_behind(&self, network_state: &NS) -> bool {
        let num_blocks: u64 = self
            .ledger
            .num_blocks()
            .expect("Failed getting number of blocks in ledger");

        if num_blocks == 0 {
            true
        } else {
            network_state.is_behind(num_blocks - 1)
        }
    }

    /// Attempts to synchronize the local ledger with the consensus view of the
    /// network.
    ///
    /// 1. Get blocks from peers.
    /// 2. Identify blocks that are “potentially safe”, and the peers who have
    ///    them.
    /// 3. Download transactions for “potentially safe” blocks.
    /// 4. Identify “safe” blocks (and their transactions). Each block
    ///    satisfies:
    ///      * A sufficient set of peers have externalized the block,
    ///      * The block is part of a blockchain of safe blocks, rooted at the
    ///        highest block in the local node’s ledger,
    ///      * The block’s ID agrees with the merkle hash of its transactions,
    ///      * None of the key images in the block have appeared before.
    /// 5. Append safe blocks to the ledger.
    ///
    /// # Arguments
    /// * `network_state` - Current state of the network, used to determine if
    ///   we're behind.
    /// * `limit` - Maximum number of blocks to add to the ledger.
    fn attempt_ledger_sync(
        &mut self,
        network_state: &NS,
        limit: u32,
    ) -> Result<(), LedgerSyncError> {
        trace_time!(self.logger, "attempt_ledger_sync");
        tracer!().in_span("attempt_ledger_sync", |_cx| {
            let (responder_ids, _, potentially_safe_blocks) = self
                .get_potentially_safe_blocks(network_state, limit)
                .ok_or(LedgerSyncError::NoSafeBlocks)?;

            if potentially_safe_blocks.is_empty() {
                return Err(LedgerSyncError::EmptyBlockVec);
            }

            let num_potentially_safe_blocks = potentially_safe_blocks.len();

            // Get transactions.
            let block_index_to_opt_data = get_block_contents(
                self.transactions_fetcher.clone(),
                &responder_ids,
                &potentially_safe_blocks,
                self.get_block_contents_timeout,
                &self.logger,
            );

            let mut blocks: Vec<BlockData> = Vec::new();
            {
                // Populate `blocks_with_transactions`. This just returns all (block,
                // transactions) until it reaches a None.
                let mut blocks_by_index = block_index_to_opt_data
                    .into_iter()
                    .filter_map(|(block_index, opt_block_data)| {
                        // Use Option::map() to extract the data, while propagating None's.
                        opt_block_data.map(|block_data| (block_index, block_data))
                    })
                    .collect::<BTreeMap<_, _>>();

                // Sort and deduplicate safe blocks by index.
                let safe_blocks_by_index: BTreeMap<BlockIndex, Block> = potentially_safe_blocks
                    .into_iter()
                    .map(|block| (block.index, block))
                    .collect();

                // Join blocks and transactions, allowing for the possibility that transactions
                // may not be available for some blocks due to failed network requests for
                // transactions.
                blocks.reserve(safe_blocks_by_index.len());
                for (block_index, block) in safe_blocks_by_index {
                    if let Some(block_data) = blocks_by_index.remove(&block_index) {
                        blocks.push(block_data);
                    } else {
                        log::error!(self.logger, "No transactions for block {:?}", block);
                        break;
                    }
                }
            }

            if blocks.is_empty() {
                log::error!(
                    self.logger,
                    "Identified {} safe blocks but was unable to get block contents.",
                    num_potentially_safe_blocks,
                );
                return Err(LedgerSyncError::NoTransactionData);
            }

            // Process safe blocks.
            log::trace!(
                &self.logger,
                "Identifying safe blocks out of {} blocks",
                blocks.len()
            );
            let safe_blocks = identify_safe_blocks(&self.ledger, &blocks, &self.logger);

            log::trace!(
                &self.logger,
                "Identified {} safe blocks out of {} blocks",
                safe_blocks.len(),
                blocks.len()
            );

            {
                tracer!().in_span("append_safe_blocks", |cx| {
                    cx.span()
                        .set_attribute(TELEMETRY_NUM_BLOCKS_APPENDED.i64(safe_blocks.len() as i64));
                    self.append_safe_blocks(&safe_blocks)
                })?;
            }

            Ok(())
        })
    }
}

/// Gets a list of Blocks that could potentially be appended after `block` from
/// each peer.
///
/// # Arguments
/// * `manager` - Manager instance.
/// * `append_after_block` - The block we're trying to append to.
/// * `limit` - Maximal number of blocks to fetch.
/// * `timeout` - Overall request timeout.
///
/// Peers are queried concurrently, and any successful responses collected
/// before a timeout occurs are returned.
fn get_blocks<BC: BlockchainConnection + 'static>(
    manager: &ConnectionManager<BC>,
    append_after_block: Block,
    limit: u32,
    timeout: Duration,
    logger: &Logger,
) -> HashMap<ResponderId, Vec<Block>> {
    trace_time!(logger, "get_blocks");

    // Query each peer in a separate worker thread. A separate thread performs a
    // timeout. Any responses obtained before the timeout are returned.
    type ResultsMap = HashMap<ResponderId, Vec<Block>>;
    let results_and_condvar = Arc::new((Mutex::new(ResultsMap::default()), Condvar::new()));

    let append_after_block = Arc::new(append_after_block);

    for conn in manager.conns().into_iter() {
        let thread_results_and_condvar = results_and_condvar.clone();
        let thread_append_after_block = append_after_block.clone();
        let logger = logger.clone();
        thread::Builder::new()
            .name(format!("GetBlocks:{conn}"))
            .spawn(move || {
                let (lock, condvar) = &*thread_results_and_condvar;

                // Perform call to get the blocks from the peer. Blocks are later verified by `identify_safe_blocks`.
                let start = thread_append_after_block.index + 1;
                let end = start + u64::from(limit);
                let mut blocks_result = Vec::new();
                let responder_id = match conn.uri().responder_id() {
                    Ok(responder_id) => responder_id,
                    Err(e) => {
                        log::warn!(
                            logger,
                            "Could not insert blocks from connection with {:?} due to NodeID conversion failure {:?}",
                            conn.uri().to_string(),
                            e
                        );
                        panic!("No node id");
                    }
                };
                match conn
                    .fetch_blocks(start..end, Fibonacci::from_millis(10).take(5))
                    .map_err(LedgerSyncError::Consensus)
                    .and_then(|blocks| verify_block_ids(blocks, &thread_append_after_block))
                {
                    Ok(mut blocks) => {
                        log::debug!(logger, "Received {} blocks from {}", blocks.len(), conn);
                        blocks_result.append(&mut blocks);
                    }
                    Err(err) => {
                        log::warn!(logger, "Failed to retrieve blocks from {}: {:?}", conn, err);
                    }
                };

                // The waiting code below (`wait_timeout_until` call) will block until
                // either a timeout occurs or number of results equal to number of connections. As
                // such, we must ensure to always insert a result for each connection, even if we
                // failed at getting blocks from that connection. Such failure, in the code above,
                // would be represented as an empty vector and would be filtered out before
                // returning from this function.
                let mut results = lock.lock().expect("mutex poisoned");
                results.insert(responder_id, blocks_result);
                condvar.notify_one();
            })
            .expect("Failed spawning GetBlocks thread!");
    }

    // Wait until either we get all results, or a timeout happens.
    let (lock, condvar) = &*results_and_condvar;
    let (worker_results, _wait_timeout_result) = condvar
        .wait_timeout_while(lock.lock().unwrap(), timeout, |ref mut results| {
            results.len() != manager.len()
        })
        .expect("waiting on condvar failed");

    // Filter out results with no blocks
    worker_results
        .clone()
        .into_iter()
        .filter(|(_responder_id, blocks)| !blocks.is_empty())
        .collect()
}

fn verify_block_ids(
    blocks: Vec<Block>,
    append_after_block: &Block,
) -> Result<Vec<Block>, LedgerSyncError> {
    let mut prev_block = append_after_block;

    for block in blocks.iter() {
        if block.parent_id != prev_block.id {
            return Err(LedgerSyncError::InvalidBlockId);
        }

        if !block.is_block_id_valid() {
            return Err(LedgerSyncError::InvalidBlockId);
        }

        prev_block = block;
    }

    Ok(blocks)
}

/// For each block index, group nodes according to the block they externalized
/// (if any).
///
/// # Arguments
/// * `node_to_blocks` - mapping from ResponderId to a consecutive list of
///   Blocks externalized by that node.
fn group_by_block(
    node_to_blocks: &HashMap<ResponderId, Vec<Block>>,
) -> BTreeMap<BlockIndex, HashMap<BlockID, HashSet<ResponderId>>> {
    // For each block index, this partitions nodes according to the contents of the
    // block they externalized. A BTreeMap allows efficient iteration of entries
    // sorted by block index, in addition to the usual HashMap functionality.
    //
    // The BlockID is the hash of the entire block contents, which is why we can
    // group by it. Block IDs are verified before they are handed to this
    // function.
    let mut block_index_to_grouping: BTreeMap<BlockIndex, HashMap<BlockID, HashSet<ResponderId>>> =
        BTreeMap::new();

    for (responder_id, blocks) in node_to_blocks {
        for block in blocks.iter() {
            let block_id_to_group: &mut HashMap<BlockID, HashSet<ResponderId>> =
                block_index_to_grouping.entry(block.index).or_default();

            let group: &mut HashSet<ResponderId> =
                block_id_to_group.entry(block.id.clone()).or_default();

            group.insert(responder_id.clone());
        }
    }
    block_index_to_grouping
}

/// Gets all transactions for each block in a list of Blocks.
///
/// It is assumed that all peers have identical Block IDs for the given blocks,
/// so it is sufficient to obtain each transaction from a single peer.
/// Specifically, this is expected to be used in conjunction with
/// `group_by_block` which identifies peers who have identical blocks.
///
/// # Arguments
/// * `transactions_fetcher` - The mechanism used for fetching transaction
///   contents for a given block.
/// * `safe_responder_ids` - ResponderIds that have been identified as agreeing
///   with eachother on the `blocks` we want to fetch.
/// * `blocks` - List of blocks to fetch transactions for.
/// * `timeout` - Overall request timeout.
///
/// Peers are queried concurrently. Currently, this method will run indefinitely
/// until all transactions have been retrieved.
fn get_block_contents<TF: TransactionsFetcher + 'static>(
    transactions_fetcher: Arc<TF>,
    safe_responder_ids: &[ResponderId],
    blocks: &[Block],
    timeout: Duration,
    logger: &Logger,
) -> BTreeMap<BlockIndex, Option<BlockData>> {
    trace_time!(logger, "get_block_contents");

    enum Msg {
        ProcessBlock {
            // Block we are trying to fetch transactions for.
            block: Block,

            // How many attempts have we made so far (this is used for calculating retry delays).
            num_attempts: u64,
        },
        Stop,
    }

    // The channel is going to hold the list of pending blocks we still need to get
    // transactions for.
    let (sender, receiver) = crossbeam_channel::bounded(blocks.len());
    for block in blocks.iter().cloned() {
        sender
            .send(Msg::ProcessBlock {
                block,
                num_attempts: 0,
            })
            .expect("failed sending to channel");
    }

    let results_and_condvar = Arc::new((Mutex::new(BTreeMap::new()), Condvar::new()));
    let deadline = Instant::now() + timeout;

    // Spawn worker threads.
    let mut thread_handles = Vec::new();

    let num_workers = std::cmp::min(MAX_CONCURRENT_GET_BLOCK_CONTENTS_CALLS, blocks.len());
    for worker_num in 0..num_workers {
        let thread_results_and_condvar = results_and_condvar.clone();
        let thread_sender = sender.clone();
        let thread_receiver = receiver.clone();
        let thread_logger = logger.clone();
        let thread_transactions_fetcher = transactions_fetcher.clone();
        let thread_safe_responder_ids = safe_responder_ids.to_owned();

        let thread_handle = thread::Builder::new()
            .name(format!("LedgerSync::GetTxs:{worker_num}"))
            .spawn(move || {
                let (lock, condvar) = &*thread_results_and_condvar;

                for msg in thread_receiver.iter() {
                    match msg {
                        Msg::ProcessBlock {
                            block,
                            num_attempts,
                        } => {
                            // Check for timeout.
                            if Instant::now() > deadline {
                                log::error!(
                                    thread_logger,
                                    "Worker {} giving up on block {}: deadline exceeded",
                                    worker_num,
                                    block.index,
                                );

                                let mut results = lock.lock().expect("mutex poisoned");
                                results.insert(block.index, None);
                                condvar.notify_one();
                                continue;
                            }

                            // Try and get contents of this block.
                            log::trace!(
                                thread_logger,
                                "Worker {} attempting block {}",
                                worker_num,
                                block.index
                            );

                            let results = thread_transactions_fetcher
                                .get_block_data(thread_safe_responder_ids.as_slice(), &block)
                                .map_err(LedgerSyncError::from)
                                .and_then(|block_data| {
                                    if block != *block_data.block() {
                                        log::debug!(
                                            thread_logger,
                                            "Block mismatch: {:02x?} vs {:02x?}",
                                            block,
                                            block_data.block(),
                                        );
                                        return Err(LedgerSyncError::TransactionsAndBlockMismatch);
                                    }

                                    let contents_hash = block_data.contents().hash();
                                    if contents_hash != block.contents_hash {
                                        log::debug!(
                                            thread_logger,
                                            "Contents and block mismatch: {:02x?} vs {:02x?}",
                                            contents_hash,
                                            block.contents_hash,
                                        );
                                        Err(LedgerSyncError::TransactionsAndBlockMismatch)
                                    } else {
                                        Ok(block_data)
                                    }
                                });

                            match results {
                                Ok(block_data) => {
                                    // Log
                                    log::trace!(
                                        thread_logger,
                                        "Worker {} got contents for block {}",
                                        worker_num,
                                        block.index
                                    );

                                    // passing the actual block and not just a block index.
                                    let mut results = lock.lock().expect("mutex poisoned");
                                    let old_result = results.insert(block.index, Some(block_data));

                                    // We should encounter each block index only once.
                                    assert!(
                                        old_result.is_none(),
                                        "Duplicate block data for index {}",
                                        block.index
                                    );

                                    // Signal condition variable to check if maybe we're done.
                                    condvar.notify_one();
                                }

                                Err(err) => {
                                    // Log
                                    log::info!(
                                        thread_logger,
                                        "Worker {} failed getting transactions for block {}: {}",
                                        worker_num,
                                        block.index,
                                        err
                                    );

                                    // Sleep, with a linearly increasing delay. This prevents
                                    // endless retries
                                    // as long as the deadline is not exceeded.
                                    let attempts = Duration::from_secs(num_attempts + 1);
                                    thread::sleep(min(attempts, MAX_SLEEP_INTERVAL));

                                    // Put back to queue for a retry
                                    thread_sender
                                        .send(Msg::ProcessBlock {
                                            block,
                                            num_attempts: num_attempts + 1,
                                        })
                                        .expect("failed sending to channel");
                                }
                            }
                        }
                        Msg::Stop => {
                            return;
                        }
                    }
                }
            })
            .expect("Failed spawning GetBlocks thread!");

        thread_handles.push(thread_handle);
    }

    // Wait until we get all results, or we timeout. Note that timeout checking is
    // handled inside the worker threads.
    log::trace!(logger, "Waiting on {} results", blocks.len());
    let (lock, condvar) = &*results_and_condvar;
    let results = condvar
        .wait_while(lock.lock().unwrap(), |ref mut results| {
            results.len() != blocks.len()
        })
        .expect("waiting on condvar failed");

    // Sanity - we will only get here when results.len() == blocks.len(), which only
    // happens when everything in the queue was proceesed.
    assert!(receiver.is_empty());

    // Tell all threads to stop.
    for _ in 0..blocks.len() {
        sender.send(Msg::Stop).expect("failed sending to channel");
    }

    // Wait for all threads to stop
    log::trace!(logger, "Joining worker threads...");
    for thread_handle in thread_handles.into_iter() {
        if let Err(err) = thread_handle.join() {
            log::error!(
                logger,
                "Failed joining get_block_contents worker thread: {:?}",
                err
            );
        }
    }

    // Return results.
    results.clone()
}

/// Identify a sequence of blocks that are safe to append to the local node's
/// ledger.
///
/// A "safe" block satisfies:
/// 1. A sufficient set of peers have externalized the block (aka "potentially
///    safe"),
/// 2. The block is part of a chain of safe blocks, rooted at the highest block
///    in the local node’s ledger,
/// 3. The block’s ID agrees with the merkle hash of its transactions,
/// 4. None of the key images in the block have appeared before.
///
/// # Arguments
/// * `ledger` - The local node's ledger.
/// * `blocks` - A sequence of Blocks with their associated transactions, in
///   increasing order of block number.
pub fn identify_safe_blocks<L: Ledger>(
    ledger: &L,
    blocks: &[BlockData],
    logger: &Logger,
) -> Vec<BlockData> {
    // The highest block externalized by the local node.
    let highest_local_block = ledger
        .get_latest_block()
        .expect("Failed getting highest local block");

    let mut safe_blocks: Vec<BlockData> = Vec::with_capacity(blocks.len());
    let mut last_safe_block: Block = highest_local_block;

    // KeyImages used by new, safe blocks.
    // They are not yet in the ledger, but may not be used again.
    let mut additional_key_images: HashSet<KeyImage> = HashSet::default();

    'block_loop: for block_data in blocks {
        let block = block_data.block();
        // The block must be part of a chain of safe blocks.
        if block.parent_id != last_safe_block.id {
            log::error!(
                logger,
                "The block's parent_id must be the last safe block in the chain.\nblock: {:?}, expected parent_id: {:?}",
                block,
                last_safe_block.id
            );
            break;
        }

        // The block's ID must agree with the merkle hash of its transactions.
        let block_contents = block_data.contents();
        let derived_block_id = compute_block_id(
            block.version,
            &block.parent_id,
            block.index,
            block.cumulative_txo_count,
            &block.root_element,
            &block_contents.hash(),
        );
        if block.id != derived_block_id {
            log::error!(
                logger,
                "Block ids do not match. Block: {:?}, derived block ID: {:?}",
                block,
                derived_block_id
            );
            break;
        }

        // No key images in the block may have been previously seen.
        for key_image in &block_contents.key_images {
            // Check if the key image is already in the local ledger.
            match ledger.contains_key_image(key_image) {
                Ok(contains_key_image) => {
                    if contains_key_image {
                        log::error!(
                            logger,
                            "Previously used KeyImage {:?} in block {:?}",
                            key_image,
                            block
                        );
                        break 'block_loop;
                    }
                }
                Err(e) => {
                    log::error!(
                        logger,
                        "contains_key_image failed on {:?}: {:?}",
                        key_image,
                        e
                    );
                    break 'block_loop;
                }
            }

            // Check if the key image was used by another potentially safe block.
            if additional_key_images.contains(key_image) {
                log::error!(
                    logger,
                    "Previously used KeyImage {:?} in block {:?}",
                    key_image,
                    block
                );
                break 'block_loop;
            }
            additional_key_images.insert(*key_image);
        }

        // This block is safe.
        last_safe_block = block.clone();
        safe_blocks.push(block_data.clone());
    }

    safe_blocks
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{test_utils::MockTransactionsFetcher, SCPNetworkState};
    use mc_blockchain_test_utils::make_block_metadata;
    use mc_blockchain_types::BlockMetadata;
    use mc_common::{logger::test_with_logger, NodeID};
    use mc_consensus_scp::{ballot::Ballot, msg::*, *};
    use mc_ledger_db::test_utils::{get_mock_ledger, get_test_ledger_blocks};
    use mc_peers_test_utils::{test_node_id, test_peer_uri, MockPeerConnection};
    use mc_util_test_helper::get_seeded_rng;

    #[test_with_logger]
    // A node with the trivial quorum set should never be "behind".
    fn test_is_behind_trivial_quorum(logger: Logger) {
        // Local node with trivial quorum set.
        let local_node_id = test_node_id(11);
        let quorum_set = QuorumSet::empty();
        let network_state = SCPNetworkState::new(local_node_id, quorum_set);
        let ledger = get_mock_ledger(25);
        let conn_manager = ConnectionManager::<MockPeerConnection>::new(vec![], logger.clone());
        let transactions_fetcher = MockTransactionsFetcher::new(ledger.clone());
        let sync_service =
            LedgerSyncService::new(ledger, conn_manager, transactions_fetcher, logger);

        assert!(!sync_service.is_behind(&network_state));
    }

    // A blocking set of peers on a higher slot isn't enough to consider this node
    // "behind".
    #[test_with_logger]
    fn test_is_behind(logger: Logger) {
        let node_a = (test_node_id(22), QuorumSet::empty());
        let node_b = (test_node_id(33), QuorumSet::empty());

        let local_node_id = test_node_id(11);
        let local_quorum_set: QuorumSet<ResponderId> = QuorumSet::new_with_node_ids(
            2,
            vec![node_a.0.clone().responder_id, node_b.0.clone().responder_id],
        );
        let local_slot_index: SlotIndex = 5;

        let mut network_state = SCPNetworkState::new(local_node_id.responder_id, local_quorum_set);
        let ledger = get_mock_ledger(local_slot_index as usize);
        let conn_manager = ConnectionManager::<MockPeerConnection>::new(vec![], logger.clone());
        let transactions_fetcher = MockTransactionsFetcher::new(ledger.clone());
        let sync_service =
            LedgerSyncService::new(ledger, conn_manager, transactions_fetcher, logger);

        // Node A has externalized a higher slot.
        // The set {Node A} is blocking, but {Node A} \union {local node} is not a
        // quorum.
        {
            let slot_index: SlotIndex = 8;
            network_state.push(Msg::new(
                node_a.0.responder_id.clone(),
                node_a.1,
                slot_index,
                Topic::Externalize(ExternalizePayload {
                    C: Ballot::new(100, &["foo"]),
                    HN: 4,
                }),
            ));
        }

        assert!(!sync_service.is_behind(&network_state));

        // Now Node B also externalizes a higher slot.
        // The set {Node A, Node B} is blocking, and {Node A, Node B} \union {local
        // node} is a quorum.
        {
            let slot_index: SlotIndex = 9;
            network_state.push(Msg::new(
                node_b.0.responder_id.clone(),
                node_b.1,
                slot_index,
                Topic::Externalize(ExternalizePayload {
                    C: Ballot::new(100, &["foo"]),
                    HN: 4,
                }),
            ));
        }

        assert!(sync_service.is_behind(&network_state));
    }

    #[test_with_logger]
    // `get_blocks` should gracefully handle peers who don't respond before the
    // timeout.
    fn test_get_blocks_with_timeout(logger: Logger) {
        let local_node_id = test_node_id(123);

        let timeout = Duration::from_millis(1000);
        let ledger = get_mock_ledger(25);
        let first_block = ledger.get_block(0).unwrap();

        // This peer returns a value before the timeout.
        let fast_peer =
            MockPeerConnection::new(test_peer_uri(1), local_node_id.clone(), ledger.clone(), 50);

        // This peer does nt return a response before the timeout.
        let slow_peer =
            MockPeerConnection::new(test_peer_uri(2), local_node_id, get_mock_ledger(0), 10000);

        let conn_manager = ConnectionManager::new(vec![fast_peer, slow_peer], logger.clone());

        let limit: u32 = 10; // Number of blocks to get.
        let responses = get_blocks(&conn_manager, first_block.clone(), limit, timeout, &logger);

        // Only node 1 should be in the responses.
        assert!(responses.contains_key(&test_peer_uri(1).responder_id().unwrap()));
        assert!(!responses.contains_key(&test_peer_uri(2).responder_id().unwrap()));

        // `responses` should contain Vec<Block> from fast_peer.
        let blocks_received = &responses[&test_peer_uri(1).responder_id().unwrap()];
        assert_eq!(blocks_received.len(), limit as usize);

        let first = first_block.index + 1;
        let last = first + limit as u64;
        for (i, block_index) in (first..last).enumerate() {
            assert_eq!(blocks_received[i], ledger.get_block(block_index).unwrap(),);
        }
    }

    #[test_with_logger]
    // `get_block_contents` should get correct transactions for the indicated
    // blocks.
    fn test_get_block_contents(logger: Logger) {
        let local_node_id = test_node_id(123);

        let num_blocks = 25;
        let mock_ledger = get_mock_ledger(num_blocks);

        let conn_manager = ConnectionManager::new(
            vec![
                MockPeerConnection::new(
                    test_peer_uri(1),
                    local_node_id.clone(),
                    mock_ledger.clone(),
                    10,
                ),
                MockPeerConnection::new(
                    test_peer_uri(2),
                    local_node_id.clone(),
                    mock_ledger.clone(),
                    10,
                ),
                MockPeerConnection::new(test_peer_uri(3), local_node_id, mock_ledger.clone(), 10),
            ],
            logger.clone(),
        );

        let transactions_fetcher = Arc::new(MockTransactionsFetcher::new(mock_ledger.clone()));

        let responder_ids: Vec<ResponderId> = conn_manager.responder_ids();

        let blocks: Vec<Block> = (0..10)
            .map(|idx| mock_ledger.get_block(idx).unwrap())
            .collect();

        let block_index_to_opt_data = get_block_contents(
            transactions_fetcher,
            responder_ids.as_slice(),
            &blocks,
            Duration::from_secs(1),
            &logger,
        );

        log::trace!(
            logger,
            "get_block_contents returned: {:?}",
            block_index_to_opt_data
        );

        // The correct number of results should be returned.
        assert_eq!(block_index_to_opt_data.len(), 10);

        for (block_index, data_opt) in block_index_to_opt_data {
            let block_data = data_opt.expect("all blocks should be populated");
            let expected = mock_ledger
                .get_block_data(block_index)
                .expect("block data should be in ledger");
            // The transactions should be correct for each block.
            assert_eq!(block_data, expected);
        }
    }

    #[test_with_logger]
    // `get_block_contents` should verify the transactions returned matched the
    // block requested.
    fn test_get_block_contents_validates_block(logger: Logger) {
        let local_node_id = test_node_id(123);

        let num_blocks = 25;
        let mock_ledger = get_mock_ledger(num_blocks);

        let conn_manager = ConnectionManager::new(
            vec![
                MockPeerConnection::new(
                    test_peer_uri(1),
                    local_node_id.clone(),
                    mock_ledger.clone(),
                    10,
                ),
                MockPeerConnection::new(
                    test_peer_uri(2),
                    local_node_id.clone(),
                    mock_ledger.clone(),
                    10,
                ),
                MockPeerConnection::new(test_peer_uri(3), local_node_id, mock_ledger.clone(), 10),
            ],
            logger.clone(),
        );

        let transactions_fetcher = Arc::new(MockTransactionsFetcher::new(mock_ledger.clone()));

        let responder_ids: Vec<ResponderId> = conn_manager.responder_ids();

        let mut blocks: Vec<Block> = (0..10)
            .map(|idx| mock_ledger.get_block(idx).unwrap())
            .collect();

        // Alter the contents hash of one of the blocks. This should cause
        // `get_block_contents` to error. Block index 3 is chosen arbitrarily.
        const BAD_BLOCK_INDEX: u64 = 3;

        blocks[BAD_BLOCK_INDEX as usize].contents_hash.0[0] =
            !blocks[BAD_BLOCK_INDEX as usize].contents_hash.0[0];

        let block_index_to_opt_data = get_block_contents(
            transactions_fetcher,
            responder_ids.as_slice(),
            &blocks,
            Duration::from_secs(1),
            &logger,
        );

        log::trace!(
            logger,
            "get_block_contents returned: {:?}",
            block_index_to_opt_data
        );

        // The correct number of results should be returned.
        assert_eq!(block_index_to_opt_data.len(), 10);

        for (block_index, data_opt) in block_index_to_opt_data {
            match data_opt {
                Some(block_data) => {
                    assert_ne!(block_index, BAD_BLOCK_INDEX);

                    let expected = mock_ledger
                        .get_block_data(block_index)
                        .expect("block data should be in ledger");
                    // The block data should be correct for each block.
                    assert_eq!(block_data, expected);
                }
                None => {
                    assert_eq!(block_index, BAD_BLOCK_INDEX);
                }
            }
        }
    }

    #[test]
    #[ignore]
    fn test_get_block_contents_for_nonexistent_blocks() {
        unimplemented!();
    }

    #[test_with_logger]
    // All "potentially safe" blocks should be returned.
    fn test_get_potentially_safe_blocks(logger: Logger) {
        // # Setup
        // ## Quorum slices
        //    local_node: {local_node, node_a, node_b}
        //    node_a: {node_a}
        //    node_b: {node_b}
        //
        // ## Blocks
        // The local_node has the origin block; node_a and node_b both have the same set
        // of blocks.

        let trivial_quorum_set = QuorumSet::empty();

        let node_a_uri = test_peer_uri(22);
        let node_a = (test_node_id(22), trivial_quorum_set.clone());

        let node_b_uri = test_peer_uri(33);
        let node_b = (test_node_id(33), trivial_quorum_set);

        let local_node_id = test_node_id(11);
        let local_quorum_set: QuorumSet<ResponderId> = QuorumSet::new_with_node_ids(
            2,
            vec![node_a.0.clone().responder_id, node_b.0.clone().responder_id],
        );

        let num_blocks = 17;
        let mock_ledger = get_mock_ledger(num_blocks);
        let mut network_state = SCPNetworkState::<ResponderId>::new(
            local_node_id.responder_id.clone(),
            local_quorum_set,
        );
        let mut peer_conns = Vec::<MockPeerConnection>::new();

        {
            let peer_a =
                MockPeerConnection::new(node_a_uri, local_node_id.clone(), mock_ledger.clone(), 50);
            peer_conns.push(peer_a);

            network_state.push(Msg::new(
                node_a.0.clone().responder_id,
                node_a.1,
                mock_ledger.num_blocks().unwrap() - 1,
                Topic::Externalize(ExternalizePayload {
                    C: Ballot::new(100, &["foo"]),
                    HN: 4,
                }),
            ));
        }

        {
            let peer_b =
                MockPeerConnection::new(node_b_uri, local_node_id, mock_ledger.clone(), 50);
            peer_conns.push(peer_b);

            network_state.push(Msg::new(
                node_b.0.clone().responder_id,
                node_b.1,
                mock_ledger.num_blocks().unwrap() - 1,
                Topic::Externalize(ExternalizePayload {
                    C: Ballot::new(100, &["foo"]),
                    HN: 4,
                }),
            ));
        }

        let ledger = get_mock_ledger(1);
        let conn_manager = ConnectionManager::new(peer_conns, logger.clone());
        let transactions_fetcher = MockTransactionsFetcher::new(ledger.clone());
        let mut sync_service =
            LedgerSyncService::new(ledger, conn_manager, transactions_fetcher, logger);

        let (responder_ids, block_index, potentially_safe_blocks) = sync_service
            .get_potentially_safe_blocks(&network_state, 100)
            .expect("No potentially safe blocks returned");
        assert_eq!(responder_ids.len(), 2);

        // Both peers have `num_blocks -1` blocks other than the origin block.
        assert_eq!(potentially_safe_blocks.len(), num_blocks - 1);

        // The index of the highest block fetched (zero-based index).
        assert_eq!(block_index, num_blocks as u64 - 1);
    }

    #[test_with_logger]
    // Only "potentially safe" blocks should be returned, even if some peers have
    // additional blocks.
    fn test_get_potentially_safe_blocks_differing_amounts(logger: Logger) {
        let trivial_quorum_set = QuorumSet::empty();

        let node_a_uri = test_peer_uri(22);
        let node_a = (test_node_id(22), trivial_quorum_set.clone());

        let node_b_uri = test_peer_uri(33);
        let node_b = (test_node_id(33), trivial_quorum_set);

        let local_node_id = test_node_id(11);
        let local_quorum_set: QuorumSet<ResponderId> = QuorumSet::new_with_node_ids(
            2,
            vec![node_a.0.clone().responder_id, node_b.0.clone().responder_id],
        );

        let mut network_state = SCPNetworkState::<ResponderId>::new(
            local_node_id.responder_id.clone(),
            local_quorum_set,
        );
        let mut peer_conns = Vec::<MockPeerConnection>::new();

        // Peer A and Peer B agree on the first 25 blocks, but Peer A has externalized
        // many additional blocks. The first 25 are "potentially safe", but the
        // rest are not.
        {
            let ledger = get_mock_ledger(145);

            network_state.push(Msg::new(
                node_a.0.clone().responder_id,
                node_a.1,
                ledger.num_blocks().unwrap() - 1,
                Topic::Externalize(ExternalizePayload {
                    C: Ballot::new(100, &["foo"]),
                    HN: 4,
                }),
            ));

            let peer_a = MockPeerConnection::new(node_a_uri, local_node_id.clone(), ledger, 50);
            peer_conns.push(peer_a);
        }

        {
            let ledger = get_mock_ledger(25);

            network_state.push(Msg::new(
                node_b.0.clone().responder_id,
                node_b.1,
                ledger.num_blocks().unwrap() - 1,
                Topic::Externalize(ExternalizePayload {
                    C: Ballot::new(100, &["foo"]),
                    HN: 4,
                }),
            ));

            let peer_b = MockPeerConnection::new(node_b_uri, local_node_id, ledger, 50);
            peer_conns.push(peer_b);
        }

        let ledger = get_mock_ledger(10);
        let conn_manager = ConnectionManager::new(peer_conns, logger.clone());
        let transactions_fetcher = MockTransactionsFetcher::new(ledger.clone());
        let mut sync_service =
            LedgerSyncService::new(ledger, conn_manager, transactions_fetcher, logger);

        let (responder_ids, slot_index, blocks) = sync_service
            .get_potentially_safe_blocks(&network_state, 100)
            .unwrap();
        assert_eq!(responder_ids.len(), 2);

        // Both peers have 24 blocks other than the origin block. We had  9 other blocks
        // to start with, so we synced 15 (9 + 15 = 24)
        assert_eq!(blocks.len(), 15);

        // The index of the highest block fetched (zero-based index).
        assert_eq!(slot_index, 24);
    }

    #[test_with_logger]
    // If an insufficient set of peers have externalized blocks in the requested
    // range, return None.
    fn test_get_potentially_safe_blocks_none(logger: Logger) {
        let trivial_quorum_set = QuorumSet::<NodeID>::empty();

        let node_a_uri = test_peer_uri(22);
        let node_a = (test_node_id(22), trivial_quorum_set.clone());

        let node_b_uri = test_peer_uri(33);
        let node_b = (test_node_id(33), trivial_quorum_set);

        let local_node_id = test_node_id(11);
        let local_quorum_set: QuorumSet<ResponderId> =
            QuorumSet::new_with_node_ids(2, vec![node_a.0.responder_id, node_b.0.responder_id]);

        let mut peer_conns = Vec::<MockPeerConnection>::new();
        let network_state = SCPNetworkState::<ResponderId>::new(
            local_node_id.responder_id.clone(),
            local_quorum_set,
        );

        // Peer A has externalized lots of blocks, but Peer B has not externalized any.
        {
            let ledger = get_mock_ledger(145);
            let peer_a = MockPeerConnection::new(node_a_uri, local_node_id.clone(), ledger, 50);
            peer_conns.push(peer_a);
        }
        {
            let ledger = get_mock_ledger(0);
            let peer_b = MockPeerConnection::new(node_b_uri, local_node_id, ledger, 50);
            peer_conns.push(peer_b);
        }

        // The local ledger only contains the origin block.
        let ledger = get_mock_ledger(25);
        let conn_manager = ConnectionManager::new(peer_conns, logger.clone());
        let transactions_fetcher = MockTransactionsFetcher::new(ledger.clone());
        let mut sync_service =
            LedgerSyncService::new(ledger, conn_manager, transactions_fetcher, logger);

        if let Some((responder_ids, block_index, blocks)) =
            sync_service.get_potentially_safe_blocks(&network_state, 100)
        {
            panic!("Node IDs: {responder_ids:?}, block index: {block_index:?}, blocks: {blocks:?}");
        }
    }

    #[test]
    #[ignore]
    fn test_get_potentially_safe_blocks_network_fork() {
        // TODO: `get_potentially_safe_blocks` should do the right thing if the
        // network is forked. This may mean returning None, returning
        // the highest block before the fork, returning blocks along one
        // fork if it is the only fork with quorum.
    }

    #[test_with_logger]
    // A set of safe blocks with valid transactions should be identified as safe.
    fn test_identify_safe_blocks(logger: Logger) {
        // The local node's ledger must contain the origin block.
        let local_ledger = get_mock_ledger(1);
        // These blocks ought to be a valid blockchain.
        let blocks = get_test_ledger_blocks(5);
        // Blocks other than the origin block should be safe to append to the local
        // node's ledger.
        let potentially_safe_blocks = &blocks[1..];

        let safe_blocks: Vec<BlockData> =
            identify_safe_blocks(&local_ledger, potentially_safe_blocks, &logger);

        assert_eq!(safe_blocks.len(), potentially_safe_blocks.len());
    }

    #[test_with_logger]
    // A block with invalid parent_id is not safe.
    fn test_identify_safe_blocks_wrong_parent_id(logger: Logger) {
        // The local node's ledger must contain the origin block.
        let local_ledger = get_mock_ledger(1);

        // These blocks and transactions ought to be a valid blockchain.
        let blocks = get_test_ledger_blocks(2);

        // Set an incorrect parent_id
        let block_data = blocks[1].clone().mutate(|block, _, _, _| {
            block.parent_id = BlockID([200u8; 32]);
        });

        let potentially_safe_blocks = vec![block_data];

        let safe_blocks = identify_safe_blocks(&local_ledger, &potentially_safe_blocks, &logger);

        assert_eq!(safe_blocks.len(), 0);
    }

    #[test_with_logger]
    // A block with a reused key image is not safe.
    fn test_identify_safe_blocks_reused_key_image_in_potentially_safe_blocks(logger: Logger) {
        // Evaluating a batch of potentially safe blocks means checking that each key
        // image is not already in the local nodes ledger, and not in any of the
        // prior potentially safe blocks. This test initializes the local node's
        // ledger to only contain the origin block, which has no key images, so
        // does not test if the local ledger's key images are checked.

        // The local node's ledger must contain the origin block.
        let local_ledger = get_mock_ledger(1);

        // These blocks and transactions ought to be a valid blockchain.
        let blocks = get_test_ledger_blocks(3);

        // Modify a block to reuse a key image from block 1.
        let block_one = blocks[1].clone();
        let block_two = blocks[2].clone().mutate(|_, contents, _, _| {
            contents.key_images.push(block_one.contents().key_images[0]);
        });

        let potentially_safe_blocks = vec![block_one, block_two];

        let safe_blocks: Vec<BlockData> =
            identify_safe_blocks(&local_ledger, &potentially_safe_blocks, &logger);

        // Block one should be safe, but block two is not.
        assert_eq!(safe_blocks.len(), 1);
        assert_eq!(safe_blocks[0].block().index, 1);
    }

    #[test_with_logger]
    // A block with a reused key image is not safe.
    fn test_identify_safe_blocks_reused_key_image_in_ledger(logger: Logger) {
        // Evaluating a batch of potentially safe blocks means checking that each key
        // image is not already in the local nodes ledger, and not in any of the
        // prior potentially safe blocks. This test initializes the local node's
        // ledger with some key images, and tests that a potentially safe block
        // that reuses a key in the ledger is considered unsafe.

        // The local node's ledger contains the origin block and block one.
        let local_ledger = get_mock_ledger(2);

        // These blocks and transactions ought to be a valid blockchain.
        let blocks = get_test_ledger_blocks(3);

        // Modify a block to reuse a key image from block 1.
        let block_one = blocks[1].clone();
        let block_two = blocks[2].clone().mutate(|_, contents, _, _| {
            contents.key_images.push(block_one.contents().key_images[0]);
        });

        let potentially_safe_blocks = vec![block_two];

        let safe_blocks: Vec<BlockData> =
            identify_safe_blocks(&local_ledger, &potentially_safe_blocks, &logger);

        // Block two is not safe.
        assert_eq!(safe_blocks.len(), 0);
    }

    #[test_with_logger]
    // A block with incorrect block ID is not safe.
    fn test_identify_safe_blocks_wrong_block_id(logger: Logger) {
        // The local node's ledger must contain the origin block.
        let local_ledger = get_mock_ledger(1);

        // These blocks and transactions ought to be a valid blockchain.
        let blocks = get_test_ledger_blocks(2);

        // Set an incorrect parent_id
        let block_one = blocks[1].clone().mutate(|block, _, _, _| {
            block.id = BlockID([99u8; 32]);
        });

        let potentially_safe_blocks: Vec<BlockData> = vec![block_one];

        let safe_blocks: Vec<BlockData> =
            identify_safe_blocks(&local_ledger, &potentially_safe_blocks, &logger);

        // Block one is not safe.
        assert_eq!(safe_blocks.len(), 0);
    }

    #[test]
    // Without a fork, nodes contain subsets of the longest blockchain. For each
    // slot (aka, block index), `group_by_block` should return a single group of
    // nodes who have externalized a block for that slot.
    fn test_group_by_block() {
        let blocks_data = get_test_ledger_blocks(17);
        let blocks: Vec<Block> = blocks_data
            .iter()
            .map(|block_data| block_data.block().clone())
            .collect();

        let mut node_to_blocks: HashMap<ResponderId, Vec<Block>> = HashMap::default();
        {
            let blocks = blocks[0..7].to_vec();
            node_to_blocks.insert(test_peer_uri(1).responder_id().unwrap(), blocks);
        }
        {
            let blocks = blocks[0..17].to_vec();
            node_to_blocks.insert(test_peer_uri(2).responder_id().unwrap(), blocks);
        }
        {
            //            let (blocks, _) = get_test_ledger_blocks(4);
            let blocks = blocks[0..4].to_vec();
            node_to_blocks.insert(test_peer_uri(3).responder_id().unwrap(), blocks);
        }

        let grouping: BTreeMap<SlotIndex, HashMap<BlockID, HashSet<ResponderId>>> =
            group_by_block(&node_to_blocks);

        for (_block_index, block_id_to_nodes) in grouping.iter().rev() {
            for (block_id, nodes) in block_id_to_nodes.iter() {
                println!("BlockID: {block_id:?} to nodes {nodes:?}");
            }
        }

        // `grouping` should contain one element for each slot where one or more peers
        // has a block.
        assert_eq!(grouping.len(), 17);

        {
            // for slots 0,1,2, there should be a single group of nodes {1,2,3}.
            let groups = grouping.get(&1).unwrap();
            assert_eq!(groups.len(), 1);
            let block_id: BlockID = blocks[1].id.clone();
            let nodes = groups.get(&block_id).unwrap();
            assert_eq!(nodes.len(), 3);
            assert!(nodes.contains(&test_peer_uri(1).responder_id().unwrap()));
            assert!(nodes.contains(&test_peer_uri(2).responder_id().unwrap()));
            assert!(nodes.contains(&test_peer_uri(3).responder_id().unwrap()));
        }

        {
            // for slots 3-6, there should be a single group of nodes {1,2}.
            let groups = grouping.get(&5).unwrap();
            assert_eq!(groups.len(), 1);
            let block_id: BlockID = blocks[5].id.clone();
            let nodes = groups.get(&block_id).unwrap();
            assert_eq!(nodes.len(), 2);
            assert!(nodes.contains(&test_peer_uri(1).responder_id().unwrap()));
            assert!(nodes.contains(&test_peer_uri(2).responder_id().unwrap()));
        }

        {
            // for slots 7-16, there should be a single group of nodes {2}.
            let groups = grouping.get(&9).unwrap();
            assert_eq!(groups.len(), 1);
            let block_id: BlockID = blocks[9].id.clone();
            let nodes = groups.get(&block_id).unwrap();
            assert_eq!(nodes.len(), 1);
            assert!(nodes.contains(&test_peer_uri(2).responder_id().unwrap()));
        }
    }

    #[test_with_logger]
    fn test_append_safe_blocks_default_metadata_provider(logger: Logger) {
        let ledger = get_mock_ledger(10);
        let conn_manager = ConnectionManager::<MockPeerConnection>::new(vec![], logger.clone());
        let transactions_fetcher = MockTransactionsFetcher::new(ledger.clone());
        let mut sync_service =
            LedgerSyncService::new(ledger, conn_manager, transactions_fetcher, logger);

        let mut blocks = get_test_ledger_blocks(15);
        blocks.drain(0..10);

        sync_service
            .append_safe_blocks(&blocks)
            .expect("failed to append blocks");

        for expected_block in blocks {
            let block_data = sync_service
                .ledger
                .get_block_data(expected_block.block().index)
                .unwrap();
            assert_eq!(block_data.block(), expected_block.block());
            assert_eq!(block_data.contents(), expected_block.contents());
            assert_eq!(block_data.signature(), None);
            assert_eq!(block_data.metadata(), expected_block.metadata());
        }
    }

    #[test_with_logger]
    fn test_append_safe_blocks_custom_metadata_provider(logger: Logger) {
        #[derive(Copy, Clone)]
        struct RandomMetadata {}
        impl BlockMetadataProvider for RandomMetadata {
            fn get_metadata(&self, block_data: &BlockData) -> Option<BlockMetadata> {
                Some(make_block_metadata(
                    block_data.block().id.clone(),
                    &mut get_seeded_rng(),
                ))
            }
        }

        let metadata_provider = RandomMetadata {};
        let ledger = get_mock_ledger(10);
        let conn_manager = ConnectionManager::<MockPeerConnection>::new(vec![], logger.clone());
        let transactions_fetcher = MockTransactionsFetcher::new(ledger.clone());
        let mut sync_service = LedgerSyncService::with_metadata_provider(
            metadata_provider,
            ledger,
            conn_manager,
            transactions_fetcher,
            logger,
        );

        let mut blocks = get_test_ledger_blocks(15);
        blocks.drain(0..10);

        sync_service
            .append_safe_blocks(&blocks)
            .expect("failed to append blocks");

        for expected_block in blocks {
            let block_data = sync_service
                .ledger
                .get_block_data(expected_block.block().index)
                .unwrap();
            assert_eq!(block_data.block(), expected_block.block());
            assert_eq!(block_data.contents(), expected_block.contents());
            assert_eq!(block_data.signature(), None);
            assert_eq!(
                block_data.metadata(),
                metadata_provider.get_metadata(&expected_block).as_ref()
            );
            // Sanity check.
            assert_ne!(block_data.metadata(), expected_block.metadata());
        }
    }
}
