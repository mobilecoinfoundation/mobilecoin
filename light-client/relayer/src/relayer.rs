// Copyright (c) 2018-2023 The MobileCoin Foundation

use crate::{Config, Sender};
use mc_account_keys::burn_address_view_private;
use mc_blockchain_types::{BlockData, BlockIndex, BlockMetadata};
use mc_common::logger::{log, Logger};
use mc_ledger_db::{Error as LedgerError, Ledger, LedgerDB};
use mc_transaction_core::tx::TxOut;
use mc_util_telemetry::{block_span_builder, telemetry_static_key, tracer, Key, Span, Tracer};
use mc_watcher::{error::WatcherDBError, watcher_db::WatcherDB};
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use std::time::Duration;

/// Telemetry: block index currently being worked on.
const TELEMETRY_BLOCK_INDEX_KEY: Key = telemetry_static_key!("block-index");

/// The relayer object is able to scan the blockchain for interesting burn txos,
/// and forward them to a "sender", together with proofs of the block's
/// validity, when it finds any.
pub struct Relayer<S: Sender> {
    config: Config,
    next_block_index: BlockIndex,
    ledger_db: LedgerDB,
    watcher_db: WatcherDB,
    sender: S,
    logger: Logger,
}

impl<S: Sender> Relayer<S> {
    /// Poll for new data every 10 ms
    const POLLING_FREQUENCY: Duration = Duration::from_millis(10);
    /// How frequently to retry if an error occurs.
    const ERROR_RETRY_FREQUENCY: Duration = Duration::from_millis(1000);

    /// Create a new relayer
    pub fn new(
        config: Config,
        ledger_db: LedgerDB,
        watcher_db: WatcherDB,
        sender: S,
        logger: Logger,
    ) -> Self {
        let next_block_index = config.start_block_index;
        Self {
            config,
            next_block_index,
            ledger_db,
            watcher_db,
            sender,
            logger,
        }
    }

    /// Entrypoint for relayer loop.
    pub fn entry_point(&mut self) -> ! {
        // Poll ledger for data to relay
        loop {
            match self.ledger_db.get_block_data(self.next_block_index) {
                Err(LedgerError::NotFound) => std::thread::sleep(Self::POLLING_FREQUENCY),
                Err(e) => {
                    log::error!(
                        self.logger,
                        "Unexpected error when checking for block data {}: {:?}",
                        self.next_block_index,
                        e
                    );
                    std::thread::sleep(Self::ERROR_RETRY_FREQUENCY);
                }
                Ok(block_data) => {
                    if let Err(err) = self.process_block(&block_data) {
                        log::error!(
                            self.logger,
                            "When processing block {}: {:?}",
                            self.next_block_index,
                            err
                        );
                        std::thread::sleep(Self::ERROR_RETRY_FREQUENCY);
                    } else {
                        self.next_block_index += 1;
                    }
                }
            }
        }
    }

    fn process_block(&mut self, block_data: &BlockData) -> Result<(), WatcherDBError> {
        // Tracing
        let tracer = tracer!();

        let mut span =
            block_span_builder(&tracer, "poll_block", self.next_block_index).start(&tracer);

        span.set_attribute(TELEMETRY_BLOCK_INDEX_KEY.i64(self.next_block_index as i64));

        // First, check if there's anything interesting in this block
        let relevant_burns = Self::check_for_relevant_burns(&block_data.contents().outputs);

        // There are no burns with relevant memos in this block so this block is
        // finished processing.
        if relevant_burns.is_empty() {
            return Ok(());
        }

        // Try to get signatures from the watcher
        // Loop until we get enough signatures
        tracer.in_span("loop_for_signatures", |_cx| {
            loop {
                let signatures = self.check_for_signatures(self.next_block_index)?;
                if signatures.len() >= self.config.min_signatures {
                    self.sender.send(
                        relevant_burns,
                        block_data.block(),
                        block_data.contents(),
                        signatures,
                    );
                    return Ok(());
                } else {
                    // We didn't get enough signatures, but let's assume that more are coming soon
                    // TODO: An alternative here is, actually use a light-client verifier object,
                    // which is a more correct approach.
                    log::debug!(
                        self.logger,
                        "Did not find a quorum yet for block {}: {} signatures < {} required",
                        self.next_block_index,
                        signatures.len(),
                        self.config.min_signatures
                    );
                    std::thread::sleep(Self::POLLING_FREQUENCY);
                }
            }
        })
    }

    /// Function to match TXOs from a block into interesting vector of
    /// unspent UTXOs.
    fn check_for_relevant_burns(outputs: &[TxOut]) -> Vec<TxOut> {
        // Iterate over each output and filter the results using a parallel iterator.
        let results: Vec<TxOut> = outputs
            .into_par_iter()
            .filter_map(|tx_out| {
                // View key match against the burn address. If it returns ok, then it's a burn.
                if tx_out.view_key_match(&burn_address_view_private()).is_ok() {
                    Some(tx_out.clone())
                } else {
                    None
                }
            })
            .collect();

        results
    }

    fn check_for_signatures(
        &self,
        block_index: BlockIndex,
    ) -> Result<Vec<BlockMetadata>, WatcherDBError> {
        let block_data_map = self.watcher_db.get_block_data_map(block_index)?;
        Ok(block_data_map
            .values()
            .filter_map(|block_data| block_data.metadata().cloned())
            .collect())
    }
}
