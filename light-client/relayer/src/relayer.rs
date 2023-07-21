// Copyright (c) 2018-2023 The MobileCoin Foundation

use crate::{error::Error, verifier::Verifier, Config, Sender};
use mc_account_keys::burn_address_view_private;
use mc_blockchain_types::{Block, BlockContents, BlockData, BlockIndex, BlockMetadata};
use mc_common::logger::{log, Logger};
use mc_ledger_db::{Error as LedgerError, Ledger, LedgerDB};
use mc_transaction_core::tx::TxOut;
use mc_util_telemetry::{telemetry_static_key, tracer, Key, TraceContextExt, Tracer};
use mc_watcher::{error::WatcherDBError, watcher_db::WatcherDB};
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, MutexGuard,
    },
    thread::{Builder as ThreadBuilder, JoinHandle},
    time::Duration,
};

/// Telemetry: block index currently being worked on.
const TELEMETRY_BLOCK_INDEX_KEY: Key = telemetry_static_key!("block-index");

#[derive(Default, Debug, Clone)]
pub struct RelayedBlock {
    pub burn_tx_outs: Vec<TxOut>,
    pub block: Block,
    pub block_contents: BlockContents,
    pub signatures: Vec<BlockMetadata>,
}

#[derive(Default)]
struct RelayerSharedState {
    current_block_index: BlockIndex,
}

pub struct Relayer {
    /// Join handle used to wait for the thread to terminate.
    join_handle: Option<JoinHandle<()>>,

    /// Stop request trigger, used to signal the thread to stop.
    stop_requested: Arc<AtomicBool>,

    /// State shared with the worker thread.
    shared_state: Arc<Mutex<RelayerSharedState>>,
}

impl Relayer {
    pub fn new<
        S: Sender + Clone + Send + Sync + 'static,
        V: Verifier + Clone + Send + Sync + 'static,
    >(
        config: Config,
        ledger_db: LedgerDB,
        watcher_db: WatcherDB,
        sender: S,
        verifier: V,
        logger: Logger,
    ) -> Self {
        let stop_requested = Arc::new(AtomicBool::new(false));
        let shared_state = Arc::new(Mutex::new(RelayerSharedState::default()));

        let thread_stop_requested = stop_requested.clone();
        let thread_shared_state = shared_state.clone();

        let join_handle = Some(
            ThreadBuilder::new()
                .name("RelayerRunner".to_owned())
                .spawn(move || {
                    RelayerThread::start(
                        config,
                        ledger_db,
                        watcher_db,
                        sender,
                        verifier,
                        thread_stop_requested,
                        thread_shared_state,
                        logger,
                    );
                })
                .expect("Could not spawn thread"),
        );
        Self {
            join_handle,
            stop_requested,
            shared_state,
        }
    }

    pub fn get_current_block_index(&self) -> BlockIndex {
        self.shared_state().current_block_index
    }

    pub fn stop(&mut self) -> Result<(), Error> {
        if let Some(join_handle) = self.join_handle.take() {
            self.stop_requested.store(true, Ordering::SeqCst);
            join_handle.join().map_err(|_| Error::ThreadJoin)?;
        }

        Ok(())
    }

    /// Get a locked reference to the shared state.
    fn shared_state(&self) -> MutexGuard<RelayerSharedState> {
        self.shared_state.lock().expect("mutex poisoned")
    }
}

impl Drop for Relayer {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

/// The relayer object is able to scan the blockchain for interesting burn txos,
/// and forward them to a "sender", together with proofs of the block's
/// validity, when it finds any.
struct RelayerThread<S, V>
where
    S: Sender + Send + Sync + 'static,
    V: Verifier + Send + Sync + 'static,
{
    _config: Config,
    next_block_index: BlockIndex,
    ledger_db: LedgerDB,
    watcher_db: WatcherDB,
    sender: S,
    verifier: V,
    stop_requested: Arc<AtomicBool>,
    shared_state: Arc<Mutex<RelayerSharedState>>,
    logger: Logger,
}

impl<S, V> RelayerThread<S, V>
where
    S: Sender + Send + Sync + 'static,
    V: Verifier + Send + Sync + 'static,
{
    /// Poll for new data every 10 ms
    const POLLING_FREQUENCY: Duration = Duration::from_millis(10);
    /// How frequently to retry if an error occurs.
    const ERROR_RETRY_FREQUENCY: Duration = Duration::from_millis(1000);

    /// Entrypoint for relayer loop.
    pub fn start(
        config: Config,
        ledger_db: LedgerDB,
        watcher_db: WatcherDB,
        sender: S,
        verifier: V,
        stop_requested: Arc<AtomicBool>,
        shared_state: Arc<Mutex<RelayerSharedState>>,
        logger: Logger,
    ) {
        let next_block_index = config.start_block_index;
        let thread = Self {
            _config: config,
            next_block_index,
            ledger_db,
            watcher_db,
            sender,
            verifier,
            stop_requested,
            shared_state,
            logger,
        };
        thread.run();
    }

    pub fn run(mut self) {
        // Poll ledger for data to relay
        log::info!(self.logger, "Relayer thread started.");
        loop {
            self.shared_state().current_block_index = self.next_block_index;
            if self.stop_requested.load(Ordering::SeqCst) {
                log::info!(self.logger, "Relayer thread stop requested.");
                break;
            }
            let block_data = tracer!().in_span("get_block_data", |cx| {
                cx.span()
                    .set_attribute(TELEMETRY_BLOCK_INDEX_KEY.i64(self.next_block_index as i64));
                self.ledger_db.get_block_data(self.next_block_index)
            });

            match block_data {
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
                    let process_block_result = tracer!().in_span("process_block", |cx| {
                        cx.span().set_attribute(
                            TELEMETRY_BLOCK_INDEX_KEY.i64(self.next_block_index as i64),
                        );
                        self.process_block(&block_data)
                    });
                    match process_block_result {
                        Ok(_) => {
                            self.next_block_index += 1;
                        }
                        Err(e) => {
                            log::error!(
                                self.logger,
                                "When processing block {}: {:?}",
                                self.next_block_index,
                                e
                            );
                            std::thread::sleep(Self::ERROR_RETRY_FREQUENCY);
                        }
                    }
                }
            }
        }
    }

    fn process_block(&mut self, block_data: &BlockData) -> Result<(), Error> {
        let relevant_burns = Self::check_for_relevant_burns(&block_data.contents().outputs);
        if relevant_burns.is_empty() {
            return Ok(());
        }

        let signatures = self.get_block_signatures(self.next_block_index)?;
        let relayed_block = RelayedBlock {
            block: block_data.block().clone(),
            block_contents: block_data.contents().clone(),
            signatures,
            burn_tx_outs: relevant_burns,
        };
        self.verifier.verify_relayed_block(&relayed_block)?;
        self.sender.send(relayed_block);
        Ok(())
    }

    /// Function to match TXOs from a block into interesting vector of
    /// unspent UTXOs.
    fn check_for_relevant_burns(outputs: &[TxOut]) -> Vec<TxOut> {
        // Iterate over each output and filter the results using a parallel iterator.
        outputs
            .into_par_iter()
            .filter_map(|tx_out| {
                // View key match against the burn address. If it returns ok, then it's a burn.
                if tx_out.view_key_match(&burn_address_view_private()).is_ok() {
                    Some(tx_out.clone())
                } else {
                    None
                }
            })
            .collect()
    }

    fn get_block_signatures(
        &self,
        block_index: BlockIndex,
    ) -> Result<Vec<BlockMetadata>, WatcherDBError> {
        let block_data_map = self.watcher_db.get_block_data_map(block_index)?;
        Ok(block_data_map
            .values()
            .filter_map(|block_data| block_data.metadata().cloned())
            .collect())
    }

    pub fn shared_state(&self) -> MutexGuard<RelayerSharedState> {
        self.shared_state.lock().expect("mutex poisoned")
    }
}
