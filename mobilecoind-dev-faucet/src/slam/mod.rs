// Copyright (c) 2018-2022 The MobileCoin Foundation

use super::{GetUtxoError, UtxoRecord, Worker};
use displaydoc::Display;
use mc_account_keys::{AccountKey, PublicAddress};
use mc_common::logger::{log, o, Logger};
use mc_mobilecoind_api::{self as api, mobilecoind_api_grpc::MobilecoindApiClient};
use mc_util_uri::ConsensusClientUri;
use std::{
    sync::{
        atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

mod prepared_utxo;
use prepared_utxo::PreparedUtxo;

mod tx_submitter;
use tx_submitter::{SubmitTxError, TxSubmitter};

/// Parameters to start a slam operation
#[derive(Clone, Debug)]
pub struct SlamParams {
    /// The total number of tx to try to submit
    pub target_num_tx: u32,
    /// The number of threads to use when submitting to consensus
    pub num_threads: u32,
    /// The number of retries to allow when submitting to consensus
    pub retries: u32,
    /// The period to wait between retries when submitting to consensus
    pub retry_period: Duration,
    /// How far forward to set the tombstone block
    pub tombstone_offset: u32,
    /// The consensus uris to submit to
    pub consensus_client_uris: Vec<ConsensusClientUri>,
}

impl Default for SlamParams {
    fn default() -> Self {
        Self {
            target_num_tx: 500,
            num_threads: 30,
            retries: 30,
            retry_period: Duration::from_millis(1000),
            tombstone_offset: 10,
            consensus_client_uris: Default::default(),
        }
    }
}

/// A report on a completed slam operation
#[derive(Clone, Debug, Default)]
pub struct SlamReport {
    /// The number of utxos successfully prepared
    pub num_prepared_utxos: u32,
    /// The number of txs successfully submitted to the network
    pub num_submitted_txs: u32,
    /// The total time spent preparing Txs
    pub prepare_time: Duration,
    /// The total time spent submitting Txs
    pub submit_time: Duration,
}

/// State which tracks the progress of a running slam operation.
/// This allows one thread to conduct the slam while another thread checks on
/// its status.
pub struct SlamState {
    // Phase tracks the state of the current slam operation if any.
    // This is used to get the status of the slam operation asynchronously,
    // and also to prevent a second slam from being started concurrently.
    // The slam state guard is responsible for that check and for resetting the
    // phase when the guard is dropped.
    phase: AtomicU32,
    // The number of tx's we want to send in total in the slam
    target_num_tx: AtomicU32,
    // The number of utxo's we have prepared so far in this slam
    num_prepared_utxos: AtomicU32,
    // The number of tx's we have successfully submitted so far in this slam
    num_submitted_txs: AtomicU32,
    // The estimated block height of the network, updated during slam as we submit to consensus
    block_height: AtomicU64,
    // Whether it has been requested to stop the slam
    stop_requested: AtomicBool,
    // grpcio environment
    env: Arc<grpcio::Environment>,
}

impl SlamState {
    /// Constants describing what phase of the slam operation we are in.
    /// These are the legal values of self.phase
    const NOT_CURRENTLY_SLAMMING: u32 = 0;
    const CONNECTING: u32 = 1;
    const PREPARING_UTXOS: u32 = 2;
    const SUBMITTING_TRANSACTIONS: u32 = 3;

    /// Create a new slam state
    pub fn new(env: Arc<grpcio::Environment>) -> Arc<Self> {
        Arc::new(Self {
            phase: Default::default(),
            target_num_tx: Default::default(),
            num_prepared_utxos: Default::default(),
            num_submitted_txs: Default::default(),
            block_height: Default::default(),
            stop_requested: Default::default(),
            env,
        })
    }

    /// Start a slam operation with given parameters
    ///
    /// This returns immediately with an error if another slam is currently in
    /// progress, otherwise it starts a new slam.
    /// Other threads can track the progress of the slam by calling
    /// "get_status()".
    ///
    /// The slam has three steps:
    /// (1) connecting to consensus
    /// (2) getting rings and proofs of membership for utxos
    /// (3) building and submitting Tx's in parallel
    ///
    /// This function returns a slam report, which includes how many Txs were
    /// ultimately submitted successfully and how long each step took, or an
    /// error message.
    pub async fn start_slam(
        self: Arc<Self>,
        params: &SlamParams,
        account_key: &AccountKey,
        mobilecoind_api_client: &MobilecoindApiClient,
        worker: &Worker,
        logger: &Logger,
    ) -> Result<SlamReport, String> {
        // This guard backs off if phase is not 0, and sets it to 1 atomically
        let _guard = SlamStateGuard::new(&*self, logger)?;
        self.target_num_tx
            .store(params.target_num_tx, Ordering::SeqCst);
        log::info!(logger, "Slam status: {}", self.get_status().unwrap());

        let tx_submitter = Arc::new(TxSubmitter::new(
            params.consensus_client_uris.clone(),
            self.env.clone(),
            logger,
        )?);
        let recipient = account_key.default_subaddress();

        // First, we have to prepare target_num_tx utxos
        self.phase
            .store(SlamState::PREPARING_UTXOS, Ordering::SeqCst);
        log::info!(logger, "Slam status: {}", self.get_status().unwrap());
        let begin_prepare_time = Instant::now();

        // A queue for the prepared utxos
        let (prepared_utxos_sender, prepared_utxos_receiver) =
            async_channel::bounded::<PreparedUtxo>(params.target_num_tx as usize);

        while self.num_prepared_utxos.load(Ordering::SeqCst) < params.target_num_tx {
            if self.stop_requested.load(Ordering::SeqCst) {
                return Err("Stop requested".to_owned());
            }
            match worker.get_any_utxo() {
                Ok(utxo_record) => {
                    // Prepare the utxo and stick it in the queue
                    // Mobilecoind can only handle one request at a time so there's no point in
                    // parallelizing this
                    let counter = self.num_prepared_utxos.load(Ordering::SeqCst) + 1;
                    match PreparedUtxo::new(
                        counter,
                        utxo_record,
                        params,
                        mobilecoind_api_client,
                        logger,
                    )
                    .await
                    {
                        Ok(prepared_utxo) => {
                            prepared_utxos_sender
                                .send(prepared_utxo)
                                .await
                                .map_err(|err| {
                                    format!("Unexpected error when preparing: {}", err)
                                })?;
                            self.num_prepared_utxos.fetch_add(1, Ordering::SeqCst);
                        }
                        Err(err) => {
                            log::error!(
                                logger,
                                "Could not prepare utxo #{}, skipping: {}",
                                counter,
                                err
                            );
                        }
                    }
                }
                Err(GetUtxoError::Busy) => {
                    // Try again later after the worker has had a chance to split more utxos
                    tokio::time::sleep(worker.get_worker_poll_period()).await;
                }
                Err(err) => {
                    // Any more serious error, like "funds depleted", means we cannot complete the
                    // slam
                    return Err(format!("Cannot obtain more utxos, aborting slam: {}", err));
                }
            }
        }

        // Close this so that workers that get to the end of the queue won't block
        prepared_utxos_sender.close();

        // Get the network state, which contains block height, now so that it is
        // fresh for the slam workers
        let network_state = {
            let resp = mobilecoind_api_client
                .get_network_status(&Default::default())
                .map_err(|err| format!("Failed getting network status: {}", err))?;
            self.block_height
                .store(resp.network_highest_block_index, Ordering::SeqCst);
            resp
        };

        // Now, we spawn worker threads, which build txs and
        // submits them, with retries, in parallel
        self.phase
            .store(SlamState::SUBMITTING_TRANSACTIONS, Ordering::SeqCst);
        log::info!(logger, "Slam status: {}", self.get_status().unwrap());
        let begin_submit_time = Instant::now();
        let prepare_time = begin_submit_time.duration_since(begin_prepare_time);

        // Note: Workers are std::thread rather than tokio::task because mc_connection
        // currently only has blocking APIs If we get an async-api for
        // attestation and tx submission, we could change this to be tasks and just use
        // the tokio thread pool. maybe some advantages?
        let workers: Vec<_> = (0..params.num_threads)
            .map(|worker_num| {
                let this = self.clone();
                let params = params.clone();
                let prepared_utxos_receiver = prepared_utxos_receiver.clone();
                let recipient = recipient.clone();
                let account_key = account_key.clone();
                let network_state = network_state.clone();
                let tx_submitter = tx_submitter.clone();
                let logger = logger.new(o! { "thread" => format!("slam-worker-{}", worker_num) });
                std::thread::spawn(move || {
                    this.slam_worker_entry_point(
                        worker_num,
                        &params,
                        prepared_utxos_receiver,
                        recipient,
                        account_key,
                        network_state,
                        tx_submitter,
                        logger,
                    )
                })
            })
            .collect();

        // Wait for each worker to finish
        log::info!(logger, "Waiting for workers to finish");
        for worker in workers {
            // Note: this is blocking, we could use async_thread instead I guess. But it
            // only blocks one thread at most since only one slam can happen at
            // a time, so it likely doesn't matter
            if worker.join().is_err() {
                // This error happens if a worker thread panics. The rest of
                // the server can still work OK, so ignore the panic.
                // The error type is Any, so we cannot easily log it, but it
                // was likely already logged.
                log::error!(
                    logger,
                    "Slam worker error on join; see previous logs for details"
                );
            }
        }
        let submit_time = Instant::now().duration_since(begin_submit_time);

        Ok(SlamReport {
            num_prepared_utxos: self.num_prepared_utxos.load(Ordering::SeqCst),
            num_submitted_txs: self.num_submitted_txs.load(Ordering::SeqCst),
            prepare_time,
            submit_time,
        })
    }

    fn slam_worker_entry_point(
        self: Arc<Self>,
        worker_num: u32,
        params: &SlamParams,
        prepared_utxos_receiver: async_channel::Receiver<PreparedUtxo>,
        recipient: PublicAddress,
        account_key: AccountKey,
        network_state: api::GetNetworkStatusResponse,
        tx_submitter: Arc<TxSubmitter>,
        logger: Logger,
    ) {
        log::info!(logger, "Worker started");
        // Continue pulling prepared utxos from the queue until it is drained
        loop {
            if self.stop_requested.load(Ordering::SeqCst) {
                return;
            }
            match prepared_utxos_receiver.try_recv() {
                Ok(prepared_utxo) => {
                    self.build_and_submit_tx(
                        params,
                        prepared_utxo,
                        &recipient,
                        &account_key,
                        &network_state,
                        worker_num,
                        &*tx_submitter,
                        &logger,
                    );
                }
                Err(_) => {
                    log::info!(logger, "A slam worker finished");
                    return;
                }
            }
        }
    }

    /// Build and submit a Tx based on a prepared utxo, using retries according
    /// to the config.
    ///
    /// Arguments:
    /// * params: the slam parameters
    /// * prepared_utxo: The prepared utxo to build a Tx from
    /// * recipient: the recipient of this Tx
    /// * account_key: the account key that owns this prepared utxo
    /// * network_state: a (recent) GetNetworkStatusResponse from mobilecoind,
    ///   for block version and block height
    /// * node_index_offset: An arbitrary number used as an offset into the list
    ///   of consensus nodes we can submit to. By varying this we can distribute
    ///   the load across several nodes instead of submitting always to one
    ///   particular node
    /// * tx_submitter: An object which can actually submit a prepared tx
    /// * logger
    fn build_and_submit_tx(
        &self,
        params: &SlamParams,
        prepared_utxo: PreparedUtxo,
        recipient: &PublicAddress,
        account_key: &AccountKey,
        network_state: &api::GetNetworkStatusResponse,
        node_index_offset: u32,
        tx_submitter: &TxSubmitter,
        logger: &Logger,
    ) {
        for _build_tries in 0..params.retries {
            let tx = prepared_utxo
                .build_tx(
                    self.block_height.load(Ordering::SeqCst) + params.tombstone_offset as u64,
                    recipient,
                    account_key,
                    network_state,
                )
                .expect("Transaction building failed");
            for tries in 0..params.retries {
                if self.stop_requested.load(Ordering::SeqCst) {
                    return;
                }
                match tx_submitter.submit_tx(
                    prepared_utxo.index,
                    &tx,
                    (prepared_utxo.index + node_index_offset + tries) as usize,
                    logger,
                ) {
                    Ok(block_height) => {
                        self.block_height.fetch_max(block_height, Ordering::SeqCst);
                        self.num_submitted_txs.fetch_add(1, Ordering::SeqCst);
                        // Submit a receipt over prepared_utxo.utxo.sender
                        // This helps the backgorund worker thread track if this
                        // payment succeeds, and avoid immediately requeuing the utxo
                        let receipt = Self::get_receipts(&tx, recipient);
                        if prepared_utxo.utxo_record.sender.send(receipt).is_err() {
                            log::error!(logger, "Could not send SubmitTxResponse to worker thread");
                        }
                        return;
                    }
                    Err(SubmitTxError::Fatal) => {
                        log::warn!(
                            logger,
                            "Fatal error when submitting tx #{}, giving up on this tx",
                            prepared_utxo.index
                        );
                        return;
                    }
                    Err(SubmitTxError::Rebuild) => {
                        log::debug!(logger, "Rebuilding tx #{}", prepared_utxo.index);
                        break;
                    }
                    Err(SubmitTxError::Retry) => {
                        std::thread::sleep(params.retry_period);
                    }
                }
            }
            std::thread::sleep(params.retry_period);
        }
        log::warn!(
            logger,
            "Built and submitted tx #{} a total of {} times without success, giving up",
            prepared_utxo.index,
            params.retries
        );
    }

    /// Get a mobilecoind-compatible SubmitTxResponse containing appropriate
    /// receipts
    ///
    /// This is needed for the background worker thread to track whether any of
    /// these payments land and avoid queueing and utxos used by slam
    fn get_receipts(
        tx: &mc_transaction_core::tx::Tx,
        recipient: &PublicAddress,
    ) -> api::SubmitTxResponse {
        // Construct sender receipt.
        let mut sender_tx_receipt = api::SenderTxReceipt::new();
        sender_tx_receipt.set_key_image_list(tx.key_images().iter().map(Into::into).collect());
        sender_tx_receipt.set_tombstone(tx.prefix.tombstone_block);

        // Construct receiver receipts.
        let receiver_tx_receipts = tx
            .prefix
            .outputs
            .iter()
            .map(|tx_out| {
                let mut receiver_tx_receipt = api::ReceiverTxReceipt::new();
                receiver_tx_receipt.set_recipient(recipient.into());
                receiver_tx_receipt.set_tx_public_key((&tx_out.public_key).into());
                receiver_tx_receipt.set_tx_out_hash(tx_out.hash().to_vec());
                receiver_tx_receipt.set_tombstone(tx.prefix.tombstone_block);

                receiver_tx_receipt
            })
            .collect();

        // Return response.
        let mut response = api::SubmitTxResponse::new();
        response.set_sender_tx_receipt(sender_tx_receipt);
        response.set_receiver_tx_receipt_list(receiver_tx_receipts.into());
        response
    }

    /// Get at status report for the slam
    ///
    /// Returns None if no slam is currently in progress.
    pub fn get_status(&self) -> Option<SlamStatus> {
        // Note: There is no lock here, so these reads are slightly racy,
        // but the target_num_tx doesn't change once slam is started, and the
        // other one is tracking the progress of another thread anyways, so this seems
        // fine.
        match self.phase.load(Ordering::SeqCst) {
            SlamState::NOT_CURRENTLY_SLAMMING => None,
            SlamState::CONNECTING => Some(SlamStatus::Connecting),
            SlamState::PREPARING_UTXOS => Some(SlamStatus::PreparingUtxos(
                self.num_prepared_utxos.load(Ordering::SeqCst),
                self.target_num_tx.load(Ordering::SeqCst),
            )),
            SlamState::SUBMITTING_TRANSACTIONS => Some(SlamStatus::SubmittingTxs(
                self.num_submitted_txs.load(Ordering::SeqCst),
                self.target_num_tx.load(Ordering::SeqCst),
            )),
            other => panic!("unexpected state: phase = {}", other),
        }
    }

    /// Request the currently running slam (if any) to stop
    /// When it stops, this flag will be reset, so it does not prevent
    /// subsequent slams from happening.
    pub fn request_stop(&self) {
        self.stop_requested.store(true, Ordering::SeqCst);
    }
}

/// An enum which describes our progress in the slam task
/// This can be displayed in a human-readable way.
#[derive(Clone, Debug, Display)]
pub enum SlamStatus {
    /// Step 1: Connecting to consensus
    Connecting,
    /// Step 2: Preparing UTXOs: {0}/{1}
    PreparingUtxos(u32, u32),
    /// Step 3: Submitting Txs: {0}/{1}
    SubmittingTxs(u32, u32),
}

/// This guard object is used in the start slam function to:
/// * Ensure that another thread does not start slam concurrently with us
/// * Ensure that we reset the state variables correctly, even if we return an
///   error
///
/// To do this, it:
/// * Atomically compares and swaps phase 1 for phase 0, returning an error if 0
///   is not the current phase
/// * Stores 0 to all variables, setting the phase last, when it is dropped.
struct SlamStateGuard<'a> {
    state: &'a SlamState,
    logger: &'a Logger,
}

impl<'a> SlamStateGuard<'a> {
    fn new(state: &'a SlamState, logger: &'a Logger) -> Result<Self, String> {
        if state
            .phase
            .compare_exchange(
                SlamState::NOT_CURRENTLY_SLAMMING,
                SlamState::CONNECTING,
                Ordering::SeqCst,
                Ordering::SeqCst,
            )
            .is_err()
        {
            return Err("Slam already in progress".to_owned());
        }
        state.num_prepared_utxos.store(0, Ordering::SeqCst);
        state.num_submitted_txs.store(0, Ordering::SeqCst);

        Ok(Self { state, logger })
    }
}

impl<'a> Drop for SlamStateGuard<'a> {
    fn drop(&mut self) {
        self.state.num_prepared_utxos.store(0, Ordering::SeqCst);
        self.state.num_submitted_txs.store(0, Ordering::SeqCst);
        self.state
            .phase
            .store(SlamState::NOT_CURRENTLY_SLAMMING, Ordering::SeqCst);
        // Set stop requested to false to ensure that we can start a slam
        // next time
        self.state.stop_requested.store(false, Ordering::SeqCst);
        log::debug!(self.logger, "slam state guard dropped");
    }
}
