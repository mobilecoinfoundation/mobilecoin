// Copyright (c) 2018-2022 The MobileCoin Foundation

//! This module creates a faucet "worker". It consists of a worker thread,
//! and a handle to the worker thread, which can be used to asynchronously get
//! the output of the worker.
//!
//! The worker ensures that the faucet is ready for operation by making self-
//! payments that split TxOut's if the number of pre-split TxOut's falls below a
//! threshold. TxOut's that are ready to be used get added to a tokio queue.
//!
//! Other threads may dequeue UTXOs from such a queue and then use them.
//! The queue also carries a one-shot channel which can give the worker a
//! SubmitTxResponse, or signal that an error occurred. The worker then follows
//! up on what happens with the UTXO, and eventually requeues it if the
//! transaction doesn't resolve successfully.
//!
//! The worker uses its own thread, but uses async-friendly tokio primitives.
//! The worker does not require to be launched from the context of a tokio
//! runtime.

#![allow(clippy::assertions_on_constants)]

use api::{
    external::PublicAddress, mobilecoind_api_grpc::MobilecoindApiClient, SubmitTxResponse,
    TxStatus, UnspentTxOut,
};
use displaydoc::Display;
use mc_common::logger::{log, o, Logger};
use mc_mobilecoind_api as api;
use mc_transaction_core::{
    constants::{MAX_INPUTS, MAX_OUTPUTS},
    ring_signature::KeyImage,
    TokenId,
};
use std::{
    cmp::min,
    collections::{hash_map::Entry, HashMap, HashSet},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::sync::oneshot::{self, error::TryRecvError};

const MAX_OUTPUTS_USIZE: usize = MAX_OUTPUTS as usize;

/// A record the worker hands to faucet threads about a UTXO they can use.
/// It expects to be notified if the UTXO is successfully submitted.
/// If the one-shot sender is dropped, the worker assumes that there was an
/// error, and the faucet dropped the UTXO, so that this UTXO can be used again
/// potentially.
pub struct UtxoRecord {
    pub utxo: UnspentTxOut,
    pub sender: oneshot::Sender<SubmitTxResponse>,
}

/// A tracker the worker keeps for UTXO records it hands to faucet threads.
pub struct UtxoTracker {
    pub utxo: UnspentTxOut,
    receiver: oneshot::Receiver<SubmitTxResponse>,
    received: Option<SubmitTxResponse>,
}

impl UtxoTracker {
    /// Make a new tracker and associated record for a given utxo
    pub fn new(utxo: UnspentTxOut) -> (Self, UtxoRecord) {
        let (sender, receiver) = oneshot::channel();

        let record = UtxoRecord {
            utxo: utxo.clone(),
            sender,
        };

        let tracker = Self {
            utxo,
            receiver,
            received: None,
        };

        (tracker, record)
    }

    // If available, get either a SubmitTxResponse, or an error indicating the
    // channel was closed, which means we had an error and couldn't submit the
    // Tx that spent this.
    pub fn poll(&mut self) -> Option<Result<SubmitTxResponse, TryRecvError>> {
        if let Some(resp) = self.received.as_ref() {
            Some(Ok(resp.clone()))
        } else {
            match self.receiver.try_recv() {
                Ok(resp) => {
                    self.received = Some(resp.clone());
                    Some(Ok(resp))
                }
                Err(TryRecvError::Empty) => None,
                Err(TryRecvError::Closed) => Some(Err(TryRecvError::Closed)),
            }
        }
    }
}

/// TokenStateReceiver holds the queue of Utxo records for a particular token
/// id, as well as other shared flags that indicate if we are out of funds etc.
pub struct TokenStateReceiver {
    receiver: async_channel::Receiver<UtxoRecord>,
    funds_depleted_flag: Arc<AtomicBool>,
    queue_depth: Arc<AtomicUsize>,
}

impl TokenStateReceiver {
    /// Get a utxo from the queue, or an error message explaining why we can't
    pub fn get_utxo(&self) -> Result<UtxoRecord, GetUtxoError> {
        loop {
            match self.receiver.try_recv() {
                Ok(utxo_record) => {
                    self.queue_depth.fetch_sub(1, Ordering::SeqCst);
                    // Check if the one-shot sender has already been closed.
                    // If it has, this means the worker dropped the tracker.
                    // This only happens if the worker decided this txo isn't unspent anymore
                    // when it polled mobilecoind.
                    // (We did not send the worker status yet.) So we should skip it and pull
                    // the next thing from the queue, since obviously a race has happened.
                    // (The worker will not spend utxos that it puts in the queue,
                    // but possibly another wallet with the same account key did.)
                    if !utxo_record.sender.is_closed() {
                        return Ok(utxo_record);
                    }
                    // Intentional fall-through to loop
                }
                Err(async_channel::TryRecvError::Empty) => {
                    return if self.funds_depleted_flag.load(Ordering::SeqCst) {
                        Err(GetUtxoError::FundsDepleted)
                    } else {
                        Err(GetUtxoError::Busy)
                    };
                }
                Err(async_channel::TryRecvError::Closed) => {
                    // This most likely means the worker thread has died
                    return Err(GetUtxoError::ChannelClosed);
                }
            }
        }
    }

    /// Get the current depth of the queue
    pub fn get_queue_depth(&self) -> usize {
        self.queue_depth.load(Ordering::SeqCst)
    }
}

/// An error which occurs when trying to get a faucet utxo from the queue
///
/// Note: The sort order here is used by the get_any_utxo function to select the
/// error which is most likely to be resolved, so that the slam worker can
/// decide whether to retry, or give up on the idea that it can get more utxos.
///
/// "less serious" errors i.e. errors that are more likely to be resolved soon,
/// should compare less, and so be listed earlier.
#[derive(Clone, Debug, Display, Eq, Ord, PartialEq, PartialOrd)]
pub enum GetUtxoError {
    /// Faucet is busy
    Busy,
    /// Funds are depleted
    FundsDepleted,
    /// Channel closed (internal error)
    ChannelClosed,
    /// Unknown Token Id
    UnknownTokenId,
}

/// The worker is responsible for pre-splitting the faucet's balance so that it
/// can handle multiple faucet requests concurrently.
///
/// It periodically calls `get_unspent_tx_out_list` for each token of interest.
/// If there are fewer than target_queue_depth TxOuts whose value is exactly
/// "target amount", then it attempts to make a self-payment which creates
/// MAX_OUTPUTS - 1 more pre-split TxOuts.
///
/// To ensure concurrent faucet requests don't try to use the same unspent
/// TxOut's as eachother, the worker puts the unspent TxOut's in a queue as they
/// appear.
///
/// Threads that have access to the worker handle can quickly try to pull an
/// unspent TxOut from the queue and send it, or find that the queue is empty
/// and give up.
pub struct Worker {
    /// The reciever queues, and flags indicating if we are out of funds, for
    /// each token id
    receivers: HashMap<TokenId, TokenStateReceiver>,

    /// The worker thread handle
    join_handle: Option<std::thread::JoinHandle<()>>,

    /// A flag which can be used to request the worker thread to join
    /// This is done by dropping the worker handle
    stop_requested: Arc<AtomicBool>,

    /// The worker poll period
    worker_poll_period: Duration,
}

impl Worker {
    /// Make a new worker object given mobilecoind connection and config info,
    /// and starts the worker thread.
    ///
    /// Arguments:
    /// * client: connection to mobilecoind
    /// * monitor_id: The monitor id for the account we are using
    /// * public_address: The public address of our monitor id, used for
    ///   self-payments
    /// * minimum_fees: The minimum fees for each token we are interested in
    /// * target_amounts: The target value for UTXOs of each token we are
    ///   interested in
    /// * target_queue_depth: The target depth of the queue for each token ID.
    ///   If a queue falls below this number the worker attempts a split Tx.
    /// * worker_poll_period: A lower bound on how often the worker should poll
    /// * logger
    ///
    /// Returns the Worker handle object, which contains the thread handle, and
    /// receives the output of the worker thread.
    pub fn new(
        client: MobilecoindApiClient,
        monitor_id: Vec<u8>,
        public_address: PublicAddress,
        minimum_fees: HashMap<TokenId, u64>,
        target_amounts: HashMap<TokenId, u64>,
        target_queue_depth: usize,
        worker_poll_period: Duration,
        logger: &Logger,
    ) -> Worker {
        let mut worker_token_states = Vec::<WorkerTokenState>::default();
        let mut receivers = HashMap::<TokenId, TokenStateReceiver>::default();

        for (token_id, value) in target_amounts.iter() {
            let minimum_fee_value = minimum_fees
                .get(token_id)
                .unwrap_or_else(|| panic!("Missing minimum fee for {}", token_id));
            let (state, receiver) = WorkerTokenState::new(*token_id, *minimum_fee_value, *value);
            worker_token_states.push(state);
            receivers.insert(*token_id, receiver);
        }

        let stop_requested = Arc::new(AtomicBool::default());
        let thread_stop_requested = stop_requested.clone();

        let logger = logger.new(o!("thread" => "worker"));
        let join_handle = Some(std::thread::spawn(move || {
            Self::worker_thread_entry_point(
                worker_token_states,
                thread_stop_requested,
                client,
                monitor_id,
                public_address,
                target_queue_depth,
                worker_poll_period,
                logger,
            )
        }));

        Worker {
            receivers,
            join_handle,
            stop_requested,
            worker_poll_period,
        }
    }

    /// The entrypoint for the worker thread.
    /// First, wait for account to sync in mobilecoind.
    /// Then enter a loop where we check stop_requested, poll each token id for
    /// activity, and sleep for a bit.
    fn worker_thread_entry_point(
        mut worker_token_states: Vec<WorkerTokenState>,
        stop_requested: Arc<AtomicBool>,
        client: MobilecoindApiClient,
        monitor_id: Vec<u8>,
        public_address: PublicAddress,
        target_queue_depth: usize,
        worker_poll_period: Duration,
        logger: Logger,
    ) {
        // First wait for account to sync
        // Get the "initial" ledger block count
        let block_count = loop {
            match client.get_ledger_info(&Default::default()) {
                Ok(resp) => break resp.block_count,
                Err(err) => {
                    log::error!(logger, "Could not get ledger info: {:?}", err);
                }
            }
            std::thread::sleep(Duration::from_millis(1000));
        };
        log::info!(logger, "Ledger is at block_count = {}", block_count);

        // Now wait for monitor state to at least pass this point
        loop {
            let mut req = api::GetMonitorStatusRequest::new();
            req.set_monitor_id(monitor_id.clone());
            match client.get_monitor_status(&req) {
                Ok(resp) => {
                    let monitor_block_count = resp.get_status().next_block;
                    if monitor_block_count >= block_count {
                        log::info!(
                            logger,
                            "Monitor has synced to block count {}",
                            monitor_block_count
                        );
                        break;
                    }
                }
                Err(err) => {
                    log::error!(logger, "Could not get monitor status: {:?}", err);
                }
            }
            std::thread::sleep(Duration::from_millis(1000));
        }

        // Poll all token ids looking for activity, then sleep for a bit
        loop {
            if stop_requested.load(Ordering::SeqCst) {
                log::info!(logger, "Worker: stop was requested");
                break;
            }
            for state in worker_token_states.iter_mut() {
                if let Err(err_str) = state.poll(
                    &client,
                    &monitor_id,
                    &public_address,
                    target_queue_depth,
                    &logger,
                ) {
                    log::error!(logger, "token id {}: {}", state.token_id, err_str);
                }
            }
            log::trace!(logger, "Worker sleeping");
            std::thread::sleep(worker_poll_period);
        }
    }

    /// Get a utxo with the target value, for a given token id.
    /// This pulls a utxo from the queue, and the recipient has responsbility
    /// to either successfully send the TxOut and use its oneshot::Sender to
    /// report the result from consensus, or, to drop the oneshot::Sender,
    /// reporting an error using the TxOut.
    pub fn get_utxo(&self, token_id: TokenId) -> Result<UtxoRecord, GetUtxoError> {
        if let Some(receiver) = self.receivers.get(&token_id) {
            receiver.get_utxo()
        } else {
            Err(GetUtxoError::UnknownTokenId)
        }
    }

    /// Get any available utxo. This is only used by slam, which just wants
    /// utxos and doesn't particularly care about token ids.
    ///
    /// The error returned is the "least serious" error, i.e. most likely to be
    /// resolved, that prevents us from getting tokens of one of the token ids.
    /// This helps slam worker decide whether to try again later or give up.
    pub fn get_any_utxo(&self) -> Result<UtxoRecord, GetUtxoError> {
        let mut least_serious_error = None;
        for (_, receiver) in self.receivers.iter() {
            match receiver.get_utxo() {
                Ok(utxo) => return Ok(utxo),
                Err(err) => {
                    if let Some(prev_err) = least_serious_error {
                        least_serious_error = Some(min(prev_err, err));
                    } else {
                        least_serious_error = Some(err);
                    }
                }
            }
        }
        // If there are no receivers, then least_serious_error will still be None,
        // so let's return UnknownTokenId
        Err(least_serious_error.unwrap_or(GetUtxoError::UnknownTokenId))
    }

    /// Get the depths of all of the queues
    pub fn get_queue_depths(&self) -> HashMap<TokenId, usize> {
        self.receivers
            .iter()
            .map(|(token_id, receiver)| (*token_id, receiver.get_queue_depth()))
            .collect()
    }

    /// Get the configured worker poll period
    pub fn get_worker_poll_period(&self) -> Duration {
        self.worker_poll_period
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        if let Some(handle) = self.join_handle.take() {
            self.stop_requested.store(true, Ordering::SeqCst);
            handle.join().expect("failed to join worker thread");
        }
    }
}

struct WorkerTokenState {
    // The token id being tracked
    token_id: TokenId,
    // the minimum fee value for this token id
    minimum_fee_value: u64,
    // The target value of UTXOS for this token id
    target_value: u64,
    // The most recently known set of UTXOS for this token id
    // When we get a new UTXO from mobilecoind, we track it using this cache.
    // The tracker contains a one-shot channel that the other side can use to
    // let us know what happens with this UTXO.
    // UTXOs are added here at the same time they are queued. As long as a UTXO
    // is in this cache, we won't requeue it, to avoid two threads spending
    // the same UTXO concurrently.
    known_utxos: HashMap<KeyImage, UtxoTracker>,
    // The queue of UTXOs with the target value
    sender: async_channel::Sender<UtxoRecord>,
    // If we submit a rebalancing transaction, the response we can use to track it
    // Only one of these will be used at a time, and split txs cannot be submitted
    // while this is in-flight.
    in_flight_rebalancing_tx_state: Option<SubmitTxResponse>,
    // If we submit a split transaction, the response we can use to track it
    // There maybe up to 16 of these in flight at a time.
    in_flight_split_tx_states: HashMap<KeyImage, SubmitTxResponse>,
    // If we submit a defragmentation transaction, the response we can use to track it
    // Only one of these will be used at a time, and this only chooses from the lesser
    // of the utxos.
    in_flight_defragmentation_tx_state: Option<SubmitTxResponse>,
    // Track the key images associated to utxos int he defragmentation tx in flight (if any)
    in_flight_defragmentation_key_images: HashSet<KeyImage>,
    // A shared flag we use to signal if have insufficient funds for this token id
    funds_depleted: Arc<AtomicBool>,
    // A shared counter used to indicate roughly how many items are in the queue
    queue_depth: Arc<AtomicUsize>,
}

impl WorkerTokenState {
    // Create a new WorkerTokenState and matching TokenStateReceiver.
    //
    // Arguments:
    // * token_id: The token id this state is tracking
    // * minimum_fee_value: The minimum fee for this token id
    // * target_value: The target value of faucet utxos for this token id
    //
    // Returns:
    // * WorkerTokenState, which is held by the worker which calls poll periodically
    // * TokenStateReceiver, which is held by the worker thread handle, which can
    //   get the output stream of the worker, for this token id.
    fn new(
        token_id: TokenId,
        minimum_fee_value: u64,
        target_value: u64,
    ) -> (WorkerTokenState, TokenStateReceiver) {
        let (sender, receiver) = async_channel::unbounded::<UtxoRecord>();

        let funds_depleted_flag = Arc::new(AtomicBool::default());
        let funds_depleted = funds_depleted_flag.clone();

        let queue_depth = Arc::new(AtomicUsize::default());
        let queue_depth_counter = queue_depth.clone();

        (
            Self {
                token_id,
                minimum_fee_value,
                target_value,
                known_utxos: Default::default(),
                sender,
                in_flight_rebalancing_tx_state: None,
                in_flight_split_tx_states: Default::default(),
                in_flight_defragmentation_tx_state: None,
                in_flight_defragmentation_key_images: Default::default(),
                funds_depleted,
                queue_depth,
            },
            TokenStateReceiver {
                receiver,
                funds_depleted_flag,
                queue_depth: queue_depth_counter,
            },
        )
    }

    // Poll a given token for activity.
    //
    // (1) Check up on old utxos, checking if they were eventually submitted
    // or not, and if those submissions were successful. If their submissions
    // resolve, it purges them from its cache so that they can be found again
    // and resubmitted if necessary.
    // (2) Get the UTXO list for this token, checks it for new UTXOs, and
    // sends things to the channel if we do find new things.
    // (3) Check if we have enough pre-split Txos, check on in-flight Tx's trying
    // to fix this, and maybe submit a new splitting Tx.
    // (this is maybe_send_split_txs)
    // (4) Check if we should send a defragmentation Tx.
    // (this is maybe_send_defragmentation_tx)
    //
    // Returns a string which should be logged if e.g. we encounter an RPC error
    fn poll(
        &mut self,
        client: &MobilecoindApiClient,
        monitor_id: &[u8],
        public_address: &PublicAddress,
        target_queue_depth: usize,
        logger: &Logger,
    ) -> Result<(), String> {
        // (1) For each known utxo already queued, check if it was sent in a
        // transaction and if so what the status is
        self.known_utxos.retain(|_key_image, tracker| {
            if let Some(status) = tracker.poll() {
                // If poll returned Some, then we either got a SubmitTxResponse or an error
                if let Ok(resp) = status {
                    // It was successfully submitted to the network, let's ask mobilecoind what's
                    // happened. If it's still in-flight we should retain it, if it has resolved,
                    // we should drop it from our records.
                    is_tx_still_in_flight(client, &resp, "Faucet", logger)
                } else {
                    // The oneshot receiver resolved in an error, this means, the other side dropped
                    // this channel, without reporting a SubmitTxResponse. This
                    // means there was an error building or submitting the Tx,
                    // and the other side has now dropped this UnspentTxOut. We should requeue it
                    // so that it can be eventually be spent, and for now we should just purge it.
                    false
                }
            } else {
                // Still in the queue as far as we know
                true
            }
        });

        // Now, get a fresh unspent tx out list associated to this token
        let mut resp = {
            let mut req = api::GetUnspentTxOutListRequest::new();
            req.token_id = *self.token_id;
            req.monitor_id = monitor_id.to_vec();

            client.get_unspent_tx_out_list(&req).map_err(|err| {
                format!(
                    "Could not get unspent txout list for token id = {}: {}",
                    self.token_id, err
                )
            })?
        };

        // (2) check all the reported utxos.
        // If it is new and has the target value, then queue it
        let mut output_list_key_images = HashSet::<KeyImage>::default();

        for utxo in resp.output_list.iter() {
            // Sanity check the token id
            if utxo.token_id != self.token_id {
                continue;
            }

            // Only utxos of exactly the target value are elligible to go in the queue.
            // The others are "non-target-value utxos" which are candidates to be used
            // (later) in split transactions that produce more target-value utxos,
            // if the queue is getting empty.
            if utxo.value != self.target_value {
                continue;
            }

            let key_image: KeyImage = utxo
                .get_key_image()
                .try_into()
                .map_err(|err| format!("invalid key image: {}", err))?;
            if let Entry::Vacant(e) = self.known_utxos.entry(key_image) {
                // We found a utxo not in the cache, let's queue and add to cache
                log::trace!(
                    logger,
                    "Queueing a utxo: key_image = {:?}, value = {}",
                    key_image,
                    utxo.value
                );
                let (tracker, record) = UtxoTracker::new(utxo.clone());
                // Add to queue depth before push, because we subtract after pop
                self.queue_depth.fetch_add(1, Ordering::SeqCst);
                if self.sender.try_send(record).is_err() {
                    panic!("Queue was closed before worker thread was joined, this is an unexpected program state");
                }
                e.insert(tracker);
            }

            // Add the key image of this utxo to a set, this helps us purge the cache
            output_list_key_images.insert(key_image);
        }

        // Remove any known utxos that no longer exist in the response list
        // That is, remove any utxo whose key image wasn't added to
        // output_list_key_images before. (This also drops the one-shot receiver,
        // and so can tell the other side not to bother sending this utxo if they get
        // it from the queue.)
        self.known_utxos
            .retain(|key_image, _tracker| output_list_key_images.contains(key_image));

        // Steps 3 and 4 consider whether to submit any txs.
        // First update the status of in-flight txs
        self.check_on_in_flight_txs(client, logger);

        // Get all the "non-target-value" utxos of this token id.
        let mut non_target_value_utxos: Vec<_> = resp
            .take_output_list()
            .into_iter()
            .filter(|utxo| utxo.token_id == self.token_id && utxo.value != self.target_value)
            .collect();
        // Sort in descending order of value
        non_target_value_utxos.sort_by(|a, b| b.value.cmp(&a.value));

        // Take the MAX_OUTPUTS largest utxos, these will be passed to
        // "maybe_send_split_txs" for consideration.
        let top_utxos =
            &non_target_value_utxos[0..non_target_value_utxos.len().min(MAX_OUTPUTS_USIZE)];

        // (3) Maybe send split txs using the top several UTXOs
        //
        // When we are doing parallel split tx's, i.e. allowing to have multiple
        // split tx's in flight at a given time so that we can produce target-value
        // TxOut's faster, there is a decision tree here, around whether to send
        // a rebalancing Tx or a bunch of split txs.
        //
        // (a) If we are shooting to have 16 split tx's in flight at any time,
        //     but almost all of our balance is in one TxOut, then there won't be
        //     any way to split up this balance in parallel. So we have a criteria
        //     to decide if this is the case, and if so, spend the 16 largest TxOuts
        //     and produce 16 equal outputs. While this rebalancing Tx is in flight,
        //     nothing else will be submitted.
        // (b) If no such Tx is in flight and that criteria does not trigger it,
        //     then there are 16 similarly large TxOuts.
        //     At this point we check the queue depth, and decide if we need to try
        //     to make more TxOut's of the target value for the queue.
        //     To do this, we take one of the 16 largest TxOut's and spend it in a
        //     way that splits off 15 TxOut's of the target value, returning the rest
        //     as change. This split tx is added to a list of at most 16 in flight
        //     split tx's. We only take a TxOut for this purpose if it is not already
        //     the subject of an in-flight split tx. Also, before doing anything
        //     we check up on the in-flight split tx's.
        let funds_are_depleted_in_top_utxos = self.maybe_send_split_txs(
            top_utxos,
            client,
            monitor_id,
            public_address,
            target_queue_depth,
            logger,
        )?;

        // (4) Maybe send a defragmentation tx, if funds are depleted in top utxos
        let defragmentation_in_progress = if funds_are_depleted_in_top_utxos {
            self.maybe_send_defragmentation_tx(
                &non_target_value_utxos,
                client,
                monitor_id,
                public_address,
                logger,
            )?
        } else {
            false
        };

        // If more split txs are needed but we can't find funds, and no defragmentation
        // is in progress, then funds are depleted. Otherwise, funds are not
        // depleted. Update the status.
        if funds_are_depleted_in_top_utxos && !defragmentation_in_progress {
            let prev_value = self.funds_depleted.swap(true, Ordering::SeqCst);
            if !prev_value {
                log::info!(logger, "Funds depleted on {}", self.token_id);
            }
        } else {
            let prev_value = self.funds_depleted.swap(false, Ordering::SeqCst);
            if prev_value {
                log::info!(logger, "Funds no longer depleted on {}", self.token_id);
            }
        }

        Ok(())
    }

    // Before parts 3 and 4, unconditionally update the status of any in-flight Tx
    // and collect any that have resolved.
    fn check_on_in_flight_txs(&mut self, client: &MobilecoindApiClient, logger: &Logger) {
        // Check on rebalancing Tx
        if let Some(prev_tx) = self.in_flight_rebalancing_tx_state.as_ref() {
            if !is_tx_still_in_flight(client, prev_tx, "Rebalancing", logger) {
                // At this point, the previous in-flight tx resolved somehow and if it was an
                // error we logged it
                self.in_flight_rebalancing_tx_state = None;
            }
        }

        // Check on split Tx's
        self.in_flight_split_tx_states
            .retain(|_key_image, submit_tx_response| {
                is_tx_still_in_flight(client, submit_tx_response, "Split", logger)
            });

        // Check on defragmentation Tx
        if let Some(prev_tx) = self.in_flight_defragmentation_tx_state.as_ref() {
            if !is_tx_still_in_flight(client, prev_tx, "Defragmentation", logger) {
                // At this point, the previous in-flight tx resolved somehow and if it was an
                // error we logged it
                self.in_flight_defragmentation_tx_state = None;
                self.in_flight_defragmentation_key_images = Default::default();
            }
        }
    }

    // This handles part 3 of the polling loop, where we maybe submit split or
    // rebalancing txs.
    //
    // * Check on the "rebalancing" Tx process, which tries to make sure that the
    //   top utxos are similar in value, and rebalances them if not.
    // * Then, if we don't rebalance the top utxos, and we need more target value
    //   utxos, make split tx's off of the top utxos in parallel (except those
    //   already being split this way)
    //
    // Returns:
    // * An error if we get a mobilecoind error
    // * True if funds are depleted among the top utxos
    // * False if funds are not depleted among the top utxos
    //
    // Assumes:
    // top_utxos is sorted in decreasing order by value and only
    // contains the right token id, and has the highest value MAX_OUTPUTS utxos.
    fn maybe_send_split_txs(
        &mut self,
        top_utxos: &[UnspentTxOut],
        client: &MobilecoindApiClient,
        monitor_id: &[u8],
        public_address: &PublicAddress,
        target_queue_depth: usize,
        logger: &Logger,
    ) -> Result<bool, String> {
        assert!(
            top_utxos.len() <= MAX_OUTPUTS_USIZE,
            "too many top utxos, this is a logic error"
        );

        // A UTXO whose value is less than this is not interesting to use as a split tx,
        // since we can't produce enough target value utxos, and pay a fee.
        let smallest_interesting_split_tx_value =
            self.target_value * (MAX_OUTPUTS - 1) + self.minimum_fee_value;

        // If there is an in-flight rebalancing Tx, wait for it to land.
        // Funds are not depleted.
        if self.in_flight_rebalancing_tx_state.is_some() {
            return Ok(false);
        }

        let total_value = top_utxos.iter().map(|utxo| utxo.value).sum::<u64>();
        if total_value < self.minimum_fee_value {
            // Funds are depleted
            return Ok(true);
        }
        let avg_value = (total_value - self.minimum_fee_value) / MAX_OUTPUTS;

        // (a) Check if rebalancing makes sense to attempt.
        // This is the case if:
        // * The average value is at least the smallest interesting split tx value,
        //   otherwise rebalancing will produce uninteresting txos.
        // * Things are currently somewhat out of whack -- there are less than
        //   NUM_OUTPUTS utxos, or the largest is > 2x the value of the smallest.
        if avg_value >= smallest_interesting_split_tx_value
            && top_utxos.get(0).map(|utxo| utxo.value).unwrap_or(0)
                > 2 * top_utxos
                    .get(MAX_OUTPUTS_USIZE - 1)
                    .map(|utxo| utxo.value)
                    .unwrap_or(0)
        {
            // Note: If we rebalance, nothing else will happen to these UTXOs
            // until the rebalancing UTXO lands, and after it does,
            // we know the criteria will be satisfied in the next pass.
            // Because:
            // * Every other UTXO is less than the least of these top utxos, so they will
            //   also be less than the average. So the TXOs produced by this rebalancing
            //   will be the top utxos after this rebalancing Tx lands, and they are all
            //   nearly equal.
            // * The avg_value also will not change much.
            //
            // So we will likely not meet the criteria after this rebalancing
            // operation, and there will not be an infinite loop of rebalancing
            // operations which don't refill the queue.
            log::info!(
                logger,
                "Attempting a rebalancing Tx for split tx parallelism on token id {}",
                self.token_id
            );

            // Check if any of these UTXOs were used by an in-flight split tx or
            // defrag tx. If so then we
            // should back off and wait for it to clear and re-evaluate.
            if top_utxos.iter().any(|utxo| {
                let key_image = utxo.get_key_image().try_into().unwrap();
                self.key_image_is_in_flight(&key_image)
            }) {
                log::info!(
                    logger,
                    "Backing off before sending a rebalancing tx {}",
                    self.token_id
                );
                return Ok(false);
            }

            // Generate an outlay
            // We will repeat this outlay MAX_OUTPUTS - 1 times
            // (-1 is for a change output, which might be slightly larger than avg_value, or
            // less due to fees)
            let mut outlay = api::Outlay::new();
            outlay.set_receiver(public_address.clone());
            outlay.set_value(avg_value);

            // Generate a Tx
            // Note: This will fail if MAX_INPUTS < MAX_OUTPUTS, but right now MAX_INPUTS =
            // MAX_OUTPUTS.
            assert!(
                MAX_INPUTS >= MAX_OUTPUTS,
                "MAX_INPUTS < MAX_OUTPUTS, this rebalancing code needs rework"
            );
            let mut req = api::GenerateTxRequest::new();
            req.set_sender_monitor_id(monitor_id.to_vec());
            req.set_token_id(*self.token_id);
            req.set_input_list(top_utxos.iter().cloned().collect());
            req.set_outlay_list(vec![outlay; MAX_OUTPUTS_USIZE - 1].into());

            let mut resp = client
                .generate_tx(&req)
                .map_err(|err| format!("Failed to generate rebalancing tx: {}", err))?;

            // Submit the Tx
            let mut req = api::SubmitTxRequest::new();
            req.set_tx_proposal(resp.take_tx_proposal());
            let submit_tx_response = client
                .submit_tx(&req)
                .map_err(|err| format!("Failed to submit rebalancing tx: {}", err))?;

            // This lets us keep tabs on when this split payment has resolved, so that we
            // can avoid sending another payment until it does
            self.in_flight_rebalancing_tx_state = Some(submit_tx_response);

            return Ok(false);
        }

        // (b) Check if more utxos are actually needed right now, and if so,
        // create them in parallel off of the top utxos.
        // We know rebalancing is not in progress and was not attempted,
        // so hopefully all (or at least some) of these are above the
        // smallest_interesting_split_tx_value.
        //
        // Hopefully, this does not cause (a) to be re-entered next time, since
        // all of these utxos will decrease by smallest_interesting_split_tx_value
        // or so, so they will all still be similar in value, and next time around
        // we can do the parallel split again.
        if self.queue_depth.load(Ordering::SeqCst) < target_queue_depth {
            log::debug!(logger, "Attempting to split on token id {}", self.token_id);

            // Generate an outlay
            // We will repeat this outlay MAX_OUTPUTS - 1 times
            // (-1 is for a change output)
            // for each split tx we submit.
            let mut outlay = api::Outlay::new();
            outlay.set_receiver(public_address.clone());
            outlay.set_value(self.target_value);

            // Try to split any top-value utxos that are not already in-flight.
            for utxo in top_utxos {
                // If the value is less than fee + target, then we can't do even one Tx
                if utxo.value < self.minimum_fee_value + self.target_value {
                    continue;
                }
                // If this utxo is already in-flight, skip it
                let key_image: KeyImage = utxo.get_key_image().try_into().unwrap();
                if self.key_image_is_in_flight(&key_image) {
                    continue;
                }

                // See how many target_value UTXOs we can create, capping at MAX_OUTPUTS - 1
                let num_target_value_utxos = core::cmp::min(
                    MAX_OUTPUTS - 1,
                    (utxo.value - self.minimum_fee_value) / self.target_value,
                ) as usize;

                // Generate a Tx
                let mut req = api::GenerateTxRequest::new();
                req.set_sender_monitor_id(monitor_id.to_vec());
                req.set_token_id(*self.token_id);
                req.set_input_list(vec![utxo.clone()].into());
                req.set_outlay_list(vec![outlay.clone(); num_target_value_utxos].into());

                let mut resp = client
                    .generate_tx(&req)
                    .map_err(|err| format!("Failed to generate split tx: {}", err))?;

                // Submit the Tx
                let mut req = api::SubmitTxRequest::new();
                req.set_tx_proposal(resp.take_tx_proposal());
                let submit_tx_response = client
                    .submit_tx(&req)
                    .map_err(|err| format!("Failed to submit split tx: {}", err))?;

                // This lets us keep tabs on when this split payment has resolved, so that we
                // can avoid sending another payment until it does
                self.in_flight_split_tx_states
                    .insert(key_image, submit_tx_response);
            }

            // If at least one thing is now in-flight then funds are not depleted.
            return Ok(self.in_flight_split_tx_states.is_empty());
        }

        // We don't report funds depleted if the queue doesn't need refilling.
        Ok(false)
    }

    // This maybe sends a "defragmentation tx", which means taking the largest
    // utxos which are not in-flight, opportunistically splitting off
    // some target-value TxOuts if possible, and sending the rest back as a
    // change TxOut.
    //
    // Returns:
    // * An error if we get a mobilecoind error
    // * True if a defragmentation tx is in flight
    // * False if a defragmentation tx is not in flight and could not be built
    //
    // Assumes:
    // utxos is sorted in decreasing order by value and only
    // contains the right token id.
    fn maybe_send_defragmentation_tx(
        &mut self,
        utxos: &[UnspentTxOut],
        client: &MobilecoindApiClient,
        monitor_id: &[u8],
        public_address: &PublicAddress,
        logger: &Logger,
    ) -> Result<bool, String> {
        // First check on the in-flight defragmentation tx, if one is in-flight
        // then let's wait for it to land.
        if self.in_flight_defragmentation_tx_state.is_some() {
            return Ok(true);
        }

        // We can only use at most MAX_INPUTS of these utxos at once
        // Avoid anything that's somehow part of an in-flight tx
        let (key_images, selected_utxos): (HashSet<KeyImage>, Vec<_>) = utxos
            .iter()
            .filter_map(|utxo| {
                let key_image: KeyImage = utxo.get_key_image().try_into().unwrap();
                if self.key_image_is_in_flight(&key_image) {
                    None
                } else {
                    Some((key_image, utxo.clone()))
                }
            })
            .take(MAX_INPUTS as usize)
            .unzip();

        let total_value_skip_first = selected_utxos
            .iter()
            .skip(1)
            .map(|utxo| utxo.value)
            .sum::<u64>();

        // If the total value after the largest is less than the fee, then even
        // if we do this, the change txo will have less value than the largest
        // one we had before this, so this is pointless, we just have dust now.
        if total_value_skip_first <= self.minimum_fee_value {
            return Ok(false);
        }

        log::info!(
            logger,
            "Attempting to defragment on token id: {}",
            self.token_id
        );
        let total_value = total_value_skip_first + selected_utxos[0].value;

        // See how many target_value UTXOs we can create, capping at MAX_OUTPUTS - 1
        let num_target_value_utxos = core::cmp::min(
            MAX_OUTPUTS - 1,
            (total_value - self.minimum_fee_value) / self.target_value,
        ) as usize;

        // Generate an outlay
        let mut outlay = api::Outlay::new();
        outlay.set_receiver(public_address.clone());
        outlay.set_value(self.target_value);

        // Generate a Tx
        let mut req = api::GenerateTxRequest::new();
        req.set_sender_monitor_id(monitor_id.to_vec());
        req.set_token_id(*self.token_id);
        req.set_input_list(selected_utxos.iter().cloned().collect());
        req.set_outlay_list(vec![outlay; num_target_value_utxos].into());

        let mut resp = client
            .generate_tx(&req)
            .map_err(|err| format!("Failed to generate split tx: {}", err))?;

        // Submit the Tx
        let mut req = api::SubmitTxRequest::new();
        req.set_tx_proposal(resp.take_tx_proposal());
        let submit_tx_response = client
            .submit_tx(&req)
            .map_err(|err| format!("Failed to submit split tx: {}", err))?;

        // This lets us keep tabs on when this split payment has resolved, so that we
        // can avoid sending another payment until it does
        self.in_flight_defragmentation_tx_state = Some(submit_tx_response);
        self.in_flight_defragmentation_key_images = key_images;

        Ok(true)
    }

    // Check if a key image is part of an in-flight transaction
    fn key_image_is_in_flight(&self, key_image: &KeyImage) -> bool {
        self.in_flight_split_tx_states.contains_key(key_image)
            || self
                .in_flight_defragmentation_key_images
                .contains(key_image)
    }
}

/// Check if a given tx is still in-flight.
/// Logs an error if something strange happened
///
/// Arguments:
/// * client: connection to mobilecoind
/// * tx: the submit tx response
/// * context: The context of this tx, used for logging
/// * logger
///
/// Returns true if the tx is still (potentially) in-flight, false if it has
/// resolved now (either successfully or in an error)
fn is_tx_still_in_flight(
    client: &MobilecoindApiClient,
    tx: &SubmitTxResponse,
    context: &str,
    logger: &Logger,
) -> bool {
    match client.get_tx_status_as_sender(tx) {
        Ok(resp) => {
            if resp.status == TxStatus::Unknown {
                return true;
            }
            if resp.status != TxStatus::Verified {
                log::error!(
                    logger,
                    "{} Tx ended with status: {:?}",
                    context,
                    resp.status
                );
            }
            // Whether successful or an error, the Tx has resolved now
            false
        }
        Err(err) => {
            log::error!(logger, "Failed getting {} Tx status: {}", context, err);
            // We still don't know the status, so it may still be in-flight
            true
        }
    }
}
