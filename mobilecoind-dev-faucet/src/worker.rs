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

use mc_common::logger::{log, Logger};
use mc_mobilecoind_api::{
    external::PublicAddress, mobilecoind_api_grpc::MobilecoindApiClient, SubmitTxResponse,
    TxStatus, UnspentTxOut,
};
use mc_transaction_core::{constants::MAX_OUTPUTS, ring_signature::KeyImage, TokenId};
use protobuf::RepeatedField;
use std::{
    collections::{HashMap, HashSet},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use tokio::sync::{
    mpsc::{self, UnboundedReceiver, UnboundedSender},
    oneshot::{self, error::TryRecvError},
};

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
            utxo: utxo.clone(),
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

/// The worker is responsible for pre-splitting the faucet's balance so that it
/// can handle multiple faucet requests concurrently.
///
/// It periodically calls `get_unspent_tx_out_list` for each token of interest.
/// If there are fewer than THRESHOLD TxOuts whose value is exactly "faucet
/// amount", then it attempts to make a self-payment which creates THRESHOLD
/// more pre-split TxOuts.
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
    receivers: HashMap<TokenId, (Mutex<mpsc::UnboundedReceiver<UtxoRecord>>, Arc<AtomicBool>)>,

    /// The worker thread handle
    join_handle: Option<std::thread::JoinHandle<()>>,

    /// A flag which can be used to request the worker thread to join
    /// This is done by dropping the worker handle
    stop_requested: Arc<AtomicBool>,
}

impl Worker {
    // If we have fewer than this many outstanding UTXOs of the target value,
    // then we start trying to split our balance into more UTXOs.
    //
    // Note: This could be a config parameter perhaps
    const THRESHOLD_QUEUE_DEPTH: usize = 20;

    // Determines frequency with which the worker thread polls for updates
    const WORKER_POLL_PERIOD: Duration = Duration::from_millis(100);

    /// Get a utxo with the target value, for a given token id.
    /// This pulls a utxo from the queue, and the recipient has responsbility
    /// to either successfully send the TxOut and use its oneshot::Sender to
    /// report the result from consensus, or, to drop the oneshot::Sender,
    /// reporting an error using the TxOut.
    pub fn get_utxo(&self, token_id: TokenId) -> Result<UtxoRecord, String> {
        if let Some((receiver, depleted_flag)) = self.receivers.get(&token_id) {
            let mut receiver = receiver.lock().expect("mutex poisoned");
            match receiver.try_recv() {
                Ok(result) => Ok(result),
                Err(mpsc::error::TryRecvError::Empty) => {
                    if depleted_flag.load(Ordering::SeqCst) {
                        Err("faucet is depleted".to_string())
                    } else {
                        Err("faucet is busy".to_string())
                    }
                }
                Err(mpsc::error::TryRecvError::Disconnected) => Err("internal error".to_string()),
            }
        } else {
            Err(format!("Unknown token id: {}", token_id))
        }
    }

    /// Make a new worker object given mobilecoind connection and config info,
    /// and starts the worker thread.
    ///
    /// Arguments:
    /// * client: connection to mobilecoind
    /// * monitor_id: The monitor id for the account we are using
    /// * public_address: The public address of our monitor id, used for
    ///   self-payments
    /// * faucet_amounts: The target value for UTXOs of each token we are
    ///   interested in
    /// * logger
    ///
    /// Returns the worker handle.
    pub fn new(
        client: MobilecoindApiClient,
        monitor_id: Vec<u8>,
        public_address: PublicAddress,
        faucet_amounts: HashMap<TokenId, u64>,
        logger: Logger,
    ) -> Worker {
        let mut worker_token_states = Vec::<WorkerTokenState>::default();
        let mut receivers =
            HashMap::<TokenId, (Mutex<UnboundedReceiver<UtxoRecord>>, Arc<AtomicBool>)>::default();

        for (token_id, value) in faucet_amounts.iter() {
            let (state, receiver, depleted_flag) = WorkerTokenState::new(*token_id, *value);
            worker_token_states.push(state);
            receivers.insert(*token_id, (Mutex::new(receiver), depleted_flag));
        }

        let stop_requested = Arc::new(AtomicBool::default());
        let thread_stop_requested = stop_requested.clone();

        let join_handle = Some(std::thread::spawn(move || {
            // Poll all token ids looking for activity, then sleep for a bit
            loop {
                if thread_stop_requested.load(Ordering::SeqCst) {
                    log::info!(logger, "Worker: stop was requested");
                    break;
                }
                for state in worker_token_states.iter_mut() {
                    if let Err(err_str) = state.poll(&client, &monitor_id, &public_address, &logger)
                    {
                        log::error!(logger, "{}", err_str);
                    }
                }
                std::thread::sleep(Self::WORKER_POLL_PERIOD);
            }
        }));

        Worker {
            receivers,
            join_handle,
            stop_requested,
        }
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
    sender: UnboundedSender<UtxoRecord>,
    // If we submit a split transaction, the response we can use to track it
    in_flight_split_tx_state: Option<SubmitTxResponse>,
    // A shared flag we use to signal if have insufficient funds for this token id
    funds_depleted: Arc<AtomicBool>,
}

impl WorkerTokenState {
    // Create a new worker token state, with a given token id and target value.
    // Returns the channels to be passed to other thread, including the receiver
    // for new UtxoRecords, and the "funds depleted" flag
    fn new(
        token_id: TokenId,
        target_value: u64,
    ) -> (
        WorkerTokenState,
        UnboundedReceiver<UtxoRecord>,
        Arc<AtomicBool>,
    ) {
        let (sender, receiver) = mpsc::unbounded_channel::<UtxoRecord>();

        let funds_depleted_flag = Arc::new(AtomicBool::default());
        let funds_depleted = funds_depleted_flag.clone();

        (
            Self {
                token_id,
                target_value,
                known_utxos: Default::default(),
                sender,
                in_flight_split_tx_state: None,
                funds_depleted,
            },
            receiver,
            funds_depleted_flag,
        )
    }

    // Poll a given token for activity.
    //
    // (1) Get the UTXO list for this token, checks it for new UTXOs, and
    // sends things to the channel if we do find new things.
    // (2) Check up on old things, checking if they were eventually submitted
    // or not, and if those submissions were successful. If their submissions
    // resolve, it purges them from its cache so that they can be found again
    // and resubmitted if necessary.
    // (3) Check if we have enough pre-split Txos, and if we don't, check
    // if we already have an in-flight Tx to try to fix this. If not then it builds
    // and submits a new splitting Tx.
    //
    // Returns a string which should be logged if e.g. we encounter an RPC error
    fn poll(
        &mut self,
        client: &MobilecoindApiClient,
        monitor_id: &[u8],
        public_address: &PublicAddress,
        logger: &Logger,
    ) -> Result<(), String> {
        // First, get the unspent tx out list associated to this token
        let resp = {
            let mut req = mc_mobilecoind_api::GetUnspentTxOutListRequest::new();
            req.token_id = *self.token_id;
            req.monitor_id = monitor_id.to_vec();

            client.get_unspent_tx_out_list(&req).map_err(|err| {
                format!(
                    "Could not get unspent txout list for token id = {}: {}",
                    self.token_id, err
                )
            })?
        };

        // Now, check all the reported utxos.
        // If they have the target value, increment queue depth.
        // If they are new since last time, report to the sender queue.
        let mut queue_depth = 0;
        let mut output_list_key_images = HashSet::<KeyImage>::default();

        for utxo in resp.output_list.iter() {
            // Sanity check the token id
            if utxo.token_id != self.token_id {
                continue;
            }

            if utxo.value != self.target_value {
                continue;
            }

            queue_depth += 1;
            let key_image: KeyImage = utxo
                .get_key_image()
                .try_into()
                .map_err(|err| format!("invalid key image: {}", err))?;
            if !self.known_utxos.contains_key(&key_image) {
                // We found a utxo that isn't in the cache, let's queue it and add it to the
                // cache
                let (tracker, record) = UtxoTracker::new(utxo.clone());
                let _ = self.sender.send(record);
                self.known_utxos.insert(key_image, tracker);
            }

            // Add the key image of this utxo to a set, this helps us purge the cache
            output_list_key_images.insert(key_image);
        }

        // Remove any known utxos that no longer exist in the response list
        // That is, remove any utxo whose key image wasn't added to
        // output_list_key_images
        self.known_utxos
            .retain(|key_image, _tracker| output_list_key_images.contains(key_image));

        // Now, for each remaining utxo, check if it was sent in a transaction and if so
        // what the status is
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
                    // so that it can be eventually be spent, and for now we should purge it.
                    false
                }
            } else {
                // Still in the queue as far as we know
                true
            }
        });

        // Check the queue depth, and decide if we should make a split tx
        if queue_depth < Worker::THRESHOLD_QUEUE_DEPTH {
            // Check if we already tried to fix this in the last iteration
            if let Some(prev_tx) = self.in_flight_split_tx_state.as_ref() {
                if is_tx_still_in_flight(client, prev_tx, "Split", logger) {
                    // There is already a fix in-flight, let's do nothing until it lands.
                    return Ok(());
                }
            }
            // At this point, the previous in-flight tx resolved somehow and if it was an
            // error we logged it
            self.in_flight_split_tx_state = None;

            // We will now attempt to build and submit a split Tx
            // First make sure we have enough funds for what we want to do, so we don't spam
            // errors when we are depleted, and so that faucet users can know
            // that retries won't help
            let value = self.target_value * (MAX_OUTPUTS - 1);
            let usable_sum: u64 = self
                .known_utxos
                .iter()
                .filter_map(|(_key_image, tracker)| {
                    if tracker.utxo.value > self.target_value {
                        Some(tracker.utxo.value)
                    } else {
                        None
                    }
                })
                .sum();
            if usable_sum < value {
                self.funds_depleted.store(true, Ordering::SeqCst);
                return Ok(());
            } else {
                self.funds_depleted.store(false, Ordering::SeqCst);
            }

            // Generate an outlay
            let mut outlay = mc_mobilecoind_api::Outlay::new();
            outlay.set_receiver(public_address.clone());
            outlay.set_value(self.target_value);

            // Send the split payment request
            // Note: In principle it's possible that we will select utxos of the target
            // value or less, because nothing promised by the API is preventing
            // that. But we know we have enough other larger utxos, and so we
            // just hope that won't happen. If it happens then some faucet
            // payments may race with this one.
            let mut req = mc_mobilecoind_api::SendPaymentRequest::new();
            req.set_sender_monitor_id(monitor_id.to_vec());
            req.set_token_id(*self.token_id);
            // This multiplies the split outlay by MAX_OUTPUTS - 1
            // (-1 is for a change output)
            req.set_outlay_list(RepeatedField::from_vec(vec![
                outlay;
                MAX_OUTPUTS as usize - 1
            ]));

            let resp = client
                .send_payment(&req)
                .map_err(|err| format!("Failed to send payment: {}", err))?;

            // Convert from SendPaymentResponse to SubmitTxResponse,
            // this is needed to check the status of an in-flight payment
            let mut submit_tx_response = SubmitTxResponse::new();
            submit_tx_response.set_sender_tx_receipt(resp.get_sender_tx_receipt().clone());
            submit_tx_response.set_receiver_tx_receipt_list(RepeatedField::from(
                resp.get_receiver_tx_receipt_list(),
            ));

            // This lets us keep tabs on when this split payment has resolved, so that we
            // can avoid sending another payment until it does
            self.in_flight_split_tx_state = Some(submit_tx_response);
        }

        Ok(())
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
            return false;
        }
        Err(err) => {
            log::error!(logger, "Failed getting {} Tx status: {}", context, err);
            // We still don't know the status, so it may still be in-flight
            return true;
        }
    }
}
