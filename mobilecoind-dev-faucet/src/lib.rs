// Copyright (c) 2018-2022 The MobileCoin Foundation

#![deny(missing_docs)]

//! HTTP faucet service backed by mobilecoind

pub mod data_types;
use data_types::*;

mod slam;
use slam::{SlamParams, SlamState};

pub use slam::{SlamReport, SlamStatus};

mod worker;
use worker::{GetUtxoError, UtxoRecord, Worker};

use clap::Parser;
use grpcio::ChannelBuilder;
use mc_account_keys::AccountKey;
use mc_api::printable::PrintableWrapper;
use mc_common::logger::{log, o, Logger};
use mc_mobilecoind_api::{self as api, mobilecoind_api_grpc::MobilecoindApiClient, MobilecoindUri};
use mc_transaction_core::{ring_signature::KeyImage, TokenId};
use mc_util_grpc::ConnectionUriGrpcioChannel;
use mc_util_keyfile::read_keyfile;
use mc_util_uri::ConsensusClientUri;
use std::{collections::HashMap, future::Future, path::PathBuf, sync::Arc, time::Duration};
use tokio::select;

/// Command line config, set with defaults that will work with
/// a standard mobilecoind instance
#[derive(Clone, Debug, Parser)]
#[clap(
    name = "mobilecoind-dev-faucet",
    about = "A stateless HTTP faucet server, backed by mobilecoind"
)]
pub struct Config {
    /// Path to json-formatted key file, containing mnemonic or root entropy.
    #[clap(long, env = "MC_KEYFILE")]
    pub keyfile: PathBuf,

    /// The amount factor, which determines the size of the payment we make. The
    /// minimum fee is multiplied by this.
    #[clap(long, default_value = "20", env = "MC_AMOUNT_FACTOR")]
    pub amount_factor: u64,

    /// Host to listen on.
    #[clap(long, default_value = "127.0.0.1", env = "MC_LISTEN_HOST")]
    pub listen_host: String,

    /// Port to start webserver on.
    #[clap(long, default_value = "9090", env = "MC_LISTEN_PORT")]
    pub listen_port: u16,

    /// MobileCoinD URI.
    #[clap(
        long,
        default_value = "insecure-mobilecoind://127.0.0.1/",
        env = "MC_MOBILECOIND_URI"
    )]
    pub mobilecoind_uri: MobilecoindUri,

    /// Target Queue Depth. When the queue for a token id is less than this in
    /// depth, the worker attempts to make a split Tx to produce more TxOuts
    /// for the queue.
    #[clap(long, default_value = "500", env = "MC_TARGET_QUEUE_DEPTH")]
    pub target_queue_depth: usize,

    /// Worker poll period in milliseconds.
    #[clap(long, default_value = "100", env = "MC_WORKER_POLL_PERIOD_MS")]
    pub worker_poll_period_ms: u64,

    /// Validator nodes to connect to during a slam run.
    /// This provides a default that can also be overrided in the
    /// JsonSlamRequest.
    ///
    /// Sample usages:
    ///     --peer mc://foo:123 --peer mc://bar:456
    ///     --peer mc://foo:123,mc://bar:456
    ///     env MC_PEER=mc://foo:123,mc://bar:456
    #[clap(long = "peer", env = "MC_PEER", use_value_delimiter = true)]
    pub peers: Option<Vec<ConsensusClientUri>>,
}

/// Connection to the mobilecoind client, and other state tracked by the running
/// server (Note that this can all be recovered by restarting the server.)
///
/// This is intended to be used with as the State of the http server in the
/// rocket framework.
pub struct State {
    /// The connection to mobilecoind
    pub mobilecoind_api_client: MobilecoindApiClient,
    /// The account key holding our funds
    pub account_key: AccountKey,
    /// The bytes of our monitor id, which holds the faucet's funds
    pub monitor_id: Vec<u8>,
    /// The public address of the faucet, which someone can use to replenish the
    /// faucet
    pub monitor_b58_address: String,
    /// The amounts the faucet attempts to pay for each token id
    /// This is initialized to network fee * amount factor at startup
    pub faucet_payout_amounts: HashMap<TokenId, u64>,
    /// Handle to worker thread, which pre-splits TxOut's in the background
    pub worker: Worker,
    /// Handle to slam state, which tracks progress of a slam (if any is in
    /// progress)
    pub slam_state: Arc<SlamState>,
    /// List of consensus uri's to submit to during slam operation
    pub consensus_uris: Option<Vec<ConsensusClientUri>>,
    /// Logger
    pub logger: Logger,
}

impl State {
    /// Create a new state from config and a logger
    /// This retries infinitely until it succeeds, logging errors
    pub fn new(config: &Config, logger: &Logger) -> State {
        // Search for keyfile and load it
        let account_key = read_keyfile(config.keyfile.clone()).expect("Could not load keyfile");

        // Set up the gRPC connection to the mobilecoind client
        // Note: choice of 2 completion queues here is not very deliberate
        let grpc_env = Arc::new(grpcio::EnvBuilder::new().cq_count(2).build());
        let ch = ChannelBuilder::new(grpc_env.clone())
            .max_receive_message_len(std::i32::MAX)
            .max_send_message_len(std::i32::MAX)
            .connect_to_uri(&config.mobilecoind_uri, logger);

        let mobilecoind_api_client = MobilecoindApiClient::new(ch);

        let (monitor_id, monitor_public_address, monitor_b58_address, minimum_fees) = loop {
            match Self::try_new(&mobilecoind_api_client, &account_key) {
                Ok(result) => break result,
                Err(err) => log::error!(logger, "Initialization failed, will retry: {}", err),
            }
            std::thread::sleep(Duration::from_millis(1000));
        };

        // The payout amount for each token id is minimum_fee * config.amount_factor
        let faucet_payout_amounts: HashMap<TokenId, u64> = minimum_fees
            .iter()
            .map(|(token_id, fee)| (*token_id, config.amount_factor * fee))
            .collect();

        // Start background worker, which splits txouts in advance
        let worker = Worker::new(
            mobilecoind_api_client.clone(),
            monitor_id.clone(),
            monitor_public_address,
            minimum_fees,
            faucet_payout_amounts.clone(),
            config.target_queue_depth,
            Duration::from_millis(config.worker_poll_period_ms),
            logger,
        );

        let slam_state = Arc::new(SlamState::new(grpc_env));

        State {
            mobilecoind_api_client,
            account_key,
            monitor_id,
            monitor_b58_address,
            faucet_payout_amounts,
            worker,
            slam_state,
            consensus_uris: config.peers.clone(),
            logger: logger.clone(),
        }
    }

    // Try to issue commands to mobilecoind to set up a new faucet, returning an
    // error if any of them fail
    //
    // Returns monitor id, monitor public address, monitor b58 address, and the
    // current network minimum fees
    fn try_new(
        mobilecoind_api_client: &MobilecoindApiClient,
        account_key: &AccountKey,
    ) -> Result<
        (
            Vec<u8>,
            mc_api::external::PublicAddress,
            String,
            HashMap<TokenId, u64>,
        ),
        String,
    > {
        // Create a monitor using our account key
        let monitor_id = {
            let mut req = api::AddMonitorRequest::new();
            req.set_account_key(account_key.into());
            req.set_num_subaddresses(2);
            req.set_name("faucet".to_string());

            let resp = mobilecoind_api_client
                .add_monitor(&req)
                .map_err(|err| format!("Failed adding a monitor: {}", err))?;

            resp.monitor_id
        };

        // Get the b58 public address for monitor
        let monitor_b58_address = {
            let mut req = api::GetPublicAddressRequest::new();
            req.set_monitor_id(monitor_id.clone());

            let resp = mobilecoind_api_client
                .get_public_address(&req)
                .map_err(|err| format!("Failed getting public address: {}", err))?;

            resp.b58_code
        };

        let monitor_printable_wrapper = PrintableWrapper::b58_decode(monitor_b58_address.clone())
            .expect("Could not decode b58 address");
        assert!(monitor_printable_wrapper.has_public_address());
        let monitor_public_address = monitor_printable_wrapper.get_public_address();

        // Get the network minimum fees and compute faucet amounts
        let minimum_fees = {
            let mut result = HashMap::<TokenId, u64>::default();

            let resp = mobilecoind_api_client
                .get_network_status(&Default::default())
                .map_err(|err| format!("Failed getting network status: {}", err))?;

            for (k, v) in resp.get_last_block_info().minimum_fees.iter() {
                result.insert(k.into(), *v);
            }

            result
        };

        Ok((
            monitor_id,
            monitor_public_address.clone(),
            monitor_b58_address,
            minimum_fees,
        ))
    }

    /// Handle a "post" to the faucet, which requests a payment from the faucet.
    /// Returns either the mobilecoind success response or an error string.
    pub async fn handle_post(
        &self,
        req: &JsonFaucetRequest,
    ) -> Result<api::SubmitTxResponse, String> {
        let printable_wrapper = PrintableWrapper::b58_decode(req.b58_address.clone())
            .map_err(|err| format!("Could not decode b58 address: {}", err))?;

        let public_address = if printable_wrapper.has_public_address() {
            printable_wrapper.get_public_address()
        } else {
            return Err(format!(
                "b58 address '{}' is not a public address",
                req.b58_address
            ));
        };

        let token_id = TokenId::from(req.token_id.as_ref());

        let utxo_record = self.worker.get_utxo(token_id).map_err(|x| x.to_string())?;
        log::trace!(
            self.logger,
            "Got a UTXO: key_image = {:?}, value = {}",
            KeyImage::try_from(utxo_record.utxo.get_key_image()).unwrap(),
            utxo_record.utxo.value
        );

        // Generate a Tx sending this specific TxOut, less fees
        let mut req = api::GenerateTxFromTxOutListRequest::new();
        req.set_account_key((&self.account_key).into());
        req.set_input_list(vec![utxo_record.utxo].into());
        req.set_receiver(public_address.clone());
        req.set_token_id(*token_id);

        let resp = self
            .mobilecoind_api_client
            .generate_tx_from_tx_out_list_async(&req)
            .map_err(|err| format!("Failed to build Tx: {}", err))?
            .await
            .map_err(|err| format!("Build Tx ended in error: {}", err))?;

        // Submit the tx proposal
        let mut req = api::SubmitTxRequest::new();
        req.set_tx_proposal(resp.get_tx_proposal().clone());

        let resp = self
            .mobilecoind_api_client
            .submit_tx_async(&req)
            .map_err(|err| format!("Failed to submit Tx: {}", err))?
            .await
            .map_err(|err| format!("Submit Tx ended in error: {}", err))?;

        // Tell the worker that this utxo was submitted, so that it can track and
        // recycle the utxo if this payment fails
        if utxo_record.sender.send(resp.clone()).is_err() {
            log::error!(
                self.logger,
                "Could not send SubmitTxResponse to worker thread"
            );
        }
        Ok(resp)
    }

    /// Handle a "get status" request to the faucet.
    /// Returns either the json status report or an error string.
    pub async fn handle_status(&self) -> Result<FaucetStatus, String> {
        // Get up-to-date balances for all the tokens we are tracking
        let mut balances: HashMap<TokenId, u64> = Default::default();
        for (token_id, _) in self.faucet_payout_amounts.iter() {
            let mut req = api::GetBalanceRequest::new();
            req.set_monitor_id(self.monitor_id.clone());
            req.set_token_id(**token_id);

            let resp = self
                .mobilecoind_api_client
                .get_balance_async(&req)
                .map_err(|err| {
                    format!(
                        "Failed to check balance for token id '{}': {}",
                        token_id, err
                    )
                })?
                .await
                .map_err(|err| {
                    format!(
                        "Balance check request for token id '{}' ended in error: {}",
                        token_id, err
                    )
                })?;
            balances.insert(*token_id, resp.balance);
        }

        let queue_depths = self.worker.get_queue_depths();

        let slam_status = self.slam_state.get_status();

        Ok(FaucetStatus {
            b58_address: self.monitor_b58_address.clone(),
            faucet_payout_amounts: self.faucet_payout_amounts.clone(),
            balances,
            queue_depths: queue_depths
                .into_iter()
                .map(|(token_id, depth)| (token_id, depth as u64))
                .collect(),
            slam_status,
        })
    }

    /// Handle a "post /slam" request.
    ///
    /// Arguments:
    /// * Json slam request parameters
    /// * A generic future indicating that it was requested to stop the slam.
    ///   This can be e.g. rocket::Shutdown.
    ///
    /// Blocks until the slam completes or ends in error, or the shutdown future
    /// resolves. Returns either a slam response structure for sucessful
    /// slam, or an error string.
    pub async fn handle_slam(
        &self,
        req: &JsonSlamRequest,
        stop_requested: impl Future<Output = ()>,
    ) -> Result<SlamResponse, String> {
        let mut params = SlamParams::try_from(req)?;
        if params.consensus_client_uris.is_empty() {
            if let Some(uris) = self.consensus_uris.as_ref() {
                params.consensus_client_uris = uris.clone();
            } else {
                return Err("No consensus uris specified".to_owned());
            }
        }

        let logger = self.logger.new(o! {"task" => "slam"});

        // Question: When we call start_slam, should we wrap this in a task?
        // I think it's possible that rocket may decide to drop this future?
        // (For instance, if the person gets tired of waiting and does ctrl-c
        // from their curl terminal.)
        // If it does, does the SlamStateGuard destructor still fire?
        //
        // If that destructor does not fire then the slam state will not be reset
        // at the end and all future slams will be unable to start.
        //
        // If we wrap this call in a task then even if rocket drops the future,
        // the slam job will still continue, and then the destructor should fire.
        //
        // I think that dropping a future implies calling destructors of all
        // objects on the stack in the async call, to avoid memory leaks,
        // So I think we don't need to wrap this in a task and the slam state
        // guard dtor will still be called no matter what.
        //
        // One issue also is, if the future is dropped before the threads are joined,
        // then they will be detached. However, I think they always finish eventually
        // anyways, so we will not be leaking threads, at least not permanently.
        let slam_state = self.slam_state.clone();
        let mut slam_fut = Box::pin(slam_state.start_slam(
            params.clone(),
            &self.account_key,
            &self.mobilecoind_api_client,
            &self.worker,
            &logger,
        ));

        // Block on either, the slam finishing, or shutdown being requested.
        // If shutdown is requested, then ask slam to stop, then block on slam stopping
        let report = select! {
            slam_result = &mut slam_fut => {
                slam_result
            },
            _ = stop_requested => {
                // This passes a signal to the slam worker threads to join
                self.slam_state.request_stop();
                // Now actually wait for the slam future to finish, so that the worker threads
                // are joined and we don't just leak them
                (&mut slam_fut).await
            }
        }?;

        Ok(SlamResponse { params, report })
    }

    /// Request any long-lived requests to stop
    pub fn request_stop(&self) {
        log::info!(self.logger, "Stop requested");
        self.slam_state.request_stop();
    }
}
