// Copyright (c) 2018-2022 The MobileCoin Foundation
#![deny(missing_docs)]

//! HTTP faucet service backed by mobilecoind

#![feature(proc_macro_hygiene, decl_macro)]

use clap::Parser;
use grpcio::ChannelBuilder;
use mc_account_keys::AccountKey;
use mc_api::printable::PrintableWrapper;
use mc_common::logger::{create_app_logger, log, o, Logger};
use mc_mobilecoind_api::{mobilecoind_api_grpc::MobilecoindApiClient, MobilecoindUri};
use mc_mobilecoind_dev_faucet::{data_types::*, worker::Worker};
use mc_transaction_core::{ring_signature::KeyImage, TokenId};
use mc_util_grpc::ConnectionUriGrpcioChannel;
use mc_util_keyfile::read_keyfile;
use mc_util_serial::JsonU64;
use rocket::{get, post, routes, serde::json::Json};
use std::{collections::HashMap, path::PathBuf, sync::Arc, time::Duration};

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
    #[clap(long, default_value = "20", env = "MC_TARGET_QUEUE_DEPTH")]
    pub target_queue_depth: usize,

    /// Worker poll period in milliseconds.
    #[clap(long, default_value = "100", env = "MC_WORKER_POLL_PERIOD_MS")]
    pub worker_poll_period_ms: u64,
}

/// Connection to the mobilecoind client
struct State {
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
    pub faucet_amounts: HashMap<TokenId, u64>,
    /// The grpcio thread pool
    #[allow(unused)]
    pub grpc_env: Arc<grpcio::Environment>,
    /// Handle to worker thread, which pre-splits TxOut's in the background
    pub worker: Worker,
    /// Logger
    pub logger: Logger,
}

impl State {
    /// Create a new state from config and a logger
    fn new(config: &Config, logger: &Logger) -> Result<State, String> {
        // Search for keyfile and load it
        let account_key = read_keyfile(config.keyfile.clone()).expect("Could not load keyfile");

        // Set up the gRPC connection to the mobilecoind client
        let grpc_env = Arc::new(grpcio::EnvBuilder::new().cq_count(1).build());
        let ch = ChannelBuilder::new(grpc_env.clone())
            .max_receive_message_len(std::i32::MAX)
            .max_send_message_len(std::i32::MAX)
            .connect_to_uri(&config.mobilecoind_uri, logger);

        let mobilecoind_api_client = MobilecoindApiClient::new(ch);

        // Create a monitor using our account key
        let monitor_id = {
            let mut req = mc_mobilecoind_api::AddMonitorRequest::new();
            req.set_account_key((&account_key).into());
            req.set_num_subaddresses(2);
            req.set_name("faucet".to_string());

            let resp = mobilecoind_api_client
                .add_monitor(&req)
                .map_err(|err| format!("Failed adding a monitor: {}", err))?;

            resp.monitor_id
        };

        // Get the b58 public address for monitor
        let monitor_b58_address = {
            let mut req = mc_mobilecoind_api::GetPublicAddressRequest::new();
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
        let faucet_amounts = {
            let mut result = HashMap::<TokenId, u64>::default();

            let resp = mobilecoind_api_client
                .get_network_status(&Default::default())
                .map_err(|err| format!("Failed getting network status: {}", err))?;

            for (k, v) in resp.get_last_block_info().minimum_fees.iter() {
                result.insert(k.into(), config.amount_factor * v);
            }

            result
        };

        // Start background worker, which splits txouts in advance
        let worker = Worker::new(
            mobilecoind_api_client.clone(),
            monitor_id.clone(),
            monitor_public_address.clone(),
            faucet_amounts.clone(),
            config.target_queue_depth,
            Duration::from_millis(config.worker_poll_period_ms),
            logger,
        );

        let logger = logger.new(o!("thread" => "http"));

        Ok(State {
            mobilecoind_api_client,
            account_key,
            monitor_id,
            monitor_b58_address,
            faucet_amounts,
            grpc_env,
            worker,
            logger,
        })
    }
}

/// Request payment from the faucet
#[post("/", format = "json", data = "<req>")]
async fn post(
    state: &rocket::State<State>,
    req: Json<JsonFaucetRequest>,
) -> Result<Json<JsonSubmitTxResponse>, JsonSubmitTxResponse> {
    let printable_wrapper = PrintableWrapper::b58_decode(req.b58_address.clone())
        .map_err(|err| format!("Could not decode b58 address: {}", err))?;

    let public_address = if printable_wrapper.has_public_address() {
        printable_wrapper.get_public_address()
    } else {
        return Err(format!("b58 address '{}' is not a public address", req.b58_address).into());
    };

    let token_id = TokenId::from(req.token_id.unwrap_or_default().as_ref());

    let utxo_record = state.worker.get_utxo(token_id)?;
    log::trace!(
        state.logger,
        "Got a UTXO: key_image = {:?}, value = {}",
        KeyImage::try_from(utxo_record.utxo.get_key_image()).unwrap(),
        utxo_record.utxo.value
    );

    // Generate a Tx sending this specific TxOut, less fees
    let mut req = mc_mobilecoind_api::GenerateTxFromTxOutListRequest::new();
    req.set_account_key((&state.account_key).into());
    req.set_input_list(vec![utxo_record.utxo].into());
    req.set_receiver(public_address.clone());
    req.set_token_id(*token_id);

    let resp = state
        .mobilecoind_api_client
        .generate_tx_from_tx_out_list_async(&req)
        .map_err(|err| format!("Failed to build Tx: {}", err))?
        .await
        .map_err(|err| format!("Build Tx ended in error: {}", err))?;

    // Submit the tx proposal
    let mut req = mc_mobilecoind_api::SubmitTxRequest::new();
    req.set_tx_proposal(resp.get_tx_proposal().clone());

    let resp = state
        .mobilecoind_api_client
        .submit_tx_async(&req)
        .map_err(|err| format!("Failed to submit Tx: {}", err))?
        .await
        .map_err(|err| format!("Submit Tx ended in error: {}", err))?;

    // Tell the worker that this utxo was submitted, so that it can track and
    // recycle the utxo if this payment fails
    let _ = utxo_record.sender.send(resp.clone());
    Ok(Json(JsonSubmitTxResponse::from(&resp)))
}

/// Request status of the faucet
#[get("/status")]
async fn status(state: &rocket::State<State>) -> Result<Json<JsonFaucetStatus>, String> {
    // Get up-to-date balances for all the tokens we are tracking
    let mut balances: HashMap<TokenId, u64> = Default::default();
    for (token_id, _) in state.faucet_amounts.iter() {
        let mut req = mc_mobilecoind_api::GetBalanceRequest::new();
        req.set_monitor_id(state.monitor_id.clone());
        req.set_token_id(**token_id);

        let resp = state
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

    let queue_depths = state.worker.get_queue_depths();

    Ok(Json(JsonFaucetStatus {
        b58_address: state.monitor_b58_address.clone(),
        faucet_amounts: state
            .faucet_amounts
            .iter()
            .map(convert_balance_pair)
            .collect(),
        balances: balances.iter().map(convert_balance_pair).collect(),
        queue_depths: queue_depths
            .into_iter()
            .map(|(token_id, depth)| (JsonU64(*token_id), JsonU64(depth as u64)))
            .collect(),
    }))
}

fn convert_balance_pair(pair: (&TokenId, &u64)) -> (JsonU64, JsonU64) {
    (JsonU64(**pair.0), JsonU64(*pair.1))
}

#[rocket::main]
async fn main() -> Result<(), rocket::Error> {
    mc_common::setup_panic_handler();
    let _sentry_guard = mc_common::sentry::init();

    let config = Config::parse();

    let (logger, _global_logger_guard) = create_app_logger(o!());
    log::info!(
        logger,
        "Starting mobilecoind-dev-faucet HTTP on {}:{}, connecting to {}",
        config.listen_host,
        config.listen_port,
        config.mobilecoind_uri,
    );

    let figment = rocket::Config::figment()
        .merge(("port", config.listen_port))
        .merge(("address", config.listen_host.clone()));

    let state = State::new(&config, &logger).expect("Could not initialize");

    let _rocket = rocket::custom(figment)
        .mount("/", routes![post, status])
        .manage(state)
        .launch()
        .await?;
    Ok(())
}
