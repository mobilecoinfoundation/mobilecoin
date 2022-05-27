// Copyright (c) 2018-2022 The MobileCoin Foundation
#![deny(missing_docs)]

//! JSON wrapper for the mobilecoind API.

#![feature(proc_macro_hygiene, decl_macro)]

use clap::Parser;
use grpcio::ChannelBuilder;
use mc_api::printable::PrintableWrapper;
use mc_common::logger::{create_app_logger, log, o, Logger};
use mc_mobilecoind_api::{
    mobilecoind_api_grpc::MobilecoindApiClient, MobilecoindUri, SubmitTxResponse, TxStatus,
};
use mc_mobilecoind_dev_faucet::data_types::*;
use mc_transaction_types::TokenId;
use mc_util_grpc::ConnectionUriGrpcioChannel;
use mc_util_keyfile::read_keyfile;
use protobuf::RepeatedField;
use rocket::{get, post, routes, serde::json::Json};
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, Mutex, MutexGuard},
    time::Duration,
};

/// Command line config, set with defaults that will work with
/// a standard mobilecoind instance
#[derive(Clone, Debug, Parser)]
#[clap(
    name = "mobilecoind-dev-faucet",
    about = "An HTTP faucet server, backed by mobilecoind"
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
}

/// Connection to the mobilecoind client
struct State {
    /// The connection to mobilecoind
    pub mobilecoind_api_client: MobilecoindApiClient,
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
    /// The submit tx response for our previous Tx if any. This lets us check
    /// if we have an in-flight tx still.
    pub inflight_tx_state: Mutex<Option<SubmitTxResponse>>,
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
            .connect_to_uri(&config.mobilecoind_uri, &logger);

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

        // Get the network minimum fees and compute faucet amounts
        let faucet_amounts = {
            let mut result = HashMap::<TokenId, u64>::default();

            let resp = mobilecoind_api_client
                .get_network_status(&Default::default())
                .map_err(|err| format!("Failed getting network status: {}", err))?;

            for (k, v) in resp.minimum_fees.iter() {
                result.insert(k.into(), *v);
            }

            result
        };

        let inflight_tx_state = Mutex::new(Default::default());

        Ok(State {
            mobilecoind_api_client,
            monitor_id,
            monitor_b58_address,
            faucet_amounts,
            grpc_env,
            inflight_tx_state,
        })
    }

    fn lock_and_check_inflight_tx_state(
        &self,
    ) -> Result<MutexGuard<Option<SubmitTxResponse>>, String> {
        let mut guard = self.inflight_tx_state.lock().expect("mutex poisoned");
        if let Some(prev_tx) = guard.as_mut() {
            let mut tries = 10;
            loop {
                let resp = self
                    .mobilecoind_api_client
                    .get_tx_status_as_sender(&prev_tx)
                    .map_err(|err| format!("Failed getting network status: {}", err))?;
                if resp.status == TxStatus::Unknown {
                    std::thread::sleep(Duration::from_millis(10));
                    tries -= 1;
                    if tries == 0 {
                        return Err("faucet is busy".to_string());
                    }
                } else {
                    break;
                }
            }
        }

        *guard = None;

        Ok(guard)
    }
}

/// Request payment from the faucet
#[post("/", format = "json", data = "<req>")]
fn post(
    state: &rocket::State<State>,
    req: Json<JsonFaucetRequest>,
) -> Result<Json<JsonSendPaymentResponse>, String> {
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

    let token_id = TokenId::from(req.token_id.unwrap_or_else(Default::default).as_ref());

    let value = *state.faucet_amounts.get(&token_id).ok_or(format!(
        "token_id: '{}' is not supported by the network",
        token_id
    ))?;

    let mut lock = state.lock_and_check_inflight_tx_state()?;

    // Generate an outlay
    let mut outlay = mc_mobilecoind_api::Outlay::new();
    outlay.set_receiver(public_address.clone());
    outlay.set_value(value);

    // Send the payment request
    let mut req = mc_mobilecoind_api::SendPaymentRequest::new();
    req.set_sender_monitor_id(state.monitor_id.clone());
    req.set_sender_subaddress(0);
    req.set_token_id(*token_id);
    req.set_outlay_list(RepeatedField::from_vec(vec![outlay]));

    let resp = state
        .mobilecoind_api_client
        .send_payment(&req)
        .map_err(|err| format!("Failed to send payment: {}", err))?;

    // Convert from SendPaymentResponse to SubmitTxResponse,
    // this is needed to check the status of an in-flight payment
    let mut submit_tx_response = SubmitTxResponse::new();
    submit_tx_response.set_sender_tx_receipt(resp.get_sender_tx_receipt().clone());
    submit_tx_response
        .set_receiver_tx_receipt_list(RepeatedField::from(resp.get_receiver_tx_receipt_list()));

    // This lets us keep tabs on when this payment has resolved, so that we can
    // avoid sending another payment until it does
    *lock = Some(submit_tx_response);

    // The receipt from the payment request can be used by the status check below
    Ok(Json(JsonSendPaymentResponse::from(&resp)))
}

/// Request status of the faucet
#[get("/status")]
fn status(state: &rocket::State<State>) -> Result<Json<JsonFaucetStatus>, String> {
    // Get up-to-date balances for all the tokens we are tracking
    let mut balances: HashMap<TokenId, u64> = Default::default();
    for (token_id, _) in state.faucet_amounts.iter() {
        let mut req = mc_mobilecoind_api::GetBalanceRequest::new();
        req.set_monitor_id(state.monitor_id.clone());
        req.set_token_id(**token_id);

        let resp = state
            .mobilecoind_api_client
            .get_balance(&req)
            .map_err(|err| {
                format!(
                    "Failed to check balance for token id '{}': {}",
                    token_id, err
                )
            })?;
        balances.insert(*token_id, resp.balance);
    }

    Ok(Json(JsonFaucetStatus {
        b58_address: state.monitor_b58_address.clone(),
        faucet_amounts: state
            .faucet_amounts
            .iter()
            .map(convert_balance_pair)
            .collect(),
        balances: balances.iter().map(convert_balance_pair).collect(),
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
