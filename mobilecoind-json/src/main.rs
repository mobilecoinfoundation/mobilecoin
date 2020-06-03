#![feature(proc_macro_hygiene, decl_macro)]

use grpcio::{ChannelBuilder, ChannelCredentialsBuilder};
use protobuf::RepeatedField;

use mc_api::external::KeyImage;
use mc_common::logger::{create_app_logger, log, o};
use mc_mobilecoind_api::mobilecoind_api_grpc::MobilecoindApiClient;
use rocket::{get, post, routes};
use rocket_contrib::json::Json;
use serde_derive::{Deserialize, Serialize};
use std::sync::Arc;
use structopt::StructOpt;

/// Command line config, set with defaults that will work with
/// a standard mobilecoind instance
#[derive(Clone, Debug, StructOpt)]
#[structopt(
    name = "mobilecoind-rest-gateway",
    about = "A REST frontend for mobilecoind"
)]
pub struct Config {
    /// Host to listen on.
    #[structopt(long, default_value = "127.0.0.1")]
    pub listen_host: String,

    /// Port to start webserver on.
    #[structopt(long, default_value = "9090")]
    pub listen_port: u16,

    /// MobileCoinD URI.
    #[structopt(long, default_value = "127.0.0.1:4444")]
    pub mobilecoind_host: String,

    /// SSL
    #[structopt(long)]
    pub use_ssl: bool,
}

/// Connection to the mobilecoind client
struct State {
    pub mobilecoind_api_client: MobilecoindApiClient,
}

#[derive(Serialize, Default)]
struct JsonEntropyResponse {
    entropy: String,
}

/// Requests a new root entropy from mobilecoind
#[get("/entropy")]
fn entropy(state: rocket::State<State>) -> Result<Json<JsonEntropyResponse>, String> {
    let resp = state
        .mobilecoind_api_client
        .generate_entropy(&mc_mobilecoind_api::Empty::new())
        .map_err(|err| format!("Failed getting entropy: {}", err))?;
    Ok(Json(JsonEntropyResponse {
        entropy: hex::encode(resp.entropy),
    }))
}

#[derive(Deserialize, Default)]
struct JsonMonitorRequest {
    key: String,
    start: u64,
    number: u64,
}

#[derive(Serialize, Default)]
struct JsonMonitorResponse {
    monitor_id: String,
}

/// Creates a monitor. Data for the key and range is POSTed using the struct above.
#[post("/create-monitor", format = "json", data = "<monitor>")]
fn create_monitor(
    state: rocket::State<State>,
    monitor: Json<JsonMonitorRequest>,
) -> Result<Json<JsonMonitorResponse>, String> {
    let entropy =
        hex::decode(&monitor.key).map_err(|err| format!("Failed to decode hex key: {}", err))?;

    let mut req = mc_mobilecoind_api::GetAccountKeyRequest::new();
    req.set_entropy(entropy.to_vec());

    let mut resp = state
        .mobilecoind_api_client
        .get_account_key(&req)
        .map_err(|err| format!("Failed getting account key for entropy: {}", err))?;

    let account_key = resp.take_account_key();

    let mut req = mc_mobilecoind_api::AddMonitorRequest::new();
    req.set_account_key(account_key);
    req.set_first_subaddress(monitor.start);
    req.set_num_subaddresses(monitor.number);
    req.set_first_block(0);

    let monitor_response = state
        .mobilecoind_api_client
        .add_monitor(&req)
        .map_err(|err| format!("Failed adding monitor: {}", err))?;

    Ok(Json(JsonMonitorResponse {
        monitor_id: hex::encode(monitor_response.monitor_id),
    }))
}

#[derive(Serialize, Default)]
struct JsonBalanceResponse {
    balance: u64,
}

/// Balance check using a created monitor and subaddress index
#[get("/monitors/<monitor_hex>/balance/<index>")]
fn balance(
    state: rocket::State<State>,
    monitor_hex: String,
    index: u64,
) -> Result<Json<JsonBalanceResponse>, String> {
    let monitor_id =
        hex::decode(monitor_hex).map_err(|err| format!("Failed to decode monitor hex: {}", err))?;

    let mut req = mc_mobilecoind_api::GetBalanceRequest::new();
    req.set_monitor_id(monitor_id);
    req.set_subaddress_index(index);

    let resp = state
        .mobilecoind_api_client
        .get_balance(&req)
        .map_err(|err| format!("Failed getting balance: {}", err))?;
    let balance = resp.get_balance();
    Ok(Json(JsonBalanceResponse { balance }))
}

#[derive(Serialize, Default)]
struct JsonRequestResponse {
    request_code: String,
}

/// Generates a request code without a balance or memo
/// TODO: also add a POST that includes balance and memo
#[get("/monitors/<monitor_hex>/request-code/<index>")]
fn request_code(
    state: rocket::State<State>,
    monitor_hex: String,
    index: u64,
) -> Result<Json<JsonRequestResponse>, String> {
    let monitor_id =
        hex::decode(monitor_hex).map_err(|err| format!("Failed to decode monitor hex: {}", err))?;

    // Get our public address.
    let mut req = mc_mobilecoind_api::GetPublicAddressRequest::new();
    req.set_monitor_id(monitor_id);
    req.set_subaddress_index(index);

    let resp = state
        .mobilecoind_api_client
        .get_public_address(&req)
        .map_err(|err| format!("Failed getting public address: {}", err))?;

    let public_address = resp.get_public_address().clone();

    // Generate b58 code
    let mut req = mc_mobilecoind_api::GetRequestCodeRequest::new();
    req.set_receiver(public_address);
    let resp = state
        .mobilecoind_api_client
        .get_request_code(&req)
        .map_err(|err| format!("Failed getting request code: {}", err))?;

    Ok(Json(JsonRequestResponse {
        request_code: String::from(resp.get_b58_code()),
    }))
}

#[derive(Deserialize)]
struct JsonTransferRequest {
    request_code: String,
    amount: u64,
}
#[derive(Serialize)]
struct JsonTransferResponse {
    key_image: String,
    tombstone: u64,
}

/// Performs a transfer from a monitor and subaddress. The target and amount are in the POST data.
#[post(
    "/monitors/<monitor_hex>/transfer/<index>",
    format = "json",
    data = "<transfer>"
)]
fn transfer(
    state: rocket::State<State>,
    monitor_hex: String,
    index: u64,
    transfer: Json<JsonTransferRequest>,
) -> Result<Json<JsonTransferResponse>, String> {
    let monitor_id =
        hex::decode(monitor_hex).map_err(|err| format!("Failed to decode monitor hex: {}", err))?;

    let mut req = mc_mobilecoind_api::ReadRequestCodeRequest::new();
    req.set_b58_code(transfer.request_code.clone());
    let resp = state
        .mobilecoind_api_client
        .read_request_code(&req)
        .map_err(|err| format!("Failed reading request code: {}", err))?;
    let public_address = resp.get_receiver();

    let mut outlay = mc_mobilecoind_api::Outlay::new();
    outlay.set_receiver(public_address.clone());
    outlay.set_value(transfer.amount);

    let mut req = mc_mobilecoind_api::SendPaymentRequest::new();
    req.set_sender_monitor_id(monitor_id);
    req.set_sender_subaddress(index);
    req.set_outlay_list(RepeatedField::from_vec(vec![outlay]));

    let resp = state
        .mobilecoind_api_client
        .send_payment(&req)
        .map_err(|err| format!("Failed to send payment: {}", err))?;

    let receipt = resp.get_sender_tx_receipt();
    Ok(Json(JsonTransferResponse {
        key_image: hex::encode(receipt.get_key_image_list()[0].get_data()),
        tombstone: receipt.get_tombstone(),
    }))
}

#[derive(Serialize, Default)]
struct JsonStatusResponse {
    status: String,
}

/// Checks the status of a transfer given a key image and tombstone block
#[get("/status/<key_hex>/<tombstone>")]
fn status(
    state: rocket::State<State>,
    key_hex: String,
    tombstone: u64,
) -> Result<Json<JsonStatusResponse>, String> {
    let mut receipt = mc_mobilecoind_api::SenderTxReceipt::new();
    let mut key_image = KeyImage::new();
    key_image.set_data(
        hex::decode(key_hex).map_err(|err| format!("Failed to decode key image hex: {}", err))?,
    );
    receipt.set_key_image_list(RepeatedField::from_vec(vec![key_image]));
    receipt.set_tombstone(tombstone);

    let mut req = mc_mobilecoind_api::GetTxStatusAsSenderRequest::new();
    req.set_receipt(receipt);

    let resp = state
        .mobilecoind_api_client
        .get_tx_status_as_sender(&req)
        .map_err(|err| format!("Failed getting status: {}", err))?;
    let status = resp.get_status();
    match status {
        mc_mobilecoind_api::TxStatus::Unknown => Ok(Json(JsonStatusResponse {
            status: String::from("unknown"),
        })),
        mc_mobilecoind_api::TxStatus::Verified => Ok(Json(JsonStatusResponse {
            status: String::from("verified"),
        })),
        mc_mobilecoind_api::TxStatus::TombstoneBlockExceeded => Ok(Json(JsonStatusResponse {
            status: String::from("failed"),
        })),
    }
}

fn main() {
    mc_common::setup_panic_handler();
    let _sentry_guard = mc_common::sentry::init();

    let config = Config::from_args();

    let (logger, _global_logger_guard) = create_app_logger(o!());
    log::info!(
        logger,
        "Starting mobilecoind HTTP gateway on {}:{}, connecting to {}",
        config.listen_host,
        config.listen_port,
        config.mobilecoind_host
    );

    // Set up the gRPC connection to the mobilecoind client
    let env = Arc::new(grpcio::EnvBuilder::new().build());
    let ch_builder = ChannelBuilder::new(env)
        .max_receive_message_len(std::i32::MAX)
        .max_send_message_len(std::i32::MAX);

    let ch = if config.use_ssl {
        let creds = ChannelCredentialsBuilder::new().build();
        ch_builder.secure_connect(&config.mobilecoind_host, creds)
    } else {
        ch_builder.connect(&config.mobilecoind_host)
    };

    let mobilecoind_api_client = MobilecoindApiClient::new(ch);

    let rocket_config = rocket::Config::build(rocket::config::Environment::Production)
        .address(&config.listen_host)
        .port(config.listen_port)
        .unwrap();

    rocket::custom(rocket_config)
        .mount(
            "/",
            routes![
                entropy,
                create_monitor,
                balance,
                request_code,
                transfer,
                status
            ],
        )
        .manage(State {
            mobilecoind_api_client,
        })
        .launch();
}
