// Copyright (c) 2018-2020 MobileCoin Inc.

//! JSON wrapper for the mobilecoind API.

#![feature(proc_macro_hygiene, decl_macro)]

use grpcio::ChannelBuilder;
use mc_api::external::{CompressedRistretto, KeyImage, PublicAddress, RistrettoPrivate};
use mc_common::logger::{create_app_logger, log, o};
use mc_mobilecoind_api::{mobilecoind_api_grpc::MobilecoindApiClient, MobilecoindUri};
use mc_mobilecoind_json::data_types::*;
use mc_util_grpc::ConnectionUriGrpcioChannel;
use protobuf::RepeatedField;
use rocket::{delete, get, post, routes};
use rocket_contrib::json::Json;
use std::{convert::TryFrom, sync::Arc};
use structopt::StructOpt;

/// Command line config, set with defaults that will work with
/// a standard mobilecoind instance
#[derive(Clone, Debug, StructOpt)]
#[structopt(name = "mobilecoind-json", about = "A REST frontend for mobilecoind")]
pub struct Config {
    /// Host to listen on.
    #[structopt(long, default_value = "127.0.0.1")]
    pub listen_host: String,

    /// Port to start webserver on.
    #[structopt(long, default_value = "9090")]
    pub listen_port: u16,

    /// MobileCoinD URI.
    #[structopt(long, default_value = "insecure-mobilecoind://127.0.0.1/")]
    pub mobilecoind_uri: MobilecoindUri,
}

/// Connection to the mobilecoind client
struct State {
    pub mobilecoind_api_client: MobilecoindApiClient,
}

/// Requests a new root entropy from mobilecoind
#[post("/entropy")]
fn entropy(state: rocket::State<State>) -> Result<Json<JsonEntropyResponse>, String> {
    let resp = state
        .mobilecoind_api_client
        .generate_entropy(&mc_mobilecoind_api::Empty::new())
        .map_err(|err| format!("Failed getting entropy: {}", err))?;
    Ok(Json(JsonEntropyResponse::from(&resp)))
}

#[get("/entropy/<entropy>")]
fn account_key(
    state: rocket::State<State>,
    entropy: String,
) -> Result<Json<JsonAccountKeyResponse>, String> {
    let entropy =
        hex::decode(entropy).map_err(|err| format!("Failed to decode hex key: {}", err))?;

    let mut req = mc_mobilecoind_api::GetAccountKeyRequest::new();
    req.set_entropy(entropy.to_vec());

    let resp = state
        .mobilecoind_api_client
        .get_account_key(&req)
        .map_err(|err| format!("Failed getting account key for entropy: {}", err))?;

    Ok(Json(JsonAccountKeyResponse::from(&resp)))
}

/// Creates a monitor. Data for the key and range is POSTed using the struct above.
#[post("/monitors", format = "json", data = "<monitor>")]
fn add_monitor(
    state: rocket::State<State>,
    monitor: Json<JsonMonitorRequest>,
) -> Result<Json<JsonMonitorResponse>, String> {
    let mut account_key = mc_mobilecoind_api::external::AccountKey::new();
    let mut view_private_key = RistrettoPrivate::new();
    view_private_key.set_data(
        hex::decode(&monitor.account_key.view_private_key)
            .map_err(|err| format!("Failed to decode hex key: {}", err))?,
    );
    let mut spend_private_key = RistrettoPrivate::new();
    spend_private_key.set_data(
        hex::decode(&monitor.account_key.spend_private_key)
            .map_err(|err| format!("Failed to decode hex key: {}", err))?,
    );
    account_key.set_view_private_key(view_private_key);
    account_key.set_spend_private_key(spend_private_key);

    let mut req = mc_mobilecoind_api::AddMonitorRequest::new();
    req.set_account_key(account_key);
    req.set_first_subaddress(monitor.first_subaddress);
    req.set_num_subaddresses(monitor.num_subaddresses);
    req.set_first_block(0);

    let monitor_response = state
        .mobilecoind_api_client
        .add_monitor(&req)
        .map_err(|err| format!("Failed adding monitor: {}", err))?;

    Ok(Json(JsonMonitorResponse::from(&monitor_response)))
}

/// Remove a monitor
#[delete("/monitors/<monitor_hex>")]
fn remove_monitor(state: rocket::State<State>, monitor_hex: String) -> Result<(), String> {
    let monitor_id =
        hex::decode(monitor_hex).map_err(|err| format!("Failed to decode monitor hex: {}", err))?;

    let mut req = mc_mobilecoind_api::RemoveMonitorRequest::new();
    req.set_monitor_id(monitor_id);

    let _resp = state
        .mobilecoind_api_client
        .remove_monitor(&req)
        .map_err(|err| format!("Failed removing monitor: {}", err))?;

    Ok(())
}

/// Gets a list of existing monitors
#[get("/monitors")]
fn monitors(state: rocket::State<State>) -> Result<Json<JsonMonitorListResponse>, String> {
    let resp = state
        .mobilecoind_api_client
        .get_monitor_list(&mc_mobilecoind_api::Empty::new())
        .map_err(|err| format!("Failed getting monitor list: {}", err))?;
    Ok(Json(JsonMonitorListResponse::from(&resp)))
}

/// Get the current status of a created monitor
#[get("/monitors/<monitor_hex>")]
fn monitor_status(
    state: rocket::State<State>,
    monitor_hex: String,
) -> Result<Json<JsonMonitorStatusResponse>, String> {
    let monitor_id =
        hex::decode(monitor_hex).map_err(|err| format!("Failed to decode monitor hex: {}", err))?;

    let mut req = mc_mobilecoind_api::GetMonitorStatusRequest::new();
    req.set_monitor_id(monitor_id);

    let resp = state
        .mobilecoind_api_client
        .get_monitor_status(&req)
        .map_err(|err| format!("Failed getting monitor status: {}", err))?;

    Ok(Json(JsonMonitorStatusResponse::from(&resp)))
}

/// Balance check using a created monitor and subaddress index
#[get("/monitors/<monitor_hex>/subaddresses/<subaddress_index>/balance")]
fn balance(
    state: rocket::State<State>,
    monitor_hex: String,
    subaddress_index: u64,
) -> Result<Json<JsonBalanceResponse>, String> {
    let monitor_id =
        hex::decode(monitor_hex).map_err(|err| format!("Failed to decode monitor hex: {}", err))?;

    let mut req = mc_mobilecoind_api::GetBalanceRequest::new();
    req.set_monitor_id(monitor_id);
    req.set_subaddress_index(subaddress_index);

    let resp = state
        .mobilecoind_api_client
        .get_balance(&req)
        .map_err(|err| format!("Failed getting balance: {}", err))?;

    Ok(Json(JsonBalanceResponse::from(&resp)))
}

#[get("/monitors/<monitor_hex>/subaddresses/<subaddress_index>/utxos")]
fn utxos(
    state: rocket::State<State>,
    monitor_hex: String,
    subaddress_index: u64,
) -> Result<Json<JsonUtxosResponse>, String> {
    let monitor_id =
        hex::decode(monitor_hex).map_err(|err| format!("Failed to decode monitor hex: {}", err))?;

    let mut req = mc_mobilecoind_api::GetUnspentTxOutListRequest::new();
    req.set_monitor_id(monitor_id);
    req.set_subaddress_index(subaddress_index);

    let resp = state
        .mobilecoind_api_client
        .get_unspent_tx_out_list(&req)
        .map_err(|err| format!("Failed getting utxos: {}", err))?;

    Ok(Json(JsonUtxosResponse::from(&resp)))
}

/// Balance check using a created monitor and subaddress index
#[get("/monitors/<monitor_hex>/subaddresses/<subaddress_index>/public-address")]
fn public_address(
    state: rocket::State<State>,
    monitor_hex: String,
    subaddress_index: u64,
) -> Result<Json<JsonPublicAddressResponse>, String> {
    let monitor_id =
        hex::decode(monitor_hex).map_err(|err| format!("Failed to decode monitor hex: {}", err))?;

    // Get our public address.
    let mut req = mc_mobilecoind_api::GetPublicAddressRequest::new();
    req.set_monitor_id(monitor_id);
    req.set_subaddress_index(subaddress_index);

    let resp = state
        .mobilecoind_api_client
        .get_public_address(&req)
        .map_err(|err| format!("Failed getting public address: {}", err))?;

    Ok(Json(JsonPublicAddressResponse::from(&resp)))
}

/// Generates a request code with an optional value and memo
#[post("/codes/request", format = "json", data = "<request>")]
fn create_request_code(
    state: rocket::State<State>,
    request: Json<JsonCreateRequestCodeRequest>,
) -> Result<Json<JsonCreateRequestCodeResponse>, String> {
    let receiver = mc_mobilecoind_api::external::PublicAddress::try_from(&request.receiver)
        .map_err(|err| format!("Failed to parse receiver's public address: {}", err))?;

    // Generate b58 code
    let mut req = mc_mobilecoind_api::CreateRequestCodeRequest::new();
    req.set_receiver(receiver);
    if let Some(value) = request.value.clone() {
        req.set_value(
            value
                .parse::<u64>()
                .map_err(|err| format!("Failed to parse value field: {}", err))?,
        );
    }
    if let Some(memo) = request.memo.clone() {
        req.set_memo(memo);
    }

    let resp = state
        .mobilecoind_api_client
        .create_request_code(&req)
        .map_err(|err| format!("Failed creating request code: {}", err))?;

    Ok(Json(JsonCreateRequestCodeResponse::from(&resp)))
}

/// Retrieves the data in a request b58_code
#[get("/codes/request/<b58_code>")]
fn parse_request_code(
    state: rocket::State<State>,
    b58_code: String,
) -> Result<Json<JsonParseRequestCodeResponse>, String> {
    let mut req = mc_mobilecoind_api::ParseRequestCodeRequest::new();
    req.set_b58_code(b58_code);
    let resp = state
        .mobilecoind_api_client
        .parse_request_code(&req)
        .map_err(|err| format!("Failed parsing request code: {}", err))?;

    // The response contains the public keys encoded in the read request, as well as a memo and
    // requested value. This can be used as-is in the transfer call below, or the value can be
    // modified.
    Ok(Json(JsonParseRequestCodeResponse::from(&resp)))
}

/// Generates an address code
#[post("/codes/address", format = "json", data = "<request>")]
fn create_address_code(
    state: rocket::State<State>,
    request: Json<JsonCreateAddressCodeRequest>,
) -> Result<Json<JsonCreateAddressCodeResponse>, String> {
    let receiver = mc_mobilecoind_api::external::PublicAddress::try_from(&request.receiver)
        .map_err(|err| format!("Failed to parse receiver's public address: {}", err))?;

    // Generate b58 code
    let mut req = mc_mobilecoind_api::CreateAddressCodeRequest::new();
    req.set_receiver(receiver);

    let resp = state
        .mobilecoind_api_client
        .create_address_code(&req)
        .map_err(|err| format!("Failed creating address code: {}", err))?;

    Ok(Json(JsonCreateAddressCodeResponse::from(&resp)))
}

/// Retrieves the data in an address b58_code
#[get("/codes/address/<b58_code>")]
fn parse_address_code(
    state: rocket::State<State>,
    b58_code: String,
) -> Result<Json<JsonParseAddressCodeResponse>, String> {
    let mut req = mc_mobilecoind_api::ParseAddressCodeRequest::new();
    req.set_b58_code(b58_code);
    let resp = state
        .mobilecoind_api_client
        .parse_address_code(&req)
        .map_err(|err| format!("Failed parding address code: {}", err))?;

    // The response contains the public keys encoded in the read request
    Ok(Json(JsonParseAddressCodeResponse::from(&resp)))
}

/// Performs a transfer from a monitor and subaddress. The public keys and amount are in the POST data.
#[post(
    "/monitors/<monitor_hex>/subaddresses/<subaddress_index>/build-and-submit",
    format = "json",
    data = "<transfer>"
)]
fn build_and_submit(
    state: rocket::State<State>,
    monitor_hex: String,
    subaddress_index: u64,
    transfer: Json<JsonSendPaymentRequest>,
) -> Result<Json<JsonSendPaymentResponse>, String> {
    let monitor_id =
        hex::decode(monitor_hex).map_err(|err| format!("Failed to decode monitor hex: {}", err))?;

    let public_address = PublicAddress::try_from(&transfer.request_data.receiver)?;

    // Generate an outlay
    let mut outlay = mc_mobilecoind_api::Outlay::new();
    outlay.set_receiver(public_address);
    outlay.set_value(
        transfer
            .request_data
            .value
            .parse::<u64>()
            .map_err(|err| format!("Failed to parse request_code.amount: {}", err))?,
    );

    // Get max_input_utxo_value.
    let max_input_utxo_value = transfer
        .max_input_utxo_value
        .clone()
        .unwrap_or_else(|| "0".to_owned()) // A value of 0 disables the max limit.
        .parse::<u64>()
        .map_err(|err| format!("Failed to parse max_input_utxo_value: {}", err))?;

    // Send the payment request
    let mut req = mc_mobilecoind_api::SendPaymentRequest::new();
    req.set_sender_monitor_id(monitor_id);
    req.set_sender_subaddress(subaddress_index);
    req.set_outlay_list(RepeatedField::from_vec(vec![outlay]));
    req.set_max_input_utxo_value(max_input_utxo_value);

    let resp = state
        .mobilecoind_api_client
        .send_payment(&req)
        .map_err(|err| format!("Failed to send payment: {}", err))?;

    // The receipt from the payment request can be used by the status check below
    Ok(Json(JsonSendPaymentResponse::from(&resp)))
}

/// Performs a transfer from a monitor and subaddress to a given address code/amount.
#[post(
    "/monitors/<monitor_hex>/subaddresses/<subaddress_index>/pay-address-code",
    format = "json",
    data = "<transfer>"
)]
fn pay_address_code(
    state: rocket::State<State>,
    monitor_hex: String,
    subaddress_index: u64,
    transfer: Json<JsonPayAddressCodeRequest>,
) -> Result<Json<JsonSendPaymentResponse>, String> {
    let monitor_id =
        hex::decode(monitor_hex).map_err(|err| format!("Failed to decode monitor hex: {}", err))?;

    // Get amount.
    let amount = transfer
        .value
        .parse::<u64>()
        .map_err(|err| format!("Failed parsing amount: {}", err))?;

    // Get max_input_utxo_value.
    let max_input_utxo_value = transfer
        .max_input_utxo_value
        .clone()
        .unwrap_or_else(|| "0".to_owned()) // A value of 0 disables the max limit.
        .parse::<u64>()
        .map_err(|err| format!("Failed to parse max_input_utxo_value: {}", err))?;

    // Send the pay address code request
    let mut req = mc_mobilecoind_api::PayAddressCodeRequest::new();
    req.set_sender_monitor_id(monitor_id);
    req.set_sender_subaddress(subaddress_index);
    req.set_receiver_b58_code(transfer.receiver_b58_address_code.clone());
    req.set_amount(amount);
    req.set_max_input_utxo_value(max_input_utxo_value);

    let resp = state
        .mobilecoind_api_client
        .pay_address_code(&req)
        .map_err(|err| format!("Failed to send payment: {}", err))?;

    // The receipt from the payment request can be used by the status check below
    Ok(Json(JsonSendPaymentResponse::from(&resp)))
}

/// Creates a transaction proposal. This can be used in an offline transaction construction
/// flow, where the proposal is created on the offline machine, and copied to the connected
/// machine for submission, via submit-tx.
#[post(
    "/monitors/<monitor_hex>/subaddresses/<subaddress_index>/generate-request-code-transaction",
    format = "json",
    data = "<request>"
)]
fn generate_request_code_transaction(
    state: rocket::State<State>,
    monitor_hex: String,
    subaddress_index: u64,
    request: Json<JsonCreateTxProposalRequest>,
) -> Result<Json<JsonCreateTxProposalResponse>, String> {
    let monitor_id =
        hex::decode(monitor_hex).map_err(|err| format!("Failed to decode monitor hex: {}", err))?;

    let public_address = PublicAddress::try_from(&request.transfer.receiver)?;

    // Generate an outlay
    let mut outlay = mc_mobilecoind_api::Outlay::new();
    outlay.set_receiver(public_address);
    outlay.set_value(
        request
            .transfer
            .value
            .parse::<u64>()
            .map_err(|err| format!("Failed to parse amount: {}", err))?,
    );

    let inputs: Vec<mc_mobilecoind_api::UnspentTxOut> = request
        .input_list
        .iter()
        .map(|input| {
            mc_mobilecoind_api::UnspentTxOut::try_from(input)
                .map_err(|err| format!("Failed to convert input: {}", err))
        })
        .collect::<Result<_, String>>()?;

    // Get a tx proposal
    let mut req = mc_mobilecoind_api::GenerateTxRequest::new();
    req.set_sender_monitor_id(monitor_id);
    req.set_change_subaddress(subaddress_index);
    req.set_outlay_list(RepeatedField::from_vec(vec![outlay]));
    req.set_input_list(RepeatedField::from_vec(inputs));

    let resp = state
        .mobilecoind_api_client
        .generate_tx(&req)
        .map_err(|err| format!("Failed to generate tx: {}", err))?;

    Ok(Json(JsonCreateTxProposalResponse::from(&resp)))
}

/// Submit a prepared TxProposal
#[post("/submit-tx", format = "json", data = "<proposal>")]
fn submit_tx(
    state: rocket::State<State>,
    proposal: Json<JsonTxProposalRequest>,
) -> Result<Json<JsonSubmitTxResponse>, String> {
    // Send the payment request
    let mut req = mc_mobilecoind_api::SubmitTxRequest::new();
    req.set_tx_proposal(
        mc_mobilecoind_api::TxProposal::try_from(&proposal.tx_proposal)
            .map_err(|err| format!("Failed to convert tx proposal: {}", err))?,
    );

    let resp = state
        .mobilecoind_api_client
        .submit_tx(&req)
        .map_err(|err| format!("Failed to send payment: {}", err))?;

    // The receipt from the payment request can be used by the status check below
    Ok(Json(JsonSubmitTxResponse::from(&resp)))
}

/// Checks the status of a transfer given a key image and tombstone block
#[post("/tx/status-as-sender", format = "json", data = "<receipt>")]
fn check_transfer_status(
    state: rocket::State<State>,
    receipt: Json<JsonSendPaymentResponse>,
) -> Result<Json<JsonStatusResponse>, String> {
    let mut sender_receipt = mc_mobilecoind_api::SenderTxReceipt::new();
    let mut key_images = Vec::new();
    for key_image_hex in &receipt.sender_tx_receipt.key_images {
        key_images.push(KeyImage::from(
            hex::decode(&key_image_hex).map_err(|err| format!("{}", err))?,
        ))
    }

    sender_receipt.set_key_image_list(RepeatedField::from_vec(key_images));
    sender_receipt.set_tombstone(receipt.sender_tx_receipt.tombstone);

    let mut req = mc_mobilecoind_api::GetTxStatusAsSenderRequest::new();
    req.set_receipt(sender_receipt);

    let resp = state
        .mobilecoind_api_client
        .get_tx_status_as_sender(&req)
        .map_err(|err| format!("Failed getting status: {}", err))?;

    Ok(Json(JsonStatusResponse::from(&resp)))
}

/// Checks the status of a transfer given data for a specific receiver
/// The sender of the transaction will take specific receipt data from the /transfer call
/// and distribute it to the recipient(s) so they can verify that a transaction has been
/// processed and the the person supplying the receipt can prove they intiated it
#[post("/tx/status-as-receiver", format = "json", data = "<receipt>")]
fn check_receiver_transfer_status(
    state: rocket::State<State>,
    receipt: Json<JsonReceiverTxReceipt>,
) -> Result<Json<JsonStatusResponse>, String> {
    let mut receiver_receipt = mc_mobilecoind_api::ReceiverTxReceipt::new();
    let mut tx_public_key = CompressedRistretto::new();
    tx_public_key.set_data(hex::decode(&receipt.tx_public_key).map_err(|err| format!("{}", err))?);
    receiver_receipt.set_tx_public_key(tx_public_key);
    receiver_receipt
        .set_tx_out_hash(hex::decode(&receipt.tx_out_hash).map_err(|err| format!("{}", err))?);
    receiver_receipt.set_tombstone(receipt.tombstone);
    receiver_receipt.set_confirmation_number(
        hex::decode(&receipt.confirmation_number).map_err(|err| format!("{}", err))?,
    );

    let mut req = mc_mobilecoind_api::GetTxStatusAsReceiverRequest::new();
    req.set_receipt(receiver_receipt);

    let resp = state
        .mobilecoind_api_client
        .get_tx_status_as_receiver(&req)
        .map_err(|err| format!("Failed getting status: {}", err))?;

    Ok(Json(JsonStatusResponse::from(&resp)))
}

/// Gets information about the entire ledger
#[get("/ledger/local")]
fn ledger_info(state: rocket::State<State>) -> Result<Json<JsonLedgerInfoResponse>, String> {
    let resp = state
        .mobilecoind_api_client
        .get_ledger_info(&mc_mobilecoind_api::Empty::new())
        .map_err(|err| format!("Failed getting ledger info: {}", err))?;

    Ok(Json(JsonLedgerInfoResponse::from(&resp)))
}

/// Retrieves the data in a request code
#[get("/ledger/blocks/<block_num>/header")]
fn block_info(
    state: rocket::State<State>,
    block_num: u64,
) -> Result<Json<JsonBlockInfoResponse>, String> {
    let mut req = mc_mobilecoind_api::GetBlockInfoRequest::new();
    req.set_block(block_num);

    let resp = state
        .mobilecoind_api_client
        .get_block_info(&req)
        .map_err(|err| format!("Failed getting ledger info: {}", err))?;

    Ok(Json(JsonBlockInfoResponse::from(&resp)))
}

/// Retrieves the details for a given block.
#[get("/ledger/blocks/<block_num>")]
fn block_details(
    state: rocket::State<State>,
    block_num: u64,
) -> Result<Json<JsonBlockDetailsResponse>, String> {
    let mut req = mc_mobilecoind_api::GetBlockRequest::new();
    req.set_block(block_num);

    let resp = state
        .mobilecoind_api_client
        .get_block(&req)
        .map_err(|err| format!("Failed getting block details: {}", err))?;

    Ok(Json(JsonBlockDetailsResponse::from(&resp)))
}
/// Retreives processed block information.
#[get("/monitors/<monitor_hex>/processed-block/<block_num>")]
fn processed_block(
    state: rocket::State<State>,
    monitor_hex: String,
    block_num: u64,
) -> Result<Json<JsonProcessedBlockResponse>, String> {
    let monitor_id =
        hex::decode(monitor_hex).map_err(|err| format!("Failed to decode monitor hex: {}", err))?;

    let mut req = mc_mobilecoind_api::GetProcessedBlockRequest::new();
    req.set_monitor_id(monitor_id);
    req.set_block(block_num);

    let resp = state
        .mobilecoind_api_client
        .get_processed_block(&req)
        .map_err(|err| format!("Failed getting processed block: {}", err))?;

    Ok(Json(JsonProcessedBlockResponse::from(&resp)))
}

/// Get the block index of a given tx out, identified by its public key.
#[get("/tx-out/<public_key_hex>/block-index")]
fn tx_out_get_block_index_by_public_key(
    state: rocket::State<State>,
    public_key_hex: String,
) -> Result<Json<JsonBlockIndexByTxPubKeyResponse>, String> {
    let tx_out_public_key = hex::decode(public_key_hex)
        .map_err(|err| format!("Failed to decode hex public key: {}", err))?;

    let mut tx_out_public_key_proto = CompressedRistretto::new();
    tx_out_public_key_proto.set_data(tx_out_public_key);

    let mut req = mc_mobilecoind_api::GetBlockIndexByTxPubKeyRequest::new();
    req.set_tx_public_key(tx_out_public_key_proto);

    let resp = state
        .mobilecoind_api_client
        .get_block_index_by_tx_pub_key(&req)
        .map_err(|err| format!("Failed getting block index: {}", err))?;

    Ok(Json(JsonBlockIndexByTxPubKeyResponse::from(&resp)))
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
        config.mobilecoind_uri,
    );

    // Set up the gRPC connection to the mobilecoind client
    let env = Arc::new(grpcio::EnvBuilder::new().build());
    let ch = ChannelBuilder::new(env)
        .max_receive_message_len(std::i32::MAX)
        .max_send_message_len(std::i32::MAX)
        .connect_to_uri(&config.mobilecoind_uri, &logger);

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
                account_key,
                add_monitor,
                remove_monitor,
                monitors,
                monitor_status,
                balance,
                utxos,
                public_address,
                create_request_code,
                parse_request_code,
                create_address_code,
                parse_address_code,
                build_and_submit,
                pay_address_code,
                generate_request_code_transaction,
                submit_tx,
                check_transfer_status,
                check_receiver_transfer_status,
                ledger_info,
                block_info,
                block_details,
                processed_block,
                tx_out_get_block_index_by_public_key,
            ],
        )
        .manage(State {
            mobilecoind_api_client,
        })
        .launch();
}
