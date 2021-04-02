// Copyright (c) 2018-2021 The MobileCoin Foundation

//! JSON wrapper for the mobilecoind API.

#![feature(proc_macro_hygiene, decl_macro)]

use grpcio::ChannelBuilder;
use mc_api::external::{CompressedRistretto, PublicAddress, RistrettoPrivate};
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

/// Set the password for the mobilecoind-db
#[post("/set-password", format = "json", data = "<password>")]
fn set_password(
    state: rocket::State<State>,
    password: Json<JsonPasswordRequest>,
) -> Result<Json<JsonPasswordResponse>, String> {
    let mut req = mc_mobilecoind_api::SetDbPasswordRequest::new();
    req.set_password(
        hex::decode(password.password.clone())
            .map_err(|err| format!("Failed decoding password hex: {}", err))?,
    );
    let _resp = state
        .mobilecoind_api_client
        .set_db_password(&req)
        .map_err(|err| format!("Failed setting password: {}", err))?;
    Ok(Json(JsonPasswordResponse { success: true }))
}

/// Unlock a previously-encrypted mobilecoind-db
#[post("/unlock-db", format = "json", data = "<password>")]
fn unlock_db(
    state: rocket::State<State>,
    password: Json<JsonUnlockDbRequest>,
) -> Result<Json<JsonUnlockDbResponse>, String> {
    let mut req = mc_mobilecoind_api::UnlockDbRequest::new();
    req.set_password(
        hex::decode(password.password.clone())
            .map_err(|err| format!("Failed decoding password hex: {}", err))?,
    );
    let _resp = state
        .mobilecoind_api_client
        .unlock_db(&req)
        .map_err(|err| format!("Failed unlocking database: {}", err))?;
    Ok(Json(JsonUnlockDbResponse { success: true }))
}

/// Requests a new root entropy from mobilecoind
#[post("/entropy")]
fn entropy(state: rocket::State<State>) -> Result<Json<JsonRootEntropyResponse>, String> {
    let resp = state
        .mobilecoind_api_client
        .generate_root_entropy(&mc_mobilecoind_api::Empty::new())
        .map_err(|err| format!("Failed getting entropy: {}", err))?;
    Ok(Json(JsonRootEntropyResponse::from(&resp)))
}

#[get("/entropy/<root_entropy>")]
fn account_key_from_root_entropy(
    state: rocket::State<State>,
    root_entropy: String,
) -> Result<Json<JsonAccountKeyResponse>, String> {
    let entropy =
        hex::decode(root_entropy).map_err(|err| format!("Failed to decode hex key: {}", err))?;

    let mut req = mc_mobilecoind_api::GetAccountKeyFromRootEntropyRequest::new();
    req.set_root_entropy(entropy.to_vec());

    let resp = state
        .mobilecoind_api_client
        .get_account_key_from_root_entropy(&req)
        .map_err(|err| format!("Failed getting account key for root entropy: {}", err))?;

    Ok(Json(JsonAccountKeyResponse::from(&resp)))
}

/// Requests a new mnemonic from mobilecoind
#[post("/mnemonic")]
fn mnemonic(state: rocket::State<State>) -> Result<Json<JsonMnemonicResponse>, String> {
    let resp = state
        .mobilecoind_api_client
        .generate_mnemonic(&mc_mobilecoind_api::Empty::new())
        .map_err(|err| format!("Failed getting entropy: {}", err))?;
    Ok(Json(JsonMnemonicResponse::from(&resp)))
}

#[post("/account-key-from-mnemonic", format = "json", data = "<mnemonic>")]
fn account_key_from_mnemonic(
    state: rocket::State<State>,
    mnemonic: Json<JsonMnemonicResponse>,
) -> Result<Json<JsonAccountKeyResponse>, String> {
    let mut req = mc_mobilecoind_api::GetAccountKeyFromMnemonicRequest::new();
    req.set_mnemonic(mnemonic.mnemonic.clone());

    let resp = state
        .mobilecoind_api_client
        .get_account_key_from_mnemonic(&req)
        .map_err(|err| format!("Failed getting account key for mnemonic: {}", err))?;

    Ok(Json(JsonAccountKeyResponse::from(&resp)))
}

/// Creates a monitor. Data for the key and range is POSTed using the struct
/// above.
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

    // The response contains the public keys encoded in the read request, as well as
    // a memo and requested value. This can be used as-is in the transfer call
    // below, or the value can be modified.
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

/// Performs a transfer from a monitor and subaddress. The public keys and
/// amount are in the POST data.
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
    if let Some(subaddress) = transfer.change_subaddress.as_ref() {
        req.set_override_change_subaddress(true);
        req.set_change_subaddress(
            subaddress
                .parse::<u64>()
                .map_err(|err| format!("Failed to parse change subaddress: {}", err))?,
        )
    }

    let resp = state
        .mobilecoind_api_client
        .send_payment(&req)
        .map_err(|err| format!("Failed to send payment: {}", err))?;

    // The receipt from the payment request can be used by the status check below
    Ok(Json(JsonSendPaymentResponse::from(&resp)))
}

/// Performs a transfer from a monitor and subaddress to a given address
/// code/amount.
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
    if let Some(subaddress) = transfer.change_subaddress.as_ref() {
        req.set_override_change_subaddress(true);
        req.set_change_subaddress(
            subaddress
                .parse::<u64>()
                .map_err(|err| format!("Failed to parse change subaddress: {}", err))?,
        )
    }

    let resp = state
        .mobilecoind_api_client
        .pay_address_code(&req)
        .map_err(|err| format!("Failed to send payment: {}", err))?;

    // The receipt from the payment request can be used by the status check below
    Ok(Json(JsonSendPaymentResponse::from(&resp)))
}

/// Creates a transaction proposal. This can be used in an offline transaction
/// construction flow, where the proposal is created on the offline machine, and
/// copied to the connected machine for submission, via submit-tx.
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
#[post("/tx/status-as-sender", format = "json", data = "<submit_response>")]
fn check_transfer_status(
    state: rocket::State<State>,
    submit_response: Json<JsonSubmitTxResponse>,
) -> Result<Json<JsonStatusResponse>, String> {
    let resp = state
        .mobilecoind_api_client
        .get_tx_status_as_sender(
            &mc_mobilecoind_api::SubmitTxResponse::try_from(&submit_response.0)
                .map_err(|err| format!("Could not convert JsonSubmitTxResponse: {}", err))?,
        )
        .map_err(|err| format!("Failed getting status: {}", err))?;

    Ok(Json(JsonStatusResponse::from(&resp)))
}

/// Checks the status of a transfer given data for a specific receiver
/// The sender of the transaction will take specific receipt data from the
/// /transfer call and distribute it to the recipient(s) so they can verify that
/// a transaction has been processed and the the person supplying the receipt
/// can prove they initiated it. This API is tied to a specific monitor id since
/// the account information is required in order to validate the confirmation
/// number.
#[post(
    "/monitors/<monitor_hex>/tx-status-as-receiver",
    format = "json",
    data = "<receipt>"
)]
fn check_receiver_transfer_status(
    state: rocket::State<State>,
    monitor_hex: String,
    receipt: Json<JsonReceiverTxReceipt>,
) -> Result<Json<JsonStatusResponse>, String> {
    let monitor_id =
        hex::decode(monitor_hex).map_err(|err| format!("Failed to decode monitor hex: {}", err))?;

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
    req.set_monitor_id(monitor_id);

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

#[post("/tx-out/proof-of-membership", format = "json", data = "<request>")]
/// Get a proof of membership for each queried TxOut.
fn get_proof_of_membership(
    state: rocket::State<State>,
    request: Json<JsonMembershipProofRequest>,
) -> Result<Json<JsonMembershipProofResponse>, String> {
    // Requested TxOuts.
    let outputs: Vec<mc_api::external::TxOut> = request
        .outputs
        .iter()
        .map(mc_api::external::TxOut::try_from)
        .collect::<Result<Vec<_>, _>>()?;

    // Make gRPC request.
    let mut get_membership_proofs_request = mc_mobilecoind_api::GetMembershipProofsRequest::new();
    get_membership_proofs_request.set_outputs(RepeatedField::from_vec(outputs));

    let get_membership_proofs_response = state
        .mobilecoind_api_client
        .get_membership_proofs(&get_membership_proofs_request)
        .map_err(|err| format!("Failed getting membership proofs: {}", err))?;

    // Return JSON response
    let outputs_and_proofs: Vec<(JsonTxOut, JsonTxOutMembershipProof)> =
        get_membership_proofs_response
            .get_output_list()
            .iter()
            .map(|tx_out_with_proof| {
                let tx_out = JsonTxOut::from(tx_out_with_proof.get_output());
                let proof = JsonTxOutMembershipProof::from(tx_out_with_proof.get_proof());
                (tx_out, proof)
            })
            .collect();

    let (outputs, membership_proofs): (Vec<JsonTxOut>, Vec<JsonTxOutMembershipProof>) =
        outputs_and_proofs.into_iter().unzip();

    let response = JsonMembershipProofResponse {
        outputs,
        membership_proofs,
    };

    Ok(Json(response))
}

#[post("/tx-out/mixin", format = "json", data = "<request>")]
/// Get a list of TxOuts for use as mixins.
fn get_mixins(
    state: rocket::State<State>,
    request: Json<JsonMixinRequest>,
) -> Result<Json<JsonMixinResponse>, String> {
    let num_mixins = request.num_mixins;
    let excluded: Vec<mc_api::external::TxOut> = request
        .excluded
        .iter()
        .map(mc_api::external::TxOut::try_from)
        .collect::<Result<Vec<_>, _>>()?;

    // Make gRPC request
    let mut get_mixins_request = mc_mobilecoind_api::GetMixinsRequest::new();
    get_mixins_request.set_num_mixins(num_mixins);
    get_mixins_request.set_excluded(RepeatedField::from_vec(excluded));

    let get_mixins_response = state
        .mobilecoind_api_client
        .get_mixins(&get_mixins_request)
        .map_err(|err| format!("Failed getting mixins: {}", err))?;

    let mixins_and_proofs: Vec<(JsonTxOut, JsonTxOutMembershipProof)> = get_mixins_response
        .get_mixins()
        .iter()
        .map(|tx_out_with_proof| {
            let tx_out = JsonTxOut::from(tx_out_with_proof.get_output());
            let proof = JsonTxOutMembershipProof::from(tx_out_with_proof.get_proof());
            (tx_out, proof)
        })
        .collect();

    let (mixins, membership_proofs): (Vec<JsonTxOut>, Vec<JsonTxOutMembershipProof>) =
        mixins_and_proofs.into_iter().unzip();

    let response = JsonMixinResponse {
        mixins,
        membership_proofs,
    };

    Ok(Json(response))
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
    let env = Arc::new(grpcio::EnvBuilder::new().cq_count(1).build());
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
                set_password,
                unlock_db,
                entropy,
                account_key_from_root_entropy,
                mnemonic,
                account_key_from_mnemonic,
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
                get_mixins,
                get_proof_of_membership,
            ],
        )
        .manage(State {
            mobilecoind_api_client,
        })
        .launch();
}
