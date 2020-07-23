// Copyright (c) 2018-2020 MobileCoin Inc.

//! Serializeable data types that wrap the mobilecoind API.

use mc_api::external::{CompressedRistretto, PublicAddress};
use serde_derive::{Deserialize, Serialize};
use std::convert::TryFrom;

#[derive(Serialize, Default)]
pub struct JsonEntropyResponse {
    pub entropy: String,
}

#[derive(Deserialize, Default)]
pub struct JsonMonitorRequest {
    pub entropy: String,
    pub first_subaddress: u64,
    pub num_subaddresses: u64,
}

#[derive(Serialize, Default)]
pub struct JsonMonitorResponse {
    pub monitor_id: String,
}

#[derive(Serialize, Default)]
pub struct JsonMonitorListResponse {
    pub monitor_id: Vec<String>,
}

#[derive(Serialize, Default)]
pub struct JsonMonitorStatusResponse {
    pub first_subaddress: u64,
    pub num_subaddresses: u64,
    pub first_block: u64,
    pub next_block: u64,
}

#[derive(Serialize, Default)]
pub struct JsonBalanceResponse {
    pub balance: String,
}

#[derive(Deserialize)]
pub struct JsonRequestCodeRequest {
    pub value: Option<u64>,
    pub memo: Option<String>,
}

#[derive(Serialize, Default)]
pub struct JsonRequestCodeResponse {
    pub request_code: String,
}

#[derive(Deserialize, Serialize, Default)]
pub struct JsonPublicAddress {
    /// Hex encoded compressed ristretto bytes
    pub view_public_key: String,

    /// Hex encoded compressed ristretto bytes
    pub spend_public_key: String,

    /// Fog Report Server Url
    pub fog_report_url: String,

    /// Hex encoded signature bytes
    pub fog_authority_sig: String,

    /// String label for fog reports
    pub fog_report_id: String,
}

// Helper conversion between json and protobuf
impl TryFrom<&JsonPublicAddress> for PublicAddress {
    type Error = String;

    fn try_from(src: &JsonPublicAddress) -> Result<PublicAddress, String> {
        // Decode the keys
        let mut view_public_key = CompressedRistretto::new();
        view_public_key.set_data(
            hex::decode(&src.view_public_key)
                .map_err(|err| format!("Failed to decode view key hex: {}", err))?,
        );
        let mut spend_public_key = CompressedRistretto::new();
        spend_public_key.set_data(
            hex::decode(&src.spend_public_key)
                .map_err(|err| format!("Failed to decode spend key hex: {}", err))?,
        );

        // Reconstruct the public address as a protobuf
        let mut public_address = PublicAddress::new();
        public_address.set_view_public_key(view_public_key);
        public_address.set_spend_public_key(spend_public_key);
        public_address.set_fog_report_url(src.fog_report_url.clone());
        public_address.set_fog_report_id(src.fog_report_id.clone());
        public_address.set_fog_authority_sig(
            hex::decode(&src.fog_authority_sig)
                .map_err(|err| format!("Failed to decode fog authority sig hex: {}", err))?,
        );

        Ok(public_address)
    }
}

#[derive(Deserialize, Serialize, Default)]
pub struct JsonReadRequestResponse {
    pub receiver: JsonPublicAddress,
    pub value: String,
    pub memo: String,
}

#[derive(Deserialize, Serialize)]
pub struct JsonSenderTxReceipt {
    pub key_images: Vec<String>,
    pub tombstone: u64,
}

#[derive(Deserialize, Serialize)]
pub struct JsonReceiverTxReceipt {
    pub recipient: JsonPublicAddress,
    pub tx_public_key: String,
    pub tx_out_hash: String,
    pub tombstone: u64,
    pub confirmation_number: String,
}

#[derive(Deserialize, Serialize)]
pub struct JsonTransferResponse {
    pub sender_tx_receipt: JsonSenderTxReceipt,
    pub receiver_tx_receipt_list: Vec<JsonReceiverTxReceipt>,
}

#[derive(Serialize, Default)]
pub struct JsonStatusResponse {
    pub status: String,
}

#[derive(Serialize, Default)]
pub struct JsonLedgerInfoResponse {
    pub block_count: String,
    pub txo_count: String,
}

#[derive(Serialize, Default)]
pub struct JsonBlockInfoResponse {
    pub key_image_count: String,
    pub txo_count: String,
}

#[derive(Serialize, Default)]
pub struct JsonBlockDetailsResponse {
    pub block_id: String,
    pub version: u32,
    pub parent_id: String,
    pub index: String,
    pub cumulative_txo_count: String,
    pub contents_hash: String,
}

#[derive(Serialize, Default)]
pub struct JsonProcessedTxOut {
    pub monitor_id: String,
    pub subaddress_index: u64,
    pub public_key: String,
    pub key_image: String,
    pub value: String, // Needs to be String since Javascript ints are not 64 bit.
    pub direction: String,
}

#[derive(Serialize, Default)]
pub struct JsonProcessedBlockResponse {
    pub tx_outs: Vec<JsonProcessedTxOut>,
}

#[derive(Deserialize)]
pub struct JsonAddressRequestCodeRequest {
    pub url: String,
}

#[derive(Serialize, Default)]
pub struct JsonAddressRequestCodeResponse {
    pub request_code: String,
}
