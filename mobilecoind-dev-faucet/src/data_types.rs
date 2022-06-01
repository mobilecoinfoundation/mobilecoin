// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Serializeable data types that wrap the mobilecoind API.

use mc_api::external::PublicAddress;
use mc_util_serial::JsonU64;
use serde_derive::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Default, Deserialize, Serialize)]
pub struct JsonFaucetRequest {
    pub b58_address: String,
    pub token_id: Option<JsonU64>,
}

#[derive(Debug, Default, Deserialize, Serialize)]
pub struct JsonFaucetStatus {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub err_str: Option<String>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub b58_address: String,
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub faucet_payout_amounts: HashMap<JsonU64, JsonU64>,
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub balances: HashMap<JsonU64, JsonU64>,
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub queue_depths: HashMap<JsonU64, JsonU64>,
}

#[derive(Debug, Default, Deserialize, Serialize)]
pub struct JsonReceiverTxReceipt {
    pub recipient: JsonPublicAddress,
    pub tx_public_key: String,
    pub tx_out_hash: String,
    pub tombstone: u64,
    pub confirmation_number: String,
}

impl From<&mc_mobilecoind_api::ReceiverTxReceipt> for JsonReceiverTxReceipt {
    fn from(src: &mc_mobilecoind_api::ReceiverTxReceipt) -> Self {
        Self {
            recipient: JsonPublicAddress::from(src.get_recipient()),
            tx_public_key: hex::encode(&src.get_tx_public_key().get_data()),
            tx_out_hash: hex::encode(&src.get_tx_out_hash()),
            tombstone: src.get_tombstone(),
            confirmation_number: hex::encode(&src.get_confirmation_number()),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
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

impl From<&PublicAddress> for JsonPublicAddress {
    fn from(src: &PublicAddress) -> Self {
        Self {
            view_public_key: hex::encode(&src.get_view_public_key().get_data()),
            spend_public_key: hex::encode(&src.get_spend_public_key().get_data()),
            fog_report_url: String::from(src.get_fog_report_url()),
            fog_report_id: String::from(src.get_fog_report_id()),
            fog_authority_sig: hex::encode(&src.get_fog_authority_sig()),
        }
    }
}

/// Related to (but not the same as) mobilecoind_api::SubmitTxResponse
///
/// This json includes a "success" field and an "err_str" field, so it is
/// effectively like an enum over `SubmitTxResponse` and `String`.
///
/// The `From` conversions set `success` to true or false appropriately.
/// In the success case, we only include the receiver tx receipt list, because
/// the faucet user cannot make use of the sender tx receipt.
#[derive(Deserialize, Serialize, Default, Debug)]
pub struct JsonSubmitTxResponse {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub err_str: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub receiver_tx_receipt_list: Vec<JsonReceiverTxReceipt>,
}

impl From<mc_mobilecoind_api::SubmitTxResponse> for JsonSubmitTxResponse {
    fn from(mut src: mc_mobilecoind_api::SubmitTxResponse) -> Self {
        Self {
            success: true,
            err_str: None,
            receiver_tx_receipt_list: src
                .take_receiver_tx_receipt_list()
                .iter()
                .map(JsonReceiverTxReceipt::from)
                .collect(),
        }
    }
}
