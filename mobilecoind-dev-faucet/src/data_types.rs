// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Serializeable data types that wrap the mobilecoind API.

use mc_api::external::PublicAddress;
use rocket::{
    http::Status,
    response::{self, content, Responder},
    Request,
};
use serde_derive::{Deserialize, Serialize};
use std::collections::HashMap;

// Represents u64 using string, when serializing to Json
// Javascript integers are not 64 bit, and so it is not really proper json.
// Using string avoids issues with some json parsers not handling large numbers
// well.
//
// This does not rely on the serde-json arbitrary precision feature, which
// (we fear) might break other things (e.g. https://github.com/serde-rs/json/issues/505)
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Hash, Serialize)]
#[serde(transparent)]
pub struct JsonU64(#[serde(with = "serde_with::rust::display_fromstr")] pub u64);

impl From<&u64> for JsonU64 {
    fn from(src: &u64) -> Self {
        Self(*src)
    }
}

impl From<&JsonU64> for u64 {
    fn from(src: &JsonU64) -> u64 {
        src.0
    }
}

impl From<JsonU64> for u64 {
    fn from(src: JsonU64) -> u64 {
        src.0
    }
}

impl AsRef<u64> for JsonU64 {
    fn as_ref(&self) -> &u64 {
        &self.0
    }
}

#[derive(Deserialize, Serialize, Default, Debug)]
pub struct JsonFaucetRequest {
    pub b58_address: String,
    pub token_id: Option<JsonU64>,
}

#[derive(Deserialize, Serialize, Default, Debug)]
pub struct JsonFaucetStatus {
    pub b58_address: String,
    pub faucet_amounts: HashMap<JsonU64, JsonU64>,
    pub balances: HashMap<JsonU64, JsonU64>,
    pub queue_depths: HashMap<JsonU64, JsonU64>,
}

#[derive(Deserialize, Serialize, Default, Debug)]
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

#[derive(Deserialize, Serialize, Default, Debug, Clone)]
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

#[derive(Deserialize, Serialize, Default, Debug)]
pub struct JsonSubmitTxResponse {
    pub success: bool,
    pub err_str: Option<String>,
    pub receiver_tx_receipt_list: Vec<JsonReceiverTxReceipt>,
}

impl From<&mc_mobilecoind_api::SubmitTxResponse> for JsonSubmitTxResponse {
    fn from(src: &mc_mobilecoind_api::SubmitTxResponse) -> Self {
        Self {
            success: true,
            err_str: None,
            receiver_tx_receipt_list: src
                .get_receiver_tx_receipt_list()
                .iter()
                .map(JsonReceiverTxReceipt::from)
                .collect(),
        }
    }
}

impl From<String> for JsonSubmitTxResponse {
    fn from(src: String) -> Self {
        Self {
            success: false,
            err_str: Some(src),
            receiver_tx_receipt_list: Default::default(),
        }
    }
}

// Implement rocket::Responder for JsonSubmitTxResponse
// If we don't do this then it is very difficult to respond to errors with
// a Json object, because we cannot implement conversions on the
// rocket::Json<...> object.
impl<'r> Responder<'r, 'static> for JsonSubmitTxResponse {
    fn respond_to(self, req: &'r Request) -> response::Result<'static> {
        let string = serde_json::to_string(&self).map_err(|_e| Status::InternalServerError)?;

        content::RawJson(string).respond_to(req)
    }
}
