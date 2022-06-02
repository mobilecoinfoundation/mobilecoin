// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Serializeable data types that wrap the mobilecoind API.

use mc_api::external::PublicAddress;
use mc_util_serial::JsonU64;
use serde_derive::{Deserialize, Serialize};
use std::collections::HashMap;

/// A request to the faucet to fund an address
#[derive(Debug, Default, Deserialize, Serialize)]
pub struct JsonFaucetRequest {
    /// The address to fund
    pub b58_address: String,
    /// The token id to fund. Assumed 0 if omitted.
    pub token_id: Option<JsonU64>,
}

/// A response describing the status of the faucet server
#[derive(Debug, Default, Deserialize, Serialize)]
pub struct JsonFaucetStatus {
    /// Whether the status request was successful
    pub success: bool,
    /// The error message in case of failure
    #[serde(skip_serializing_if = "Option::is_none")]
    pub err_str: Option<String>,
    /// The b58 address of the faucet. This address can be paid to replenish the
    /// faucet.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub b58_address: String,
    /// The map of token id -> payout amount for that token id. (The recipient
    /// gets a little less because of fees.)
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub faucet_payout_amounts: HashMap<JsonU64, JsonU64>,
    /// The current balances of the faucet.
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub balances: HashMap<JsonU64, JsonU64>,
    /// The current depths of the queue of utxos for each token id. If these
    /// queues run out then the faucet needs some more time to rebuild them.
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub queue_depths: HashMap<JsonU64, JsonU64>,
}

/// A Tx receipt that the reciepient of a payment can use (with mobilecoind)
/// to track the payment. This is returned with faucet payment responses.
#[derive(Debug, Default, Deserialize, Serialize)]
pub struct JsonReceiverTxReceipt {
    /// The recipient of the payment
    pub recipient: JsonPublicAddress,
    /// The hex-encoded bytes of the tx out public key
    pub tx_public_key: String,
    /// The hex-encoded bytes of the tx out hash
    pub tx_out_hash: String,
    /// The tombstone block of the submitted transaction
    pub tombstone: u64,
    /// The hex-encoded bytes of the confirmation number
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

/// A Json encoded public address structure
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
#[derive(Debug, Default, Deserialize, Serialize)]
pub struct JsonSubmitTxResponse {
    /// Whether the payment was submitted successfully
    pub success: bool,
    /// An error message if the payment could not be submitted successfully
    #[serde(skip_serializing_if = "Option::is_none")]
    pub err_str: Option<String>,
    /// A receipt for each TxOut that was sent (just one, if submitted
    /// successfully)
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
