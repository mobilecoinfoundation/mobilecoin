// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Serializeable data types that wrap the mobilecoind API.

use mc_api::external::PublicAddress;
use mc_mobilecoind_api as api;
use mc_transaction_core::TokenId;
use mc_util_serial::JsonU64;
use serde_derive::{Deserialize, Serialize};
use std::collections::HashMap;

/// A request to the faucet to fund an address
#[derive(Debug, Default, Deserialize, Serialize)]
pub struct JsonFaucetRequest {
    /// The address to fund
    pub b58_address: String,
    /// The token id to fund. Assumed 0 if omitted.
    #[serde(default)]
    pub token_id: JsonU64,
}

/// A response describing the status of the faucet server
#[derive(Debug, Default, Deserialize, Serialize)]
pub struct JsonFaucetStatus {
    /// Whether the status request was successful
    pub success: bool,
    /// The error message in case of failure
    #[serde(skip_serializing_if = "String::is_empty")]
    pub err_str: String,
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

/// The data obtained when the faucet gets its status successfully
pub struct FaucetStatus {
    /// The b58 address of the faucet
    pub b58_address: String,
    /// The faucet payout amounts
    pub faucet_payout_amounts: HashMap<TokenId, u64>,
    /// The balance in each token id
    pub balances: HashMap<TokenId, u64>,
    /// The queue depth for each token id
    pub queue_depths: HashMap<TokenId, u64>,
}

impl From<Result<FaucetStatus, String>> for JsonFaucetStatus {
    fn from(src: Result<FaucetStatus, String>) -> Self {
        match src {
            Ok(FaucetStatus {
                b58_address,
                faucet_payout_amounts,
                balances,
                queue_depths,
            }) => JsonFaucetStatus {
                success: true,
                err_str: String::default(),
                b58_address,
                faucet_payout_amounts: faucet_payout_amounts
                    .into_iter()
                    .map(convert_balance_pair)
                    .collect(),
                balances: balances.into_iter().map(convert_balance_pair).collect(),
                queue_depths: queue_depths.into_iter().map(convert_balance_pair).collect(),
            },
            Err(err_str) => JsonFaucetStatus {
                success: false,
                err_str,
                ..Default::default()
            },
        }
    }
}

fn convert_balance_pair(pair: (TokenId, u64)) -> (JsonU64, JsonU64) {
    (JsonU64(*pair.0), JsonU64(pair.1))
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

impl From<&api::ReceiverTxReceipt> for JsonReceiverTxReceipt {
    fn from(src: &api::ReceiverTxReceipt) -> Self {
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
            fog_report_url: src.get_fog_report_url().into(),
            fog_report_id: src.get_fog_report_id().into(),
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
    #[serde(skip_serializing_if = "String::is_empty")]
    pub err_str: String,
    /// A receipt for each TxOut that was sent (just one, if submitted
    /// successfully)
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub receiver_tx_receipt_list: Vec<JsonReceiverTxReceipt>,
}

impl From<Result<api::SubmitTxResponse, String>> for JsonSubmitTxResponse {
    fn from(src: Result<api::SubmitTxResponse, String>) -> Self {
        match src {
            Ok(mut resp) => Self {
                success: true,
                err_str: String::default(),
                receiver_tx_receipt_list: resp
                    .take_receiver_tx_receipt_list()
                    .iter()
                    .map(JsonReceiverTxReceipt::from)
                    .collect(),
            },
            Err(err_str) => Self {
                success: false,
                err_str,
                ..Default::default()
            },
        }
    }
}
