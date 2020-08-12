// Copyright (c) 2018-2020 MobileCoin Inc.

//! Serializeable data types that wrap the mobilecoind API.

use mc_api::external::{CompressedRistretto, PublicAddress};
use serde_derive::{Deserialize, Serialize};
use std::convert::TryFrom;

#[derive(Serialize, Default)]
pub struct JsonEntropyResponse {
    pub entropy: String,
}

impl From<&mc_mobilecoind_api::GenerateEntropyResponse> for JsonEntropyResponse {
    fn from(src: &mc_mobilecoind_api::GenerateEntropyResponse) -> Self {
        Self {
            entropy: hex::encode(&src.entropy),
        }
    }
}

#[derive(Deserialize, Serialize, Default)]
pub struct JsonAccountKeyResponse {
    pub view_private_key: String,
    pub spend_private_key: String,
}

impl From<&mc_mobilecoind_api::GetAccountKeyResponse> for JsonAccountKeyResponse {
    fn from(src: &mc_mobilecoind_api::GetAccountKeyResponse) -> Self {
        Self {
            view_private_key: hex::encode(&src.get_account_key().get_view_private_key().get_data()),
            spend_private_key: hex::encode(
                &src.get_account_key().get_spend_private_key().get_data(),
            ),
        }
    }
}

#[derive(Deserialize, Default)]
pub struct JsonMonitorRequest {
    pub account_key: JsonAccountKeyResponse,
    pub first_subaddress: u64,
    pub num_subaddresses: u64,
}

#[derive(Serialize, Default)]
pub struct JsonMonitorResponse {
    pub monitor_id: String,
}

impl From<&mc_mobilecoind_api::AddMonitorResponse> for JsonMonitorResponse {
    fn from(src: &mc_mobilecoind_api::AddMonitorResponse) -> Self {
        Self {
            monitor_id: hex::encode(&src.monitor_id),
        }
    }
}

#[derive(Serialize, Default)]
pub struct JsonMonitorListResponse {
    pub monitor_ids: Vec<String>,
}

impl From<&mc_mobilecoind_api::GetMonitorListResponse> for JsonMonitorListResponse {
    fn from(src: &mc_mobilecoind_api::GetMonitorListResponse) -> Self {
        Self {
            monitor_ids: src.get_monitor_id_list().iter().map(hex::encode).collect(),
        }
    }
}

#[derive(Serialize, Default)]
pub struct JsonMonitorStatusResponse {
    pub first_subaddress: u64,
    pub num_subaddresses: u64,
    pub first_block: u64,
    pub next_block: u64,
}

impl From<&mc_mobilecoind_api::GetMonitorStatusResponse> for JsonMonitorStatusResponse {
    fn from(src: &mc_mobilecoind_api::GetMonitorStatusResponse) -> Self {
        let status = src.get_status();

        Self {
            first_subaddress: status.get_first_subaddress(),
            num_subaddresses: status.get_num_subaddresses(),
            first_block: status.get_first_block(),
            next_block: status.get_next_block(),
        }
    }
}

#[derive(Serialize, Default)]
pub struct JsonBalanceResponse {
    pub balance: String,
}

impl From<&mc_mobilecoind_api::GetBalanceResponse> for JsonBalanceResponse {
    fn from(src: &mc_mobilecoind_api::GetBalanceResponse) -> Self {
        Self {
            balance: src.balance.to_string(),
        }
    }
}

#[derive(Deserialize)]
pub struct JsonRequestCodeRequest {
    pub public_address: JsonPublicAddress,
    pub value: Option<u64>,
    pub memo: Option<String>,
}

#[derive(Serialize, Default)]
pub struct JsonRequestCodeResponse {
    pub request_code: String,
}

impl From<&mc_mobilecoind_api::GetRequestCodeResponse> for JsonRequestCodeResponse {
    fn from(src: &mc_mobilecoind_api::GetRequestCodeResponse) -> Self {
        Self {
            request_code: String::from(src.get_b58_code()),
        }
    }
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
    pub fog_authority_fingerprint_sig: String,

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
            fog_authority_fingerprint_sig: hex::encode(&src.get_fog_authority_fingerprint_sig()),
        }
    }
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
        public_address.set_fog_authority_fingerprint_sig(
            hex::decode(&src.fog_authority_fingerprint_sig)
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

impl From<&mc_mobilecoind_api::ReadRequestCodeResponse> for JsonReadRequestResponse {
    fn from(src: &mc_mobilecoind_api::ReadRequestCodeResponse) -> Self {
        Self {
            receiver: JsonPublicAddress::from(src.get_receiver()),
            value: src.get_value().to_string(),
            memo: src.get_memo().to_string(),
        }
    }
}

#[derive(Deserialize, Serialize)]
pub struct JsonSenderTxReceipt {
    pub key_images: Vec<String>,
    pub tombstone: u64,
}

impl From<&mc_mobilecoind_api::SenderTxReceipt> for JsonSenderTxReceipt {
    fn from(src: &mc_mobilecoind_api::SenderTxReceipt) -> Self {
        Self {
            key_images: src
                .get_key_image_list()
                .iter()
                .map(|key_image| hex::encode(key_image.get_data()))
                .collect(),
            tombstone: src.get_tombstone(),
        }
    }
}

#[derive(Deserialize, Serialize)]
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
            confirmation_number: hex::encode(&src.get_tx_out_hash()),
        }
    }
}

#[derive(Deserialize, Serialize)]
pub struct JsonTransferResponse {
    pub sender_tx_receipt: JsonSenderTxReceipt,
    pub receiver_tx_receipt_list: Vec<JsonReceiverTxReceipt>,
}

impl From<&mc_mobilecoind_api::SendPaymentResponse> for JsonTransferResponse {
    fn from(src: &mc_mobilecoind_api::SendPaymentResponse) -> Self {
        Self {
            sender_tx_receipt: JsonSenderTxReceipt::from(src.get_sender_tx_receipt()),
            receiver_tx_receipt_list: src
                .get_receiver_tx_receipt_list()
                .iter()
                .map(JsonReceiverTxReceipt::from)
                .collect(),
        }
    }
}

#[derive(Serialize, Default)]
pub struct JsonStatusResponse {
    pub status: String,
}

impl From<&mc_mobilecoind_api::GetTxStatusAsSenderResponse> for JsonStatusResponse {
    fn from(src: &mc_mobilecoind_api::GetTxStatusAsSenderResponse) -> Self {
        let status_str = match src.get_status() {
            mc_mobilecoind_api::TxStatus::Unknown => "unknown",
            mc_mobilecoind_api::TxStatus::Verified => "verified",
            mc_mobilecoind_api::TxStatus::TombstoneBlockExceeded => "failed",
            mc_mobilecoind_api::TxStatus::InvalidConfirmationNumber => "invalid_confirmation",
        };

        Self {
            status: String::from(status_str),
        }
    }
}

impl From<&mc_mobilecoind_api::GetTxStatusAsReceiverResponse> for JsonStatusResponse {
    fn from(src: &mc_mobilecoind_api::GetTxStatusAsReceiverResponse) -> Self {
        let status_str = match src.get_status() {
            mc_mobilecoind_api::TxStatus::Unknown => "unknown",
            mc_mobilecoind_api::TxStatus::Verified => "verified",
            mc_mobilecoind_api::TxStatus::TombstoneBlockExceeded => "failed",
            mc_mobilecoind_api::TxStatus::InvalidConfirmationNumber => "invalid_confirmation",
        };

        Self {
            status: String::from(status_str),
        }
    }
}

#[derive(Serialize, Default)]
pub struct JsonLedgerInfoResponse {
    pub block_count: String,
    pub txo_count: String,
}

impl From<&mc_mobilecoind_api::GetLedgerInfoResponse> for JsonLedgerInfoResponse {
    fn from(src: &mc_mobilecoind_api::GetLedgerInfoResponse) -> Self {
        Self {
            block_count: src.block_count.to_string(),
            txo_count: src.txo_count.to_string(),
        }
    }
}

#[derive(Serialize, Default)]
pub struct JsonBlockInfoResponse {
    pub key_image_count: String,
    pub txo_count: String,
}

impl From<&mc_mobilecoind_api::GetBlockInfoResponse> for JsonBlockInfoResponse {
    fn from(src: &mc_mobilecoind_api::GetBlockInfoResponse) -> Self {
        Self {
            key_image_count: src.key_image_count.to_string(),
            txo_count: src.txo_count.to_string(),
        }
    }
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

impl From<&mc_mobilecoind_api::GetBlockResponse> for JsonBlockDetailsResponse {
    fn from(src: &mc_mobilecoind_api::GetBlockResponse) -> Self {
        let block = src.get_block();

        Self {
            block_id: hex::encode(&block.get_id().get_data()),
            version: block.get_version(),
            parent_id: hex::encode(&block.get_parent_id().get_data()),
            index: block.get_index().to_string(),
            cumulative_txo_count: block.get_cumulative_txo_count().to_string(),
            contents_hash: hex::encode(&block.get_contents_hash().get_data()),
        }
    }
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

impl From<&mc_mobilecoind_api::ProcessedTxOut> for JsonProcessedTxOut {
    fn from(src: &mc_mobilecoind_api::ProcessedTxOut) -> Self {
        let direction_str = match src.direction {
            mc_mobilecoind_api::ProcessedTxOutDirection::Invalid => "invalid",
            mc_mobilecoind_api::ProcessedTxOutDirection::Received => "received",
            mc_mobilecoind_api::ProcessedTxOutDirection::Spent => "spent",
        };

        Self {
            monitor_id: hex::encode(&src.get_monitor_id()),
            subaddress_index: src.subaddress_index,
            public_key: hex::encode(&src.get_public_key().get_data()),
            key_image: hex::encode(&src.get_key_image().get_data()),
            value: src.value.to_string(),
            direction: direction_str.to_owned(),
        }
    }
}

#[derive(Serialize, Default)]
pub struct JsonProcessedBlockResponse {
    pub tx_outs: Vec<JsonProcessedTxOut>,
}

impl From<&mc_mobilecoind_api::GetProcessedBlockResponse> for JsonProcessedBlockResponse {
    fn from(src: &mc_mobilecoind_api::GetProcessedBlockResponse) -> Self {
        Self {
            tx_outs: src
                .get_tx_outs()
                .iter()
                .map(JsonProcessedTxOut::from)
                .collect(),
        }
    }
}

#[derive(Deserialize)]
pub struct JsonAddressRequestCodeRequest {
    pub url: String,
}

#[derive(Serialize, Default)]
pub struct JsonAddressRequestCodeResponse {
    pub request_code: String,
}

impl From<&mc_mobilecoind_api::GetAddressRequestCodeResponse> for JsonAddressRequestCodeResponse {
    fn from(src: &mc_mobilecoind_api::GetAddressRequestCodeResponse) -> Self {
        Self {
            request_code: String::from(src.get_b58_code()),
        }
    }
}
