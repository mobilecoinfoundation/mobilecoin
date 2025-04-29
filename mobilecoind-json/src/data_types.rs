// Copyright (c) 2018-2023 The MobileCoin Foundation

//! Serializeable data types that wrap the mobilecoind API.

use mc_api::external::{
    CompressedRistretto, EncryptedFogHint, EncryptedMemo, InputRules, KeyImage, MaskedAmount,
    PublicAddress, RingMlsag, SignatureRctBulletproofs, Tx, TxIn, TxOutMembershipElement,
    TxOutMembershipHash, TxOutMembershipProof, TxPrefix,
};
use mc_mobilecoind_api as api;
use mc_util_serial::JsonU64;
use serde_derive::{Deserialize, Serialize};

#[derive(Deserialize, Default, Debug)]
pub struct JsonPasswordRequest {
    pub password: String,
}

#[derive(Serialize, Default, Debug)]
pub struct JsonPasswordResponse {
    pub success: bool,
}

#[derive(Deserialize, Default, Debug)]
pub struct JsonUnlockDbRequest {
    pub password: String,
}

#[derive(Serialize, Default, Debug)]
pub struct JsonUnlockDbResponse {
    pub success: bool,
}

#[derive(Serialize, Default, Debug)]
pub struct JsonRootEntropyResponse {
    pub entropy: String,
}

impl From<&api::GenerateRootEntropyResponse> for JsonRootEntropyResponse {
    fn from(src: &api::GenerateRootEntropyResponse) -> Self {
        Self {
            entropy: hex::encode(&src.root_entropy),
        }
    }
}

#[derive(Deserialize, Serialize, Default, Debug)]
pub struct JsonMnemonicResponse {
    pub mnemonic: String,
}

impl From<&api::GenerateMnemonicResponse> for JsonMnemonicResponse {
    fn from(src: &api::GenerateMnemonicResponse) -> Self {
        Self {
            mnemonic: src.mnemonic.clone(),
        }
    }
}

#[derive(Deserialize, Serialize, Default, Debug)]
pub struct JsonAccountKeyResponse {
    pub view_private_key: String,
    pub spend_private_key: String,
}

impl From<&api::GetAccountKeyResponse> for JsonAccountKeyResponse {
    fn from(src: &api::GetAccountKeyResponse) -> Self {
        let default_account_key = Default::default();
        let account_key = src.account_key.as_ref().unwrap_or(&default_account_key);
        Self {
            view_private_key: hex::encode(
                account_key
                    .view_private_key
                    .as_ref()
                    .unwrap_or(&Default::default())
                    .data
                    .as_slice(),
            ),
            spend_private_key: hex::encode(
                account_key
                    .spend_private_key
                    .as_ref()
                    .unwrap_or(&Default::default())
                    .data
                    .as_slice(),
            ),
        }
    }
}

#[derive(Deserialize, Default, Debug)]
pub struct JsonMonitorRequest {
    pub account_key: JsonAccountKeyResponse,
    pub first_subaddress: u64,
    pub num_subaddresses: u64,
}

#[derive(Serialize, Default, Debug)]
pub struct JsonMonitorResponse {
    pub monitor_id: String,
    pub is_new: bool,
}

impl From<&api::AddMonitorResponse> for JsonMonitorResponse {
    fn from(src: &api::AddMonitorResponse) -> Self {
        Self {
            monitor_id: hex::encode(&src.monitor_id),
            is_new: src.is_new,
        }
    }
}

#[derive(Serialize, Default, Debug)]
pub struct JsonMonitorListResponse {
    pub monitor_ids: Vec<String>,
}

impl From<&api::GetMonitorListResponse> for JsonMonitorListResponse {
    fn from(src: &api::GetMonitorListResponse) -> Self {
        Self {
            monitor_ids: src.monitor_id_list.iter().map(hex::encode).collect(),
        }
    }
}

#[derive(Serialize, Default, Debug)]
pub struct JsonMonitorStatusResponse {
    pub first_subaddress: u64,
    pub num_subaddresses: u64,
    pub first_block: u64,
    pub next_block: u64,
}

impl From<&api::GetMonitorStatusResponse> for JsonMonitorStatusResponse {
    fn from(src: &api::GetMonitorStatusResponse) -> Self {
        let default_status = Default::default();
        let status = src.status.as_ref().unwrap_or(&default_status);

        Self {
            first_subaddress: status.first_subaddress,
            num_subaddresses: status.num_subaddresses,
            first_block: status.first_block,
            next_block: status.next_block,
        }
    }
}

#[derive(Serialize, Default, Debug)]
pub struct JsonBalanceResponse {
    pub balance: String,
}

impl From<&api::GetBalanceResponse> for JsonBalanceResponse {
    fn from(src: &api::GetBalanceResponse) -> Self {
        Self {
            balance: src.balance.to_string(),
        }
    }
}

#[derive(Serialize, Deserialize, Default, Debug)]
pub struct JsonUnspentTxOut {
    pub tx_out: JsonTxOut,
    pub subaddress_index: u64,
    pub key_image: String,
    pub value: JsonU64,
    pub attempted_spend_height: u64,
    pub attempted_spend_tombstone: u64,
    pub monitor_id: String,
}

impl From<&api::UnspentTxOut> for JsonUnspentTxOut {
    fn from(src: &api::UnspentTxOut) -> Self {
        Self {
            tx_out: src.tx_out.as_ref().unwrap_or(&Default::default()).into(),
            subaddress_index: src.subaddress_index,
            key_image: hex::encode(
                src.key_image
                    .as_ref()
                    .unwrap_or(&Default::default())
                    .data
                    .as_slice(),
            ),
            value: JsonU64(src.value),
            attempted_spend_height: src.attempted_spend_height,
            attempted_spend_tombstone: src.attempted_spend_tombstone,
            monitor_id: hex::encode(src.monitor_id.as_slice()),
        }
    }
}

// Helper conversion between json and protobuf
impl TryFrom<&JsonUnspentTxOut> for api::UnspentTxOut {
    type Error = String;

    fn try_from(src: &JsonUnspentTxOut) -> Result<api::UnspentTxOut, String> {
        // Reconstruct the public address as a protobuf
        Ok(api::UnspentTxOut {
            tx_out: Some(
                mc_api::external::TxOut::try_from(&src.tx_out)
                    .map_err(|err| format!("Failed to get TxOut: {err}"))?,
            ),
            subaddress_index: src.subaddress_index,
            key_image: Some(KeyImage {
                data: hex::decode(&src.key_image)
                    .map_err(|err| format!("Failed to decode key image hex: {err}"))?,
            }),
            value: src.value.into(),
            attempted_spend_height: src.attempted_spend_height,
            attempted_spend_tombstone: src.attempted_spend_tombstone,
            monitor_id: hex::decode(&src.monitor_id)
                .map_err(|err| format!("Failed to decode monitor id hex: {err}"))?,
            ..Default::default()
        })
    }
}

#[derive(Serialize, Default, Debug)]
pub struct JsonUtxosResponse {
    pub output_list: Vec<JsonUnspentTxOut>,
}

impl From<&api::GetUnspentTxOutListResponse> for JsonUtxosResponse {
    fn from(src: &api::GetUnspentTxOutListResponse) -> Self {
        Self {
            output_list: src.output_list.iter().map(JsonUnspentTxOut::from).collect(),
        }
    }
}

#[derive(Deserialize, Default, Debug)]
pub struct JsonCreateRequestCodeRequest {
    pub receiver: JsonPublicAddress,
    pub value: Option<JsonU64>,
    pub memo: Option<String>,
}

#[derive(Serialize, Default, Debug)]
pub struct JsonCreateRequestCodeResponse {
    pub b58_request_code: String,
}

impl From<&api::CreateRequestCodeResponse> for JsonCreateRequestCodeResponse {
    fn from(src: &api::CreateRequestCodeResponse) -> Self {
        Self {
            b58_request_code: src.b58_code.clone(),
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
            view_public_key: hex::encode(
                src.view_public_key
                    .as_ref()
                    .unwrap_or(&Default::default())
                    .data
                    .as_slice(),
            ),
            spend_public_key: hex::encode(
                src.spend_public_key
                    .as_ref()
                    .unwrap_or(&Default::default())
                    .data
                    .as_slice(),
            ),
            fog_report_url: src.fog_report_url.clone(),
            fog_report_id: src.fog_report_id.clone(),
            fog_authority_sig: hex::encode(src.fog_authority_sig.as_slice()),
        }
    }
}

#[derive(Deserialize, Serialize, Default, Debug)]
pub struct JsonPublicAddressResponse {
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

    /// b58-encoded public address
    pub b58_address_code: String,
}

impl From<&api::GetPublicAddressResponse> for JsonPublicAddressResponse {
    fn from(src: &api::GetPublicAddressResponse) -> Self {
        let default_address = Default::default();
        let public_address = src.public_address.as_ref().unwrap_or(&default_address);
        Self {
            view_public_key: hex::encode(
                public_address
                    .view_public_key
                    .as_ref()
                    .unwrap_or(&Default::default())
                    .data
                    .as_slice(),
            ),
            spend_public_key: hex::encode(
                public_address
                    .spend_public_key
                    .as_ref()
                    .unwrap_or(&Default::default())
                    .data
                    .as_slice(),
            ),
            fog_report_url: public_address.fog_report_url.clone(),
            fog_report_id: public_address.fog_report_id.clone(),
            fog_authority_sig: hex::encode(public_address.fog_authority_sig.as_slice()),
            b58_address_code: src.b58_code.to_string(),
        }
    }
}

// Helper conversion between json and protobuf
impl TryFrom<&JsonPublicAddress> for PublicAddress {
    type Error = String;

    fn try_from(src: &JsonPublicAddress) -> Result<PublicAddress, String> {
        // Decode the keys
        let view_public_key = CompressedRistretto {
            data: hex::decode(&src.view_public_key)
                .map_err(|err| format!("Failed to decode view key hex: {err}"))?,
        };
        let spend_public_key = CompressedRistretto {
            data: hex::decode(&src.spend_public_key)
                .map_err(|err| format!("Failed to decode spend key hex: {err}"))?,
        };

        // Reconstruct the public address as a protobuf
        Ok(PublicAddress {
            view_public_key: Some(view_public_key),
            spend_public_key: Some(spend_public_key),
            fog_report_url: src.fog_report_url.clone(),
            fog_report_id: src.fog_report_id.clone(),
            fog_authority_sig: hex::decode(&src.fog_authority_sig)
                .map_err(|err| format!("Failed to decode fog authority sig hex: {err}"))?,
        })
    }
}

#[derive(Deserialize, Serialize, Default, Debug)]
pub struct JsonParseRequestCodeResponse {
    pub receiver: JsonPublicAddress,
    pub value: JsonU64,
    pub memo: String,
}

impl From<&api::ParseRequestCodeResponse> for JsonParseRequestCodeResponse {
    fn from(src: &api::ParseRequestCodeResponse) -> Self {
        Self {
            receiver: JsonPublicAddress::from(src.receiver.as_ref().unwrap_or(&Default::default())),
            value: JsonU64(src.value),
            memo: src.memo.to_string(),
        }
    }
}

#[derive(Deserialize, Default, Debug)]
pub struct JsonCreateAddressCodeRequest {
    pub receiver: JsonPublicAddress,
}

#[derive(Serialize, Default, Debug)]
pub struct JsonCreateAddressCodeResponse {
    pub b58_code: String,
}

impl From<&api::CreateAddressCodeResponse> for JsonCreateAddressCodeResponse {
    fn from(src: &api::CreateAddressCodeResponse) -> Self {
        Self {
            b58_code: src.b58_code.clone(),
        }
    }
}

#[derive(Deserialize, Serialize, Default, Debug)]
pub struct JsonParseAddressCodeResponse {
    pub receiver: JsonPublicAddress,
}

impl From<&api::ParseAddressCodeResponse> for JsonParseAddressCodeResponse {
    fn from(src: &api::ParseAddressCodeResponse) -> Self {
        Self {
            receiver: JsonPublicAddress::from(src.receiver.as_ref().unwrap_or(&Default::default())),
        }
    }
}

#[derive(Deserialize, Serialize, Default, Debug)]
pub struct JsonSenderTxReceipt {
    pub key_images: Vec<String>,
    pub tombstone: u64,
}

impl From<&api::SenderTxReceipt> for JsonSenderTxReceipt {
    fn from(src: &api::SenderTxReceipt) -> Self {
        Self {
            key_images: src
                .key_image_list
                .iter()
                .map(|key_image| hex::encode(key_image.data.as_slice()))
                .collect(),
            tombstone: src.tombstone,
        }
    }
}

#[derive(Deserialize, Serialize, Default, Debug)]
pub struct JsonReceiverTxReceipt {
    pub recipient: JsonPublicAddress,
    pub tx_public_key: String,
    pub tx_out_hash: String,
    pub tombstone: u64,
    pub confirmation_number: String,
}

impl From<&api::ReceiverTxReceipt> for JsonReceiverTxReceipt {
    fn from(src: &api::ReceiverTxReceipt) -> Self {
        Self {
            recipient: JsonPublicAddress::from(
                src.recipient.as_ref().unwrap_or(&Default::default()),
            ),
            tx_public_key: hex::encode(
                src.tx_public_key
                    .as_ref()
                    .unwrap_or(&Default::default())
                    .data
                    .as_slice(),
            ),
            tx_out_hash: hex::encode(src.tx_out_hash.as_slice()),
            tombstone: src.tombstone,
            confirmation_number: hex::encode(src.confirmation_number.as_slice()),
        }
    }
}

#[derive(Deserialize, Serialize, Default, Debug)]
pub struct JsonSendPaymentRequest {
    pub request_data: JsonParseRequestCodeResponse,
    pub max_input_utxo_value: Option<JsonU64>,
    pub change_subaddress: Option<JsonU64>,
}

#[derive(Deserialize, Serialize, Default, Debug)]
pub struct JsonSendPaymentResponse {
    pub sender_tx_receipt: JsonSenderTxReceipt,
    pub receiver_tx_receipt_list: Vec<JsonReceiverTxReceipt>,
}

impl From<&api::SendPaymentResponse> for JsonSendPaymentResponse {
    fn from(src: &api::SendPaymentResponse) -> Self {
        Self {
            sender_tx_receipt: JsonSenderTxReceipt::from(
                src.sender_tx_receipt
                    .as_ref()
                    .unwrap_or(&Default::default()),
            ),
            receiver_tx_receipt_list: src
                .receiver_tx_receipt_list
                .iter()
                .map(JsonReceiverTxReceipt::from)
                .collect(),
        }
    }
}

#[derive(Deserialize, Serialize, Debug)]
pub struct JsonPayAddressCodeRequest {
    pub receiver_b58_address_code: String,
    pub value: JsonU64,
    pub max_input_utxo_value: Option<JsonU64>,
    pub change_subaddress: Option<JsonU64>,
}

#[derive(Deserialize, Serialize, Default, Debug, Clone)]
pub struct JsonOutlay {
    pub value: JsonU64,
    pub receiver: JsonPublicAddress,
}

impl From<&api::Outlay> for JsonOutlay {
    fn from(src: &api::Outlay) -> Self {
        Self {
            value: JsonU64(src.value),
            receiver: src.receiver.as_ref().unwrap_or(&Default::default()).into(),
        }
    }
}

impl TryFrom<&JsonOutlay> for api::Outlay {
    type Error = String;

    fn try_from(src: &JsonOutlay) -> Result<api::Outlay, String> {
        Ok(api::Outlay {
            value: src.value.into(),
            receiver: Some(
                PublicAddress::try_from(&src.receiver)
                    .map_err(|err| format!("Could not convert receiver: {err}"))?,
            ),
            ..Default::default()
        })
    }
}

#[derive(Deserialize, Serialize, Default, Debug, Clone)]
pub struct JsonOutlayV2 {
    pub value: JsonU64,
    pub receiver: JsonPublicAddress,
    pub token_id: JsonU64,
}

impl From<&api::OutlayV2> for JsonOutlayV2 {
    fn from(src: &api::OutlayV2) -> Self {
        Self {
            value: JsonU64(src.value),
            token_id: JsonU64(src.token_id),
            receiver: src.receiver.as_ref().unwrap_or(&Default::default()).into(),
        }
    }
}

impl TryFrom<&JsonOutlayV2> for api::OutlayV2 {
    type Error = String;

    fn try_from(src: &JsonOutlayV2) -> Result<api::OutlayV2, String> {
        Ok(api::OutlayV2 {
            value: src.value.into(),
            token_id: src.token_id.into(),
            receiver: Some(
                PublicAddress::try_from(&src.receiver)
                    .map_err(|err| format!("Could not convert receiver: {err}"))?,
            ),
            ..Default::default()
        })
    }
}

#[derive(Deserialize, Serialize, Default, Debug, Clone)]
pub struct JsonMaskedAmount {
    pub commitment: String,
    pub masked_value: JsonU64,
    pub masked_token_id: String,
    pub version: Option<u32>,
}

impl From<&mc_api::external::tx_out::MaskedAmount> for JsonMaskedAmount {
    fn from(src: &mc_api::external::tx_out::MaskedAmount) -> Self {
        match src {
            mc_api::external::tx_out::MaskedAmount::MaskedAmountV1(src) => Self {
                commitment: hex::encode(
                    src.commitment
                        .as_ref()
                        .unwrap_or(&Default::default())
                        .data
                        .as_slice(),
                ),
                masked_value: JsonU64(src.masked_value),
                masked_token_id: hex::encode(src.masked_token_id.as_slice()),
                version: Some(1),
            },
            mc_api::external::tx_out::MaskedAmount::MaskedAmountV2(src) => Self {
                commitment: hex::encode(
                    src.commitment
                        .as_ref()
                        .unwrap_or(&Default::default())
                        .data
                        .as_slice(),
                ),
                masked_value: JsonU64(src.masked_value),
                masked_token_id: hex::encode(src.masked_token_id.as_slice()),
                version: Some(2),
            },
        }
    }
}

// Helper conversion between json and protobuf
impl TryFrom<&JsonMaskedAmount> for mc_api::external::tx_out::MaskedAmount {
    type Error = String;

    fn try_from(src: &JsonMaskedAmount) -> Result<mc_api::external::tx_out::MaskedAmount, String> {
        let commitment = CompressedRistretto {
            data: hex::decode(&src.commitment)
                .map_err(|err| format!("Failed to decode commitment hex: {err}"))?,
        };
        let masked_amount = MaskedAmount {
            commitment: Some(commitment),
            masked_value: src.masked_value.into(),
            masked_token_id: hex::decode(&src.masked_token_id)
                .map_err(|err| format!("Failed to decode masked token id hex: {err}"))?,
        };

        match src.version {
            None | Some(1) => Ok(mc_api::external::tx_out::MaskedAmount::MaskedAmountV1(
                masked_amount,
            )),
            Some(2) => Ok(mc_api::external::tx_out::MaskedAmount::MaskedAmountV2(
                masked_amount,
            )),
            Some(other) => Err(format!("Unknown masked amount version: {other}")),
        }
    }
}

#[derive(Deserialize, Serialize, Default, Debug, Clone)]
pub struct JsonTxOut {
    pub masked_amount: Option<JsonMaskedAmount>,
    pub target_key: String,
    pub public_key: String,
    pub e_fog_hint: String,
    pub e_memo: String,
}

impl From<&mc_api::external::TxOut> for JsonTxOut {
    fn from(src: &mc_api::external::TxOut) -> Self {
        Self {
            masked_amount: src.masked_amount.as_ref().map(Into::into),
            target_key: hex::encode(
                src.target_key
                    .as_ref()
                    .unwrap_or(&Default::default())
                    .data
                    .as_slice(),
            ),
            public_key: hex::encode(
                src.public_key
                    .as_ref()
                    .unwrap_or(&Default::default())
                    .data
                    .as_slice(),
            ),
            e_fog_hint: hex::encode(
                src.e_fog_hint
                    .as_ref()
                    .unwrap_or(&Default::default())
                    .data
                    .as_slice(),
            ),
            e_memo: hex::encode(
                src.e_memo
                    .as_ref()
                    .unwrap_or(&Default::default())
                    .data
                    .as_slice(),
            ),
        }
    }
}

// Helper conversion between json and protobuf
impl TryFrom<&JsonTxOut> for mc_api::external::TxOut {
    type Error = String;

    fn try_from(src: &JsonTxOut) -> Result<mc_api::external::TxOut, String> {
        let target_key = CompressedRistretto {
            data: hex::decode(&src.target_key)
                .map_err(|err| format!("Failed to decode target key hex: {err}"))?,
        };
        let public_key = CompressedRistretto {
            data: hex::decode(&src.public_key)
                .map_err(|err| format!("Failed to decode public key hex: {err}"))?,
        };
        let e_fog_hint = EncryptedFogHint {
            data: hex::decode(&src.e_fog_hint)
                .map_err(|err| format!("Failed to decode e_fog_hint hex: {err}"))?,
        };
        let memo_data = hex::decode(&src.e_memo)
            .map_err(|err| format!("Failed to decode e_memo hex: {err}"))?;
        let e_memo = if memo_data.is_empty() {
            None
        } else {
            Some(EncryptedMemo { data: memo_data })
        };

        Ok(mc_api::external::TxOut {
            masked_amount: src
                .masked_amount
                .as_ref()
                .map(TryInto::try_into)
                .transpose()?,
            target_key: Some(target_key),
            public_key: Some(public_key),
            e_fog_hint: Some(e_fog_hint),
            e_memo,
        })
    }
}

#[derive(Deserialize, Serialize, Default, Debug, Clone)]
pub struct JsonRange {
    pub from: JsonU64,
    pub to: JsonU64,
}

#[derive(Deserialize, Serialize, Default, Debug, Clone)]
pub struct JsonTxOutMembershipElement {
    pub range: JsonRange,
    pub hash: String,
}

impl From<&TxOutMembershipElement> for JsonTxOutMembershipElement {
    fn from(src: &TxOutMembershipElement) -> Self {
        Self {
            range: JsonRange {
                from: JsonU64(src.range.as_ref().unwrap_or(&Default::default()).from),
                to: JsonU64(src.range.as_ref().unwrap_or(&Default::default()).to),
            },
            hash: hex::encode(
                src.hash
                    .as_ref()
                    .unwrap_or(&Default::default())
                    .data
                    .as_slice(),
            ),
        }
    }
}

#[derive(Deserialize, Serialize, Default, Debug, Clone)]
pub struct JsonTxOutMembershipProof {
    pub index: JsonU64,
    pub highest_index: JsonU64,
    pub elements: Vec<JsonTxOutMembershipElement>,
}

impl From<&TxOutMembershipProof> for JsonTxOutMembershipProof {
    fn from(src: &TxOutMembershipProof) -> Self {
        Self {
            index: JsonU64(src.index),
            highest_index: JsonU64(src.highest_index),
            elements: src
                .elements
                .iter()
                .map(JsonTxOutMembershipElement::from)
                .collect(),
        }
    }
}

impl TryFrom<&JsonTxOutMembershipProof> for TxOutMembershipProof {
    type Error = String;

    fn try_from(src: &JsonTxOutMembershipProof) -> Result<TxOutMembershipProof, String> {
        let mut elements: Vec<TxOutMembershipElement> = Vec::new();
        for element in &src.elements {
            let range = mc_api::external::Range {
                from: element.range.from.into(),
                to: element.range.to.into(),
            };

            let hash = TxOutMembershipHash {
                data: hex::decode(&element.hash)
                    .map_err(|err| format!("Could not decode elem hash: {err}"))?,
            };

            let elem = TxOutMembershipElement {
                range: Some(range),
                hash: Some(hash),
            };
            elements.push(elem);
        }

        Ok(TxOutMembershipProof {
            index: src.index.into(),
            highest_index: src.highest_index.into(),
            elements,
        })
    }
}

#[derive(Deserialize, Serialize, Default, Debug)]
/// A request for randomly sampled TxOuts for use as mixins.
pub struct JsonMixinRequest {
    /// Number of mixins requested.
    pub num_mixins: u64,
    /// Outputs that should be excluded from the result.
    pub excluded: Vec<JsonTxOut>,
}

#[derive(Deserialize, Serialize, Default, Debug)]
/// Randomly sampled TxOuts for use as mixins, with membership proofs.
pub struct JsonMixinResponse {
    /// TxOuts to use as mixins.
    pub mixins: Vec<JsonTxOut>,
    /// Corresponding membership proofs.
    pub membership_proofs: Vec<JsonTxOutMembershipProof>,
}

#[derive(Deserialize, Serialize, Default, Debug)]
/// Requests Merkle proof-of-membership for each queried TxOut
pub struct JsonMembershipProofRequest {
    pub outputs: Vec<JsonTxOut>,
}

#[derive(Deserialize, Serialize, Default, Debug)]
/// Outputs and their corresponding proofs of membership.
pub struct JsonMembershipProofResponse {
    /// Queried outputs.
    pub outputs: Vec<JsonTxOut>,
    /// Corresponding membership proofs.
    pub membership_proofs: Vec<JsonTxOutMembershipProof>,
}

#[derive(Deserialize, Serialize, Default, Debug, Clone)]
pub struct JsonInputRules {
    pub required_outputs: Vec<JsonTxOut>,
    pub max_tombstone_block: u64,
}

impl From<&InputRules> for JsonInputRules {
    fn from(src: &InputRules) -> Self {
        Self {
            required_outputs: src.required_outputs.iter().map(JsonTxOut::from).collect(),
            max_tombstone_block: src.max_tombstone_block,
        }
    }
}

impl TryFrom<&JsonInputRules> for InputRules {
    type Error = String;

    fn try_from(src: &JsonInputRules) -> Result<InputRules, String> {
        Ok(InputRules {
            required_outputs: src
                .required_outputs
                .iter()
                .map(|out| {
                    mc_api::external::TxOut::try_from(out)
                        .map_err(|err| format!("Could not get TxOut: {err}"))
                })
                .collect::<Result<_, String>>()?,
            max_tombstone_block: src.max_tombstone_block,
            ..Default::default()
        })
    }
}

#[derive(Deserialize, Serialize, Default, Debug, Clone)]
pub struct JsonTxIn {
    pub ring: Vec<JsonTxOut>,
    pub proofs: Vec<JsonTxOutMembershipProof>,
    pub input_rules: Option<JsonInputRules>,
}

impl From<&TxIn> for JsonTxIn {
    fn from(src: &TxIn) -> Self {
        Self {
            ring: src.ring.iter().map(JsonTxOut::from).collect(),
            proofs: src
                .proofs
                .iter()
                .map(JsonTxOutMembershipProof::from)
                .collect(),
            input_rules: src.input_rules.as_ref().map(JsonInputRules::from),
        }
    }
}

impl TryFrom<&JsonTxIn> for TxIn {
    type Error = String;

    fn try_from(src: &JsonTxIn) -> Result<TxIn, String> {
        let mut outputs: Vec<mc_api::external::TxOut> = Vec::new();
        for output in &src.ring {
            let p_output = mc_api::external::TxOut::try_from(output)
                .map_err(|err| format!("Could not get TxOut: {err}"))?;
            outputs.push(p_output);
        }

        let mut proofs: Vec<TxOutMembershipProof> = Vec::new();
        for proof in &src.proofs {
            let p_proof = TxOutMembershipProof::try_from(proof)
                .map_err(|err| format!("Could not get proof: {err}"))?;
            proofs.push(p_proof);
        }

        let input_rules = src
            .input_rules
            .as_ref()
            .map(InputRules::try_from)
            .transpose()?;

        Ok(TxIn {
            ring: outputs,
            proofs,
            input_rules,
        })
    }
}

#[derive(Deserialize, Serialize, Default, Debug, Clone)]
pub struct JsonTxPrefix {
    pub inputs: Vec<JsonTxIn>,
    pub outputs: Vec<JsonTxOut>,
    pub fee: JsonU64,
    tombstone_block: JsonU64,
}

impl From<&TxPrefix> for JsonTxPrefix {
    fn from(src: &TxPrefix) -> Self {
        Self {
            inputs: src.inputs.iter().map(JsonTxIn::from).collect(),
            outputs: src.outputs.iter().map(JsonTxOut::from).collect(),
            fee: JsonU64(src.fee),
            tombstone_block: JsonU64(src.tombstone_block),
        }
    }
}

impl TryFrom<&JsonTxPrefix> for TxPrefix {
    type Error = String;

    fn try_from(src: &JsonTxPrefix) -> Result<TxPrefix, String> {
        let mut inputs: Vec<TxIn> = Vec::new();
        for input in &src.inputs {
            let p_input =
                TxIn::try_from(input).map_err(|err| format!("Could not get TxIn: {err}"))?;
            inputs.push(p_input);
        }

        let mut outputs: Vec<mc_api::external::TxOut> = Vec::new();
        for output in &src.outputs {
            let p_output = mc_api::external::TxOut::try_from(output)
                .map_err(|err| format!("Could not get TxOut: {err}"))?;
            outputs.push(p_output);
        }

        Ok(TxPrefix {
            inputs,
            outputs,
            fee: src.fee.into(),
            tombstone_block: src.tombstone_block.into(),
            ..Default::default()
        })
    }
}

#[derive(Deserialize, Serialize, Default, Debug, Clone)]
pub struct JsonRingMLSAG {
    pub c_zero: String,
    pub responses: Vec<String>,
    pub key_image: String,
}

impl From<&RingMlsag> for JsonRingMLSAG {
    fn from(src: &RingMlsag) -> Self {
        Self {
            c_zero: hex::encode(
                src.c_zero
                    .as_ref()
                    .unwrap_or(&Default::default())
                    .data
                    .as_slice(),
            ),
            responses: src
                .responses
                .iter()
                .map(|x| hex::encode(x.data.as_slice()))
                .collect(),
            key_image: hex::encode(
                src.key_image
                    .as_ref()
                    .unwrap_or(&Default::default())
                    .data
                    .as_slice(),
            ),
        }
    }
}

#[derive(Deserialize, Serialize, Default, Debug, Clone)]
pub struct JsonSignatureRctBulletproofs {
    pub ring_signatures: Vec<JsonRingMLSAG>,
    pub pseudo_output_commitments: Vec<String>,
    pub range_proof_bytes: String,
    pub range_proofs: Vec<String>,
    pub pseudo_output_token_ids: Vec<JsonU64>,
    pub output_token_ids: Vec<JsonU64>,
}

impl From<&SignatureRctBulletproofs> for JsonSignatureRctBulletproofs {
    fn from(src: &SignatureRctBulletproofs) -> Self {
        Self {
            ring_signatures: src
                .ring_signatures
                .iter()
                .map(JsonRingMLSAG::from)
                .collect(),
            pseudo_output_commitments: src
                .pseudo_output_commitments
                .iter()
                .map(|x| hex::encode(x.data.as_slice()))
                .collect(),
            range_proof_bytes: hex::encode(src.range_proof_bytes.as_slice()),
            range_proofs: src.range_proofs.iter().map(hex::encode).collect(),
            pseudo_output_token_ids: src.pseudo_output_token_ids.iter().map(Into::into).collect(),
            output_token_ids: src.output_token_ids.iter().map(Into::into).collect(),
        }
    }
}

impl TryFrom<&JsonSignatureRctBulletproofs> for SignatureRctBulletproofs {
    type Error = String;

    fn try_from(src: &JsonSignatureRctBulletproofs) -> Result<SignatureRctBulletproofs, String> {
        let mut ring_sigs: Vec<RingMlsag> = Vec::new();
        for sig in &src.ring_signatures {
            let c_zero = mc_api::external::CurveScalar {
                data: hex::decode(&sig.c_zero)
                    .map_err(|err| format!("Could not decode from hex: {err}"))?,
            };

            let mut responses: Vec<mc_api::external::CurveScalar> = Vec::new();
            for resp in &sig.responses {
                let response = mc_api::external::CurveScalar {
                    data: hex::decode(resp)
                        .map_err(|err| format!("Could not decode from hex: {err}"))?,
                };
                responses.push(response);
            }

            let key_image = KeyImage {
                data: hex::decode(&sig.key_image)
                    .map_err(|err| format!("Could not decode from hex: {err}"))?,
            };
            let ring_sig = RingMlsag {
                c_zero: Some(c_zero),
                responses,
                key_image: Some(key_image),
            };

            ring_sigs.push(ring_sig);
        }

        let mut commitments: Vec<CompressedRistretto> = Vec::new();
        for comm in &src.pseudo_output_commitments {
            let compressed = CompressedRistretto {
                data: hex::decode(comm)
                    .map_err(|err| format!("Could not decode from hex: {err}"))?,
            };
            commitments.push(compressed);
        }

        let signature = SignatureRctBulletproofs {
            ring_signatures: ring_sigs,
            pseudo_output_commitments: commitments,
            range_proof_bytes: hex::decode(&src.range_proof_bytes).map_err(|err| {
                format!(
                    "Could not decode top-level range proof from hex '{}': {}",
                    &src.range_proof_bytes, err
                )
            })?,
            range_proofs: src
                .range_proofs
                .iter()
                .map(|hex_str| {
                    hex::decode(hex_str).map_err(|err| {
                        format!("Could not decode range proof from hex '{hex_str}': {err}")
                    })
                })
                .collect::<Result<_, _>>()?,
            pseudo_output_token_ids: src.pseudo_output_token_ids.iter().map(Into::into).collect(),
            output_token_ids: src.output_token_ids.iter().map(Into::into).collect(),
        };
        Ok(signature)
    }
}

#[derive(Deserialize, Serialize, Default, Debug, Clone)]
pub struct JsonTx {
    pub prefix: JsonTxPrefix,
    pub signature: JsonSignatureRctBulletproofs,
}

impl From<&Tx> for JsonTx {
    fn from(src: &Tx) -> Self {
        Self {
            prefix: src.prefix.as_ref().unwrap_or(&Default::default()).into(),
            signature: src.signature.as_ref().unwrap_or(&Default::default()).into(),
        }
    }
}

impl TryFrom<&JsonTx> for Tx {
    type Error = String;

    fn try_from(src: &JsonTx) -> Result<Tx, String> {
        let tx = Tx {
            prefix: Some(
                TxPrefix::try_from(&src.prefix)
                    .map_err(|err| format!("Could not convert TxPrefix: {err}"))?,
            ),
            signature: Some(
                SignatureRctBulletproofs::try_from(&src.signature)
                    .map_err(|err| format!("Could not convert signature: {err}"))?,
            ),
            ..Default::default()
        };
        Ok(tx)
    }
}

// FIXME: Add sci's to this?
#[derive(Deserialize, Serialize, Default, Debug)]
pub struct JsonTxProposal {
    pub input_list: Vec<JsonUnspentTxOut>,
    pub outlay_list: Vec<JsonOutlayV2>,
    pub tx: JsonTx,
    pub fee: u64,
    pub outlay_index_to_tx_out_index: Vec<(usize, usize)>,
    pub outlay_confirmation_numbers: Vec<Vec<u8>>,
}

impl From<&api::TxProposal> for JsonTxProposal {
    fn from(src: &api::TxProposal) -> Self {
        let outlay_map: Vec<(usize, usize)> = src
            .outlay_index_to_tx_out_index
            .iter()
            .map(|(key, val)| (*key as usize, *val as usize))
            .collect();
        Self {
            input_list: src.input_list.iter().map(JsonUnspentTxOut::from).collect(),
            outlay_list: src.outlay_list.iter().map(JsonOutlayV2::from).collect(),
            tx: src.tx.as_ref().unwrap_or(&Default::default()).into(),
            fee: src.fee,
            outlay_index_to_tx_out_index: outlay_map,
            outlay_confirmation_numbers: src.outlay_confirmation_numbers.to_vec(),
        }
    }
}

// Helper conversion between json and protobuf
impl TryFrom<&JsonTxProposal> for api::TxProposal {
    type Error = String;

    fn try_from(src: &JsonTxProposal) -> Result<api::TxProposal, String> {
        let mut inputs: Vec<api::UnspentTxOut> = Vec::new();
        for input in src.input_list.iter() {
            let utxo = api::UnspentTxOut::try_from(input)
                .map_err(|err| format!("Failed to convert input: {err}"))?;
            inputs.push(utxo);
        }

        let mut outlays: Vec<api::OutlayV2> = Vec::new();
        for outlay in src.outlay_list.iter() {
            let out = api::OutlayV2::try_from(outlay)
                .map_err(|err| format!("Failed to convert outlay: {err}"))?;
            outlays.push(out);
        }

        // Reconstruct the public address as a protobuf
        Ok(api::TxProposal {
            input_list: inputs,
            outlay_list: outlays,
            tx: Some(Tx::try_from(&src.tx).map_err(|err| format!("Could not convert tx: {err}"))?),
            fee: src.fee,
            outlay_index_to_tx_out_index: src
                .outlay_index_to_tx_out_index
                .iter()
                .map(|(key, val)| (*key as u64, *val as u64))
                .collect(),
            outlay_confirmation_numbers: src.outlay_confirmation_numbers.clone(),
            ..Default::default()
        })
    }
}

#[derive(Deserialize, Serialize, Default, Debug)]
pub struct JsonCreateTxProposalRequest {
    pub input_list: Vec<JsonUnspentTxOut>,
    pub transfer: JsonParseRequestCodeResponse,
}

#[derive(Deserialize, Serialize, Default, Debug)]
pub struct JsonCreateTxProposalResponse {
    pub tx_proposal: JsonTxProposal,
}

impl From<&api::GenerateTxResponse> for JsonCreateTxProposalResponse {
    fn from(src: &api::GenerateTxResponse) -> Self {
        Self {
            tx_proposal: src
                .tx_proposal
                .as_ref()
                .unwrap_or(&Default::default())
                .into(),
        }
    }
}

#[derive(Deserialize, Serialize, Default, Debug)]
pub struct JsonTxProposalRequest {
    pub tx_proposal: JsonTxProposal,
}

#[derive(Deserialize, Serialize, Default, Debug)]
pub struct JsonSubmitTxResponse {
    pub sender_tx_receipt: JsonSenderTxReceipt,
    pub receiver_tx_receipt_list: Vec<JsonReceiverTxReceipt>,
}

impl From<&api::SubmitTxResponse> for JsonSubmitTxResponse {
    fn from(src: &api::SubmitTxResponse) -> Self {
        Self {
            sender_tx_receipt: src
                .sender_tx_receipt
                .as_ref()
                .unwrap_or(&Default::default())
                .into(),
            receiver_tx_receipt_list: src
                .receiver_tx_receipt_list
                .iter()
                .map(JsonReceiverTxReceipt::from)
                .collect(),
        }
    }
}

impl TryFrom<&JsonSubmitTxResponse> for api::SubmitTxResponse {
    type Error = String;

    fn try_from(src: &JsonSubmitTxResponse) -> Result<Self, String> {
        let key_images: Vec<KeyImage> = src
            .sender_tx_receipt
            .key_images
            .iter()
            .map(|k| {
                hex::decode(k).map(KeyImage::from).map_err(|err| {
                    format!("Failed to decode hex for sender_tx_receipt.key_images: {err}")
                })
            })
            .collect::<Result<Vec<KeyImage>, String>>()?;
        let sender_receipt = api::SenderTxReceipt {
            key_image_list: key_images,
            tombstone: src.sender_tx_receipt.tombstone,
        };

        let mut receiver_receipts = Vec::new();
        for r in src.receiver_tx_receipt_list.iter() {
            let pubkey = mc_api::external::CompressedRistretto {
                data: hex::decode(&r.tx_public_key)
                    .map_err(|err| format!("Failed to decode hex for tx_public_key: {err}"))?,
            };
            let receiver_receipt = api::ReceiverTxReceipt {
                recipient: Some(
                    PublicAddress::try_from(&r.recipient)
                        .map_err(|err| format!("Failed to convert recipient: {err}"))?,
                ),
                tx_public_key: Some(pubkey),
                tx_out_hash: hex::decode(&r.tx_out_hash)
                    .map_err(|err| format!("Failed to decode hex for tx_out_hash: {err}"))?,
                tombstone: r.tombstone,
                confirmation_number: hex::decode(&r.confirmation_number).map_err(|err| {
                    format!("Failed to decode hex for confirmation_number: {err}")
                })?,
            };
            receiver_receipts.push(receiver_receipt);
        }

        Ok(api::SubmitTxResponse {
            sender_tx_receipt: Some(sender_receipt),
            receiver_tx_receipt_list: receiver_receipts,
        })
    }
}

#[derive(Serialize, Default, Debug)]
pub struct JsonStatusResponse {
    pub status: String,
}

impl From<&api::GetTxStatusAsSenderResponse> for JsonStatusResponse {
    fn from(src: &api::GetTxStatusAsSenderResponse) -> Self {
        let status_str = match src.status() {
            api::TxStatus::Unknown => "unknown",
            api::TxStatus::Verified => "verified",
            api::TxStatus::TombstoneBlockExceeded => "failed",
            api::TxStatus::InvalidConfirmationNumber => "invalid_confirmation",
            api::TxStatus::PublicKeysInDifferentBlocks => "public_keys_in_different_blocks",
            api::TxStatus::TransactionFailureKeyImageBlockMismatch => {
                "transaction_failure_key_image_block_mismatch"
            }
            api::TxStatus::TransactionFailureKeyImageAlreadySpent => {
                "transaction_failure_key_image_already_spent"
            }
        };

        Self {
            status: String::from(status_str),
        }
    }
}

impl From<&api::GetTxStatusAsReceiverResponse> for JsonStatusResponse {
    fn from(src: &api::GetTxStatusAsReceiverResponse) -> Self {
        let status_str = match src.status() {
            api::TxStatus::Unknown => "unknown",
            api::TxStatus::Verified => "verified",
            api::TxStatus::TombstoneBlockExceeded => "failed",
            api::TxStatus::InvalidConfirmationNumber => "invalid_confirmation",
            api::TxStatus::PublicKeysInDifferentBlocks => "public_keys_in_different_blocks",
            api::TxStatus::TransactionFailureKeyImageBlockMismatch => {
                "transaction_failure_key_image_block_mismatch"
            }
            api::TxStatus::TransactionFailureKeyImageAlreadySpent => {
                "transaction_failure_key_image_already_spent"
            }
        };

        Self {
            status: String::from(status_str),
        }
    }
}

#[derive(Serialize, Default, Debug)]
pub struct JsonLedgerInfoResponse {
    pub block_count: JsonU64,
    pub txo_count: JsonU64,
}

impl From<&api::GetLedgerInfoResponse> for JsonLedgerInfoResponse {
    fn from(src: &api::GetLedgerInfoResponse) -> Self {
        Self {
            block_count: JsonU64(src.block_count),
            txo_count: JsonU64(src.txo_count),
        }
    }
}

#[derive(Serialize, Default, Debug)]
pub struct JsonBlockSignature {
    pub src_url: String,
    pub filename: String,
    pub signature: String,
    pub signer: String,
    pub signed_at: u64,
}

impl From<&api::ArchiveBlockSignatureData> for JsonBlockSignature {
    fn from(src: &api::ArchiveBlockSignatureData) -> Self {
        let default_signature = Default::default();
        let signature = src.signature.as_ref().unwrap_or(&default_signature);
        Self {
            src_url: src.src_url.clone(),
            filename: src.filename.clone(),
            signature: hex::encode(
                signature
                    .signature
                    .as_ref()
                    .unwrap_or(&Default::default())
                    .data
                    .as_slice(),
            ),
            signer: hex::encode(
                signature
                    .signer
                    .as_ref()
                    .unwrap_or(&Default::default())
                    .data
                    .as_slice(),
            ),
            signed_at: signature.signed_at,
        }
    }
}

#[derive(Serialize, Default, Debug)]
pub struct JsonBlockInfoResponse {
    pub key_image_count: JsonU64,
    pub txo_count: JsonU64,
}

impl From<&api::GetBlockInfoResponse> for JsonBlockInfoResponse {
    fn from(src: &api::GetBlockInfoResponse) -> Self {
        Self {
            key_image_count: JsonU64(src.key_image_count),
            txo_count: JsonU64(src.txo_count),
        }
    }
}

#[derive(Serialize, Default, Debug)]
pub struct JsonBlockDetailsResponse {
    pub block_id: String,
    pub version: u32,
    pub parent_id: String,
    pub index: JsonU64,
    pub cumulative_txo_count: JsonU64,
    pub contents_hash: String,
    pub key_images: Vec<String>,
    pub txos: Vec<JsonTxOut>,
    pub signatures: Vec<JsonBlockSignature>,
}

impl From<&api::GetBlockResponse> for JsonBlockDetailsResponse {
    fn from(src: &api::GetBlockResponse) -> Self {
        let default_block = Default::default();
        let block = src.block.as_ref().unwrap_or(&default_block);

        Self {
            block_id: hex::encode(
                block
                    .id
                    .as_ref()
                    .unwrap_or(&Default::default())
                    .data
                    .as_slice(),
            ),
            version: block.version,
            parent_id: hex::encode(
                block
                    .parent_id
                    .as_ref()
                    .unwrap_or(&Default::default())
                    .data
                    .as_slice(),
            ),
            index: JsonU64(block.index),
            cumulative_txo_count: JsonU64(block.cumulative_txo_count),
            contents_hash: hex::encode(
                block
                    .contents_hash
                    .as_ref()
                    .unwrap_or(&Default::default())
                    .data
                    .as_slice(),
            ),
            key_images: src
                .key_images
                .iter()
                .map(|k| hex::encode(k.data.as_slice()))
                .collect(),
            txos: src.txos.iter().map(JsonTxOut::from).collect(),
            signatures: src
                .signatures
                .iter()
                .map(JsonBlockSignature::from)
                .collect(),
        }
    }
}

#[derive(Serialize, Default, Debug)]
pub struct JsonProcessedTxOut {
    pub monitor_id: String,
    pub subaddress_index: u64,
    pub public_key: String,
    pub key_image: String,
    pub value: JsonU64,
    pub direction: String,
}

impl From<&api::ProcessedTxOut> for JsonProcessedTxOut {
    fn from(src: &api::ProcessedTxOut) -> Self {
        let direction_str = match src.direction() {
            api::ProcessedTxOutDirection::Invalid => "invalid",
            api::ProcessedTxOutDirection::Received => "received",
            api::ProcessedTxOutDirection::Spent => "spent",
        };

        Self {
            monitor_id: hex::encode(src.monitor_id.as_slice()),
            subaddress_index: src.subaddress_index,
            public_key: hex::encode(
                src.public_key
                    .as_ref()
                    .unwrap_or(&Default::default())
                    .data
                    .as_slice(),
            ),
            key_image: hex::encode(
                src.key_image
                    .as_ref()
                    .unwrap_or(&Default::default())
                    .data
                    .as_slice(),
            ),
            value: JsonU64(src.value),
            direction: direction_str.to_owned(),
        }
    }
}

#[derive(Serialize, Default, Debug)]
pub struct JsonProcessedBlockResponse {
    pub tx_outs: Vec<JsonProcessedTxOut>,
}

impl From<&api::GetProcessedBlockResponse> for JsonProcessedBlockResponse {
    fn from(src: &api::GetProcessedBlockResponse) -> Self {
        Self {
            tx_outs: src.tx_outs.iter().map(JsonProcessedTxOut::from).collect(),
        }
    }
}

#[derive(Serialize, Default, Debug)]
pub struct JsonBlockIndexByTxPubKeyResponse {
    pub block_index: String,
}

impl From<&api::GetBlockIndexByTxPubKeyResponse> for JsonBlockIndexByTxPubKeyResponse {
    fn from(src: &api::GetBlockIndexByTxPubKeyResponse) -> Self {
        Self {
            block_index: src.block.to_string(),
        }
    }
}

#[derive(Serialize, Default, Debug)]
pub struct JsonMobilecoindVersionResponse {
    pub version: String,
}

impl From<&api::MobilecoindVersionResponse> for JsonMobilecoindVersionResponse {
    fn from(src: &api::MobilecoindVersionResponse) -> Self {
        Self {
            version: src.version.to_string(),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use mc_crypto_keys::RistrettoPrivate;
    use mc_ledger_db::{
        test_utils::{create_ledger, create_transaction, initialize_ledger},
        Ledger,
    };
    use mc_transaction_core::{tokens::Mob, tx::TxOut, Amount, BlockVersion, PublicAddress, Token};
    use mc_transaction_core_test_utils::AccountKey;
    use mc_util_from_random::FromRandom;
    use rand::{rngs::StdRng, SeedableRng};
    use std::collections::BTreeMap;

    /// Test conversion of TxProposal
    #[test]
    fn test_tx_proposal_conversion() {
        // First, go from rust -> proto
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

        let tx = {
            let mut ledger = create_ledger();
            let sender = AccountKey::random(&mut rng);
            let recipient = AccountKey::random(&mut rng);
            initialize_ledger(BlockVersion::MAX, &mut ledger, 1, &sender, &mut rng);

            let block_contents = ledger.get_block_contents(0).unwrap();
            let tx_out = block_contents.outputs[0].clone();

            create_transaction(
                BlockVersion::MAX,
                &ledger,
                &tx_out,
                &sender,
                &recipient.default_subaddress(),
                10,
                &mut rng,
            )
        };

        let utxo = {
            let amount = Amount {
                value: 1u64 << 13,
                token_id: Mob::ID,
            };
            let tx_out = TxOut::new(
                BlockVersion::MAX,
                amount,
                &PublicAddress::from_random(&mut rng),
                &RistrettoPrivate::from_random(&mut rng),
                Default::default(),
            )
            .unwrap();

            let subaddress_index = 123;
            let key_image = mc_transaction_core::ring_signature::KeyImage::from(456);
            let value = 789;
            let attempted_spend_height = 1000;
            let attempted_spend_tombstone = 1234;

            // make proto UnspentTxOut
            api::UnspentTxOut {
                tx_out: Some((&tx_out).into()),
                subaddress_index,
                key_image: Some((&key_image).into()),
                value,
                attempted_spend_height,
                attempted_spend_tombstone,
                ..Default::default()
            }
        };

        // Make proto outlay
        let public_addr = AccountKey::random(&mut rng).default_subaddress();
        let outlay = api::OutlayV2 {
            value: 1234,
            receiver: Some((&public_addr).into()),
            ..Default::default()
        };

        let outlay_index_to_tx_out_index = BTreeMap::from_iter(vec![(0, 0)]);
        let outlay_confirmation_numbers = [mc_transaction_extra::TxOutConfirmationNumber::from(
            [0u8; 32],
        )];

        // Make proto TxProposal
        let proto_proposal = api::TxProposal {
            input_list: vec![utxo],
            outlay_list: vec![outlay],
            tx: Some((&tx).into()),
            fee: 0,
            outlay_index_to_tx_out_index,
            outlay_confirmation_numbers: outlay_confirmation_numbers
                .iter()
                .map(|x| x.to_vec())
                .collect(),
            ..Default::default()
        };

        // Proto -> Json
        let json_proposal = JsonTxProposal::from(&proto_proposal);

        // Json -> Proto
        let proto2 = api::TxProposal::try_from(&json_proposal).unwrap();

        // Assert each field, then the whole thing
        assert_eq!(proto_proposal.input_list, proto2.input_list);
        assert_eq!(proto_proposal.outlay_list, proto2.outlay_list);

        // The tx is complicated, so check each field of the tx
        assert_eq!(
            proto_proposal.tx.as_ref().unwrap().prefix,
            proto2.tx.as_ref().unwrap().prefix
        );
        assert_eq!(
            proto_proposal
                .tx
                .as_ref()
                .unwrap()
                .signature
                .as_ref()
                .unwrap()
                .ring_signatures[0]
                .c_zero,
            proto2
                .tx
                .as_ref()
                .unwrap()
                .signature
                .as_ref()
                .unwrap()
                .ring_signatures[0]
                .c_zero
        );
        assert_eq!(
            proto_proposal
                .tx
                .as_ref()
                .unwrap()
                .signature
                .as_ref()
                .unwrap()
                .ring_signatures[0]
                .responses,
            proto2
                .tx
                .as_ref()
                .unwrap()
                .signature
                .as_ref()
                .unwrap()
                .ring_signatures[0]
                .responses
        );
        assert_eq!(
            proto_proposal
                .tx
                .as_ref()
                .unwrap()
                .signature
                .as_ref()
                .unwrap()
                .ring_signatures[0]
                .key_image,
            proto2
                .tx
                .as_ref()
                .unwrap()
                .signature
                .as_ref()
                .unwrap()
                .ring_signatures[0]
                .key_image
        );
        assert_eq!(
            proto_proposal
                .tx
                .as_ref()
                .unwrap()
                .signature
                .as_ref()
                .unwrap()
                .ring_signatures,
            proto2
                .tx
                .as_ref()
                .unwrap()
                .signature
                .as_ref()
                .unwrap()
                .ring_signatures
        );
        assert_eq!(
            proto_proposal
                .tx
                .as_ref()
                .unwrap()
                .signature
                .as_ref()
                .unwrap()
                .pseudo_output_commitments,
            proto2
                .tx
                .as_ref()
                .unwrap()
                .signature
                .as_ref()
                .unwrap()
                .pseudo_output_commitments
        );
        assert_eq!(
            proto_proposal
                .tx
                .as_ref()
                .unwrap()
                .signature
                .as_ref()
                .unwrap()
                .range_proof_bytes,
            proto2
                .tx
                .as_ref()
                .unwrap()
                .signature
                .as_ref()
                .unwrap()
                .range_proof_bytes
        );
        assert_eq!(
            proto_proposal
                .tx
                .as_ref()
                .unwrap()
                .signature
                .as_ref()
                .unwrap()
                .range_proofs,
            proto2
                .tx
                .as_ref()
                .unwrap()
                .signature
                .as_ref()
                .unwrap()
                .range_proofs
        );
        assert_eq!(
            proto_proposal
                .tx
                .as_ref()
                .unwrap()
                .signature
                .as_ref()
                .unwrap()
                .pseudo_output_token_ids,
            proto2
                .tx
                .as_ref()
                .unwrap()
                .signature
                .as_ref()
                .unwrap()
                .pseudo_output_token_ids
        );
        assert_eq!(
            proto_proposal
                .tx
                .as_ref()
                .unwrap()
                .signature
                .as_ref()
                .unwrap()
                .output_token_ids,
            proto2
                .tx
                .as_ref()
                .unwrap()
                .signature
                .as_ref()
                .unwrap()
                .output_token_ids
        );

        assert_eq!(
            proto_proposal.tx.as_ref().unwrap().signature,
            proto2.tx.as_ref().unwrap().signature
        );
        assert_eq!(proto_proposal.tx, proto2.tx);

        // Check the rest of the fields
        assert_eq!(proto_proposal.fee, proto2.fee);
        assert_eq!(
            proto_proposal.outlay_index_to_tx_out_index,
            proto2.outlay_index_to_tx_out_index
        );
        assert_eq!(
            proto_proposal.outlay_confirmation_numbers,
            proto2.outlay_confirmation_numbers
        );
        assert_eq!(proto_proposal, proto2);
    }
}
