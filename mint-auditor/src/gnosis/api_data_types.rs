// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Structs for deserializing Gnosis API responses.
//! See https://safe-transaction.gnosis.io/ for the API spec.

use super::{Error, EthAddr, EthTxHash};
use mc_util_serial::JsonU64;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::str::FromStr;
use url::Url;

/// See `/safes/{address}/all-transactions/` at https://safe-transaction.gnosis.io/
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AllTransactionsResponse {
    /// Number of results returned
    pub count: u64,

    /// URL for getting the next page of results
    pub next: Option<Url>,

    /// URL for getting the previous page of results
    pub previous: Option<Url>,

    /// Raw results data
    pub results: Vec<Value>,
}

/// Decoded data
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DataDecoded {
    /// Method name
    pub method: String,

    /// Method parameters
    pub parameters: Vec<DataDecodedParameter>,
}

/// Decoded data parameter
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DataDecodedParameter {
    /// Parameter name
    pub name: String,

    /// Parameter value
    pub value: String,

    /// Decoded value
    #[serde(rename = "valueDecoded")]
    pub value_decoded: Option<Vec<ValueDecoded>>,
}

/// Decoded value
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ValueDecoded {
    /// Operation
    pub operation: u64,

    /// Destination address
    pub to: EthAddr,

    /// Value
    pub value: String,

    /// Raw data
    pub data: String,

    /// Decoded data
    #[serde(rename = "dataDecoded")]
    pub data_decoded: Option<Box<DataDecoded>>,
}

/// Multi-sig transaction
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MultiSigTransaction {
    /// Safe address
    pub safe: EthAddr,

    /// Destination contract
    pub to: EthAddr,

    /// Value being transferred
    pub value: JsonU64,

    /// Raw transaction data
    pub data: Option<String>,

    /// Ethereum block number.
    #[serde(rename = "blockNumber")]
    pub eth_block_number: u64,

    /// Transaction hash
    #[serde(rename = "transactionHash")]
    pub tx_hash: EthTxHash,

    /// Decoded transaction data
    #[serde(rename = "dataDecoded")]
    pub data_decoded: Option<DataDecoded>,
}

/// Ethereum transfer
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EthereumTransfer {
    /// From address
    pub from: EthAddr,

    /// To address
    pub to: EthAddr,

    /// Token contract address that is being transferred
    /// None for Eth transfers
    #[serde(rename = "tokenAddress")]
    pub token_addr: Option<EthAddr>,

    /// Transaction hash
    #[serde(rename = "transactionHash")]
    pub tx_hash: EthTxHash,

    /// Transaction type
    #[serde(rename = "type")]
    pub tx_type: String,

    /// Value being transferred
    pub value: JsonU64,
}

/// Ethereum transaction
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EthereumTransaction {
    /// Transaction hash
    #[serde(rename = "txHash")]
    pub tx_hash: EthTxHash,

    /// Ethereum block number.
    #[serde(rename = "blockNumber")]
    pub eth_block_number: u64,

    /// Transfers
    pub transfers: Vec<EthereumTransfer>,
}

/// Possible transaction types that are returned from
/// `/safes/{address}/all-transactions/`
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "txType")]
pub enum Transaction {
    /// Multi-sig transaction
    #[serde(rename = "MULTISIG_TRANSACTION")]
    MultiSig(MultiSigTransaction),

    /// Ethereum transaction
    #[serde(rename = "ETHEREUM_TRANSACTION")]
    Ethereum(EthereumTransaction),

    /// Module transaction
    #[serde(rename = "MODULE_TRANSACTION")]
    Module(Value),
}

/// Raw (unparsed) transaction.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RawGnosisTransaction {
    raw: Value,
}

impl RawGnosisTransaction {
    /// Deserialize transaction from JSON.
    pub fn from_json_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Ok(Self::from(serde_json::from_slice::<Value>(bytes)?))
    }

    /// Serialize transaction into JSON.
    pub fn to_json_string(&self) -> String {
        self.raw.to_string()
    }

    /// Decode a Gnosis Safe transaction.
    pub fn decode(&self) -> Result<Transaction, Error> {
        Ok(serde_json::from_value(self.raw.clone())?)
    }

    /// Get the transaction hash.
    pub fn tx_hash(&self) -> Result<EthTxHash, Error> {
        let hash_str = self
            .raw
            .get("transactionHash")
            .or_else(|| self.raw.get("txHash"))
            .and_then(|val| val.as_str())
            .ok_or_else(|| {
                Error::Other("GnosisSafeTransaction: missing transactionHash".to_string())
            })?;
        EthTxHash::from_str(hash_str)
            .map_err(|err| Error::Other(format!("Failed parsing tx hash '{}': {}", hash_str, err)))
    }
}

impl From<Value> for RawGnosisTransaction {
    fn from(raw: Value) -> Self {
        Self { raw }
    }
}
