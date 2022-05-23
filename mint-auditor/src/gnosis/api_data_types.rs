// Copyright (c) 2018-2022 The MobileCoin Foundation

//! TODO

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Deserialize, Serialize)]
pub struct AllTransactionsResponse {
    pub count: u64,
    pub next: Option<String>,
    pub previous: Option<String>,
    pub results: Vec<Value>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DataDecoded {
    method: String,
    parameters: Vec<DataDecodedParameter>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DataDecodedParameter {
    name: String,
    // type: String,
    value: String,

    #[serde(rename = "valueDecoded")]
    value_decoded: Option<Vec<ValueDecoded>>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ValueDecoded {
    operation: u64,
    to: String,
    value: String,
    data: String,

    #[serde(rename = "dataDecoded")]
    data_decoded: Option<Box<DataDecoded>>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct MultiSigTransaction {
    safe: String,
    to: String,
    value: String,
    data: Option<String>,

    #[serde(rename = "dataDecoded")]
    data_decoded: Option<DataDecoded>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "txType")]
pub enum Transaction {
    #[serde(rename = "MULTISIG_TRANSACTION")]
    MultiSig(MultiSigTransaction),

    #[serde(rename = "ETHEREUM_TRANSACTION")]
    Ethereum(Value),

    #[serde(rename = "MODULE_TRANSACTION")]
    Module(Value),
}