// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Gnosis Safe transaction fetcher, used to get the transaction data from a
//! gnosis safe-transaction-service.

use super::error::Error;
use mc_common::logger::{log, o, Logger};
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

#[derive(Debug, Deserialize, Serialize)]
struct DataDecoded {
    method: String,
    parameters: Vec<DataDecodedParameter>,
}

#[derive(Debug, Deserialize, Serialize)]
struct DataDecodedParameter {
    name: String,
    // type: String,
    value: String,

    #[serde(rename = "valueDecoded")]
    value_decoded: Option<Vec<ValueDecoded>>,
}

#[derive(Debug, Deserialize, Serialize)]
struct ValueDecoded {
    operation: u64,
    to: String,
    value: String,
    data: String,

    #[serde(rename = "dataDecoded")]
    data_decoded: Option<Box<DataDecoded>>,
}

#[derive(Debug, Deserialize, Serialize)]
struct MultiSigTransaction {
    safe: String,
    to: String,
    value: String,
    data: Option<String>,

    #[serde(rename = "dataDecoded")]
    data_decoded: Option<DataDecoded>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "txType")]
enum DecodedGnosisTransaction {
    #[serde(rename = "MULTISIG_TRANSACTION")]
    MultiSig(MultiSigTransaction),

    #[serde(rename = "ETHEREUM_TRANSACTION")]
    Ethereum(Value),

    #[serde(rename = "MODULE_TRANSACTION")]
    Module(Value),
}

#[derive(Debug, Deserialize, Serialize)]
struct GnosisTransaction {
    raw: Value,
}

impl GnosisTransaction {
    pub fn decode(&self) -> Result<DecodedGnosisTransaction, Error> {
        Ok(serde_json::from_value(self.raw.clone())?)
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct AllTransactionsResponse {
    count: u64,
    next: Option<String>,
    previous: Option<String>,
    results: Vec<Value>,
}

/// Gnosis Safe transaction fetcher, used to get the transaction data from a
/// gnosis safe-transaction-service.
pub struct GnosisSafeFetcher {
    /// Base URL for the gnosis safe-transaction-service API.
    base_url: Url,

    /// The [reqwest::Client].
    client: Client,

    /// Logger.
    logger: Logger,
}

impl GnosisSafeFetcher {
    /// Instantiate a [GnosisSafeFetcher] fetching transactions from the given
    /// URL endpoint.
    /// The URL endpoint is expected to run the Gnosis safe-transaction-service
    /// (https://github.com/safe-global/safe-transaction-service/)
    pub fn new(mut base_url: Url, logger: Logger) -> Result<Self, Error> {
        if !base_url.path().ends_with('/') {
            base_url = base_url.join(&format!("{}/", base_url.path()))?;
        }

        let logger = logger.new(o!("url" => base_url.to_string()));

        let client = Client::builder()
            .build()
            .map_err(|e| Error::Other(format!("Failed to create reqwest client: {}", e)))?;

        Ok(Self {
            base_url,
            client,
            logger,
        })
    }

    /// Fetch transaction data.
    /// This returns only transactions that were executed and confirmed.
    pub async fn get_transaction_data(&self, safe_address: &str) -> Result<Vec<u8>, Error> {
        let url = self.base_url.join(&format!(
            "api/v1/safes/{}/all-transactions/?executed=true&queued=false&trusted=true",
            safe_address
        ))?;
        log::debug!(self.logger, "Fetching transactions from: {}", url);

        let response = self
            .client
            .get(url.as_str())
            .send()
            .await
            .map_err(|err| Error::Other(format!("Failed to fetch '{}': {}", url, err)))?;
        if response.status() != StatusCode::OK {
            return Err(Error::Other(format!(
                "Failed to fetch '{}': Expected status 200, got {}",
                url,
                response.status()
            )));
        }

        let data = response
            .json::<AllTransactionsResponse>()
            .await
            .map_err(|err| Error::Other(format!("Failed parsing JSON from '{}': {}", url, err)))?;
        println!("AAA {:#?}", data);
        Ok(Vec::default())
    }
}
