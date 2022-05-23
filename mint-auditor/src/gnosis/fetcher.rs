// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Gnosis Safe transaction fetcher, used to get the transaction data from a
//! gnosis safe-transaction-service.
//!
//! TODO
//! - figure out what to return from get_all_transactions so that we capture
//!   both the full response, and optionally the decoded transaction data
//! - need to include offsets
//! - need to store in lmdb: 1) map of real tx hash -> data (used to lookup from
//!   mint nonce) 2) list of all hashes in chronological order? reverse
//!   chronological order? lmdb ordering is messsy
//! - code that takes a MintTx and returns the matching
//!   DecodedGnosisSafeTransaction, this needs to: 1) lookup by the nonce 2)
//!   compare the amount
//! - code that takes DecodedGnosisSafeTransaction and if it contains a burn
//!   (moving token out + burn memo multi-tx) try and locate matching mc
//!   transaction (lookup by txout pub key)
//!
//! two scanning modes:
//! 1) everything
//! 2) until reaching a known hash

use super::{api_data_types, error::Error};
use futures::{FutureExt, Stream, StreamExt};
use mc_common::logger::{log, o, Logger};
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{fmt, str::FromStr};
use url::Url;

pub const ETH_TX_HASH_LEN: usize = 32;
pub const SAFE_ID_LEN: usize = 20;

// TODO move somewhere else
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EthTxHash([u8; ETH_TX_HASH_LEN]);

impl TryFrom<&[u8]> for EthTxHash {
    type Error = Error;

    fn try_from(src: &[u8]) -> Result<Self, Self::Error> {
        let bytes: [u8; ETH_TX_HASH_LEN] = src
            .try_into()
            .map_err(|_| Error::Other("EthTxHash: invalid length".to_string()))?;
        Ok(Self(bytes))
    }
}

impl FromStr for EthTxHash {
    type Err = Error;

    fn from_str(src: &str) -> Result<Self, Self::Err> {
        let bytes = if src.starts_with("0x") {
            hex::decode(&src[2..])
        } else {
            hex::decode(src)
        }
        .map_err(|_| Error::Other("EthTxHash: invalid hex".to_string()))?;
        Self::try_from(&bytes[..])
    }
}

impl fmt::Display for EthTxHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl AsRef<[u8]> for EthTxHash {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}

// TODO move somewhere else
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SafeId([u8; SAFE_ID_LEN]);

impl TryFrom<&[u8]> for SafeId {
    type Error = Error;

    fn try_from(src: &[u8]) -> Result<Self, Self::Error> {
        let bytes: [u8; SAFE_ID_LEN] = src
            .try_into()
            .map_err(|_| Error::Other("SafeId: invalid length".to_string()))?;
        Ok(Self(bytes))
    }
}

impl FromStr for SafeId {
    type Err = Error;

    fn from_str(src: &str) -> Result<Self, Self::Err> {
        let bytes = if src.starts_with("0x") {
            hex::decode(&src[2..])
        } else {
            hex::decode(src)
        }
        .map_err(|_| Error::Other("SafeId: invalid hex".to_string()))?;
        Self::try_from(&bytes[..])
    }
}

impl fmt::Display for SafeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl AsRef<[u8]> for SafeId {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}

// TODO move somewhere else
#[derive(Debug, Deserialize, Serialize)]
pub struct GnosisSafeTransaction {
    raw: Value,
}

impl GnosisSafeTransaction {
    pub fn decode(&self) -> Result<api_data_types::Transaction, Error> {
        Ok(serde_json::from_value(self.raw.clone())?)
    }

    pub fn tx_hash(&self) -> Result<EthTxHash, Error> {
        let hash_str = self
            .raw
            .get("transactionHash")
            .or_else(|| self.raw.get("txHash"))
            .and_then(|val| val.as_str())
            .ok_or(Error::Other(
                "GnosisSafeTransaction: missing transactionHash".to_string(),
            ))?;
        Ok(EthTxHash::from_str(hash_str)?)
    }

    pub fn to_json_string(&self) -> String {
        self.raw.to_string()
    }

    pub fn from_json_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Ok(Self::from(serde_json::from_slice::<Value>(bytes)?))
    }
}

impl From<Value> for GnosisSafeTransaction {
    fn from(value: Value) -> Self {
        Self { raw: value }
    }
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
        let x = EthTxHash::from_str(
            "0x09ae7f9f06fff9a2bc14bb0595b335a4b2c175d01a347d30956f4b235258d2e1",
        )
        .unwrap();
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
    pub async fn get_transaction_data(
        &self,
        safe_address: &str,
    ) -> Result<Vec<GnosisSafeTransaction>, Error> {
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
            .json::<api_data_types::AllTransactionsResponse>()
            .await
            .map_err(|err| Error::Other(format!("Failed parsing JSON from '{}': {}", url, err)))?;

        Ok(data
            .results
            .into_iter()
            .map(GnosisSafeTransaction::from)
            .collect())
    }
}
