// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Gnosis Safe transaction fetcher, used to get the transaction data from a
//! gnosis safe-transaction-service.

use super::{
    api_data_types::{AllTransactionsResponse, RawGnosisTransaction},
    Error, EthAddr,
};
use mc_common::logger::{log, o, Logger};
use reqwest::{blocking::Client, StatusCode};
use url::Url;

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
            base_url.push("/");
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
    /// This method will continously reach out to the API service until all
    /// transactions have been fetched. Because of pagination, this might result
    /// in multiple requests. This returns only transactions that were
    /// executed and confirmed.
    pub fn get_all_transaction_data(
        &self,
        safe_address: &EthAddr,
    ) -> Result<Vec<RawGnosisTransaction>, Error> {
        let mut url = self.base_url.join(&format!(
            "api/v1/safes/{}/all-transactions/?executed=true&queued=false&trusted=true",
            safe_address
        ))?;

        let mut raw_transactions = Vec::new();

        loop {
            let response = self.get_all_transaction_data_from_url(&url)?;
            raw_transactions.extend(response.results.into_iter().map(RawGnosisTransaction::from));

            match response.next {
                Some(next_url) => {
                    url = next_url;
                }
                None => break,
            };
        }

        Ok(raw_transactions)
    }

    /// Fetch transaction data from a specific url endpoint.
    fn get_all_transaction_data_from_url(
        &self,
        url: &Url,
    ) -> Result<AllTransactionsResponse, Error> {
        log::debug!(self.logger, "Fetching transactions from: {}", url);

        let response = self
            .client
            .get(url.clone())
            .send()
            .map_err(|err| Error::Other(format!("Failed to fetch '{}': {}", url, err)))?;
        if response.status() != StatusCode::OK {
            return Err(Error::Other(format!(
                "Failed to fetch '{}': Expected status 200, got {}",
                url,
                response.status()
            )));
        }

        response.json().map_err(|err| {
            Error::ApiResultParse(format!("Failed parsing JSON from '{}': {}", url, err))
        })
    }
}
