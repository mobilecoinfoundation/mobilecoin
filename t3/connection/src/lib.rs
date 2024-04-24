// Copyright (c) 2018-2023 The MobileCoin Foundation

mod error;

pub use error::Error;
use grpcio::{CallOption, ChannelBuilder, EnvBuilder, MetadataBuilder};
use mc_common::logger::Logger;
use mc_connection::Connection;
use mc_t3_api::{
    external::CompressedRistretto, t3_grpc::TransactionServiceClient, CreateTransactionRequest,
    FindTransactionsRequest, ListTransactionsRequest, T3Uri, TestErrorRequest,
    TransparentTransaction,
};
use mc_util_grpc::ConnectionUriGrpcioChannel;
use mc_util_uri::ConnectionUri;
use std::{
    cmp::Ordering,
    fmt::{Display, Formatter, Result as FmtResult},
    hash::{Hash, Hasher},
    sync::Arc,
};

pub fn common_headers_call_option(api_key: &str) -> CallOption {
    let mut metadata_builder = MetadataBuilder::new();
    let api_key_string = format!("ApiKey {}", api_key);
    metadata_builder
        .add_str("Authorization", &api_key_string)
        .expect("Could not add api-key header");

    CallOption::default().headers(metadata_builder.build())
}

#[derive(Clone)]
pub struct T3Connection {
    uri: T3Uri,
    api_key: String,
    transaction_service_client: TransactionServiceClient,
}

impl T3Connection {
    pub fn new(uri: &T3Uri, api_key: String, logger: Logger) -> Self {
        let env = Arc::new(EnvBuilder::new().name_prefix("T3RPC").build());
        let ch = ChannelBuilder::new(env)
            .max_receive_message_len(std::i32::MAX)
            .max_send_message_len(std::i32::MAX)
            .connect_to_uri(uri, &logger);

        let transaction_service_client = TransactionServiceClient::new(ch);

        Self {
            uri: uri.clone(),
            api_key,
            transaction_service_client,
        }
    }

    pub fn find_transactions(
        &self,
        address_hashes: Vec<Vec<u8>>,
        public_keys: Vec<CompressedRistretto>,
        public_key_hex: Vec<String>,
    ) -> Result<Vec<TransparentTransaction>, Error> {
        let mut request = FindTransactionsRequest::new();
        request.set_address_hashes(address_hashes.into());
        request.set_public_keys(public_keys.into());
        request.set_public_key_hex(public_key_hex.into());

        let response = self
            .transaction_service_client
            .find_transactions_opt(&request, common_headers_call_option(&self.api_key));

        Ok(response.map(|mut response| response.take_transactions().to_vec())?)
    }

    pub fn list_transactions(
        &self,
        created_since: u64,
    ) -> Result<Vec<TransparentTransaction>, Error> {
        let mut request = ListTransactionsRequest::new();
        request.set_created_since(created_since);

        let response = self
            .transaction_service_client
            .list_transactions_opt(&request, common_headers_call_option(&self.api_key));

        Ok(response.map(|mut response| response.take_transactions().to_vec())?)
    }

    pub fn create_transaction(
        &self,
        transparent_transaction: TransparentTransaction,
    ) -> Result<TransparentTransaction, Error> {
        let mut request = CreateTransactionRequest::new();
        request.set_transaction(transparent_transaction);

        let response = self
            .transaction_service_client
            .create_transaction_opt(&request, common_headers_call_option(&self.api_key));

        Ok(response.map(|mut response| response.take_transaction())?)
    }

    pub fn test_error(&self, code: i32) -> Result<(), Error> {
        let mut request = TestErrorRequest::new();
        request.set_code(code);

        let response = self
            .transaction_service_client
            .test_error_opt(&request, common_headers_call_option(&self.api_key));

        Ok(response.map(|_| ())?)
    }
}

impl Display for T3Connection {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "{}", self.uri)
    }
}

impl Eq for T3Connection {}

impl Hash for T3Connection {
    fn hash<H: Hasher>(&self, hasher: &mut H) {
        self.uri.addr().hash(hasher);
    }
}

impl PartialEq for T3Connection {
    fn eq(&self, other: &Self) -> bool {
        self.uri.addr() == other.uri.addr()
    }
}

impl Ord for T3Connection {
    fn cmp(&self, other: &Self) -> Ordering {
        self.uri.addr().cmp(&other.uri.addr())
    }
}

impl PartialOrd for T3Connection {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Connection for T3Connection {
    type Uri = T3Uri;

    fn uri(&self) -> Self::Uri {
        self.uri.clone()
    }
}

#[cfg(test)]
mod tests {}
