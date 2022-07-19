// Copyright (c) 2018-2022 The MobileCoin Foundation

use crate::error::RouterServerError;
use mc_attest_api::attest;
use mc_fog_api::{view::MultiViewStoreQueryResponse, view_grpc::FogViewStoreApiClient};
use mc_fog_uri::FogViewStoreUri;
use std::{str::FromStr, sync::Arc};

/// The result of processing the MultiViewStoreQueryResponse from each Fog View
/// Shard.
pub struct ProcessedShardResponseData {
    /// gRPC clients for Shards that need to be retried for a successful
    /// response.
    pub shard_clients_for_retry: Vec<Arc<FogViewStoreApiClient>>,

    /// Uris for *individual* Fog View Stores that need to be authenticated with
    /// by the Fog Router. It should only have entries if
    /// `shard_clients_for_retry` has entries.
    pub view_store_uris_for_authentication: Vec<FogViewStoreUri>,

    /// New, successfully processed query responses.
    pub new_query_responses: Vec<attest::Message>,
}

impl ProcessedShardResponseData {
    pub fn new(
        shard_clients_for_retry: Vec<Arc<FogViewStoreApiClient>>,
        view_store_uris_for_authentication: Vec<FogViewStoreUri>,
        new_query_responses: Vec<attest::Message>,
    ) -> Self {
        ProcessedShardResponseData {
            shard_clients_for_retry,
            view_store_uris_for_authentication,
            new_query_responses,
        }
    }
}

/// Processes the MultiViewStoreQueryResponses returned by each Fog View Shard.
pub fn process_shard_responses(
    clients_and_responses: Vec<(Arc<FogViewStoreApiClient>, MultiViewStoreQueryResponse)>,
) -> Result<ProcessedShardResponseData, RouterServerError> {
    let mut shard_clients_for_retry = Vec::new();
    let mut view_store_uris_for_authentication = Vec::new();
    let mut new_query_responses = Vec::new();

    for (shard_client, mut response) in clients_and_responses {
        // We did not receive a query_response for this shard.Therefore, we need to:
        //  (a) retry the query
        //  (b) authenticate with the Fog View Store that returned the decryption_error
        if response.has_decryption_error() {
            shard_clients_for_retry.push(shard_client);
            let store_uri =
                FogViewStoreUri::from_str(&response.get_decryption_error().fog_view_store_uri)?;
            view_store_uris_for_authentication.push(store_uri);
        } else {
            new_query_responses.push(response.take_query_response());
        }
    }

    Ok(ProcessedShardResponseData::new(
        shard_clients_for_retry,
        view_store_uris_for_authentication,
        new_query_responses,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use grpcio::ChannelBuilder;
    use mc_common::logger::{test_with_logger, Logger};
    use mc_util_grpc::ConnectionUriGrpcioChannel;

    fn create_successful_mvq_response() -> MultiViewStoreQueryResponse {
        let mut successful_response = MultiViewStoreQueryResponse::new();
        let client_auth_request = Vec::new();
        successful_response
            .mut_query_response()
            .set_data(client_auth_request);

        successful_response
    }

    fn create_failed_mvq_response(i: usize) -> MultiViewStoreQueryResponse {
        let mut failed_response = MultiViewStoreQueryResponse::new();
        let view_uri_string = format!(
            "insecure-fog-view-store://node{}.test.mobilecoin.com:3225",
            i
        );
        failed_response
            .mut_decryption_error()
            .set_fog_view_store_uri(view_uri_string);

        failed_response
    }

    fn create_grpc_client(i: usize, logger: Logger) -> Arc<FogViewStoreApiClient> {
        let view_uri_string = format!(
            "insecure-fog-view-store://node{}.test.mobilecoin.com:3225",
            i
        );
        let view_uri = FogViewStoreUri::from_str(&view_uri_string).unwrap();
        let grpc_env = Arc::new(
            grpcio::EnvBuilder::new()
                .name_prefix("processor-test".to_string())
                .build(),
        );

        let grpc_client = FogViewStoreApiClient::new(
            ChannelBuilder::default_channel_builder(grpc_env).connect_to_uri(&view_uri, &logger),
        );

        Arc::new(grpc_client)
    }

    #[test_with_logger]
    fn one_successful_response_no_shard_clients(logger: Logger) {
        let grpc_client = create_grpc_client(0, logger.clone());
        let successful_mvq_response = create_successful_mvq_response();
        let clients_and_responses = vec![(grpc_client, successful_mvq_response)];

        let result = process_shard_responses(clients_and_responses);

        assert!(result.is_ok());

        let shard_clients_for_retry = result.unwrap().shard_clients_for_retry;
        assert!(shard_clients_for_retry.is_empty());
    }

    #[test_with_logger]
    fn one_successful_response_no_pending_authentications(logger: Logger) {
        let grpc_client = create_grpc_client(0, logger.clone());
        let successful_mvq_response = create_successful_mvq_response();
        let clients_and_responses = vec![(grpc_client, successful_mvq_response)];

        let result = process_shard_responses(clients_and_responses);

        assert!(result.is_ok());

        let view_store_uris_for_authentication = result.unwrap().view_store_uris_for_authentication;
        assert!(view_store_uris_for_authentication.is_empty());
    }

    #[test_with_logger]
    fn one_successful_response_one_new_query_response(logger: Logger) {
        let grpc_client = create_grpc_client(0, logger.clone());
        let successful_mvq_response = create_successful_mvq_response();
        let clients_and_responses = vec![(grpc_client, successful_mvq_response)];

        let result = process_shard_responses(clients_and_responses);

        assert!(result.is_ok());

        let new_query_response = result.unwrap().new_query_responses;
        assert_eq!(new_query_response.len(), 1);
    }

    #[test_with_logger]
    fn one_failed_response_one_pending_shard_client(logger: Logger) {
        let client_index = 0;
        let grpc_client = create_grpc_client(client_index, logger.clone());
        let failed_mvq_response = create_failed_mvq_response(client_index);
        let clients_and_responses = vec![(grpc_client, failed_mvq_response)];

        let result = process_shard_responses(clients_and_responses);

        assert!(result.is_ok());

        let shard_clients_for_retry = result.unwrap().shard_clients_for_retry;
        assert_eq!(shard_clients_for_retry.len(), 1);
    }

    #[test_with_logger]
    fn one_failed_response_one_pending_authentications(logger: Logger) {
        let client_index: usize = 0;
        let grpc_client = create_grpc_client(client_index, logger.clone());
        let failed_mvq_response = create_failed_mvq_response(client_index);
        let clients_and_responses = vec![(grpc_client, failed_mvq_response)];

        let result = process_shard_responses(clients_and_responses);

        assert!(result.is_ok());

        let view_store_uris_for_authentication = result.unwrap().view_store_uris_for_authentication;
        assert_eq!(view_store_uris_for_authentication.len(), 1);
    }

    #[test_with_logger]
    fn one_failed_response_zero_new_query_responses(logger: Logger) {
        let client_index: usize = 0;
        let grpc_client = create_grpc_client(client_index, logger.clone());
        let failed_mvq_response = create_failed_mvq_response(client_index);
        let clients_and_responses = vec![(grpc_client, failed_mvq_response)];

        let result = process_shard_responses(clients_and_responses);

        assert!(result.is_ok());

        let new_query_responses = result.unwrap().new_query_responses;
        assert!(new_query_responses.is_empty());
    }

    #[test_with_logger]
    fn mixed_failed_and_successful_responses_processes_correctly(logger: Logger) {
        const NUMBER_OF_FAILURES: usize = 11;
        const NUMBER_OF_SUCCESSES: usize = 8;

        let mut clients_and_responses = Vec::new();
        for i in 0..NUMBER_OF_FAILURES {
            let grpc_client = create_grpc_client(i, logger.clone());
            let failed_mvq_response = create_failed_mvq_response(i);
            clients_and_responses.push((grpc_client, failed_mvq_response));
        }
        for i in 0..NUMBER_OF_SUCCESSES {
            let client_index = i + NUMBER_OF_FAILURES;
            let grpc_client = create_grpc_client(client_index, logger.clone());
            let successful_mvq_response = create_successful_mvq_response();
            clients_and_responses.push((grpc_client, successful_mvq_response));
        }

        let result = process_shard_responses(clients_and_responses);
        assert!(result.is_ok());
        let processed_shard_response_data = result.unwrap();

        assert_eq!(
            processed_shard_response_data.shard_clients_for_retry.len(),
            NUMBER_OF_FAILURES
        );
        assert_eq!(
            processed_shard_response_data
                .view_store_uris_for_authentication
                .len(),
            NUMBER_OF_FAILURES
        );
        assert_eq!(
            processed_shard_response_data.new_query_responses.len(),
            NUMBER_OF_SUCCESSES
        );
    }
}
