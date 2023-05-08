// Copyright (c) 2018-2022 The MobileCoin Foundation

use crate::{error::RouterServerError, fog_view_router_server::Shard};
use mc_common::logger::{log, Logger};
use mc_fog_types::view::MultiViewStoreQueryResponse;
use mc_fog_uri::FogViewStoreUri;
use std::str::FromStr;

/// The result of processing the MultiViewStoreQueryResponse from each Fog View
/// Shard.
pub struct ProcessedShardResponseData {
    /// gRPC clients for Shards that need to be retried for a successful
    /// response.
    pub shards_for_retry: Vec<Shard>,

    /// Uris for *individual* Fog View Stores that need to be authenticated with
    /// by the Fog Router. It should only have entries if
    /// `shard_clients_for_retry` has entries.
    pub view_store_uris_for_authentication: Vec<FogViewStoreUri>,

    /// New, successfully processed query responses.
    pub multi_view_store_query_responses: Vec<MultiViewStoreQueryResponse>,
}

impl ProcessedShardResponseData {
    pub fn new(
        shards_for_retry: Vec<Shard>,
        view_store_uris_for_authentication: Vec<FogViewStoreUri>,
        new_query_responses: Vec<MultiViewStoreQueryResponse>,
    ) -> Self {
        ProcessedShardResponseData {
            shards_for_retry,
            view_store_uris_for_authentication,
            multi_view_store_query_responses: new_query_responses,
        }
    }
}

/// Processes the MultiViewStoreQueryResponses returned by each Fog View Shard.
pub fn process_shard_responses(
    shards_and_responses: Vec<(Shard, MultiViewStoreQueryResponse)>,
    logger: Logger,
) -> Result<ProcessedShardResponseData, RouterServerError> {
    let mut shards_for_retry = Vec::new();
    let mut view_store_uris_for_authentication = Vec::new();
    let mut new_query_responses = Vec::new();

    for (shard, response) in shards_and_responses {
        if response.block_range != shard.block_range {
            return Err(RouterServerError::ViewStoreError(format!("The shard response's block range {} does not match the shard's configured block range {}.", response.block_range, shard.block_range)));
        }
        match response.status {
            mc_fog_types::view::MultiViewStoreQueryResponseStatus::Unknown => {
                log::error!(
                    logger,
                    "Received a response with status 'unknown' from store{}",
                    FogViewStoreUri::from_str(&response.store_uri)?
                );
                shards_for_retry.push(shard);
            }
            mc_fog_types::view::MultiViewStoreQueryResponseStatus::Success => {
                new_query_responses.push(response.clone());
            }
            // The shard was unable to produce a query response because the Fog View Store
            // it contacted isn't authenticated with the Fog View Router. Therefore
            // we need to (a) retry the query (b) authenticate with the Fog View
            // Store.
            mc_fog_types::view::MultiViewStoreQueryResponseStatus::AuthenticationError => {
                shards_for_retry.push(shard);
                view_store_uris_for_authentication
                    .push(FogViewStoreUri::from_str(&response.store_uri)?);
            }
            // Don't do anything if the Fog View Store isn't ready. It's already authenticated,
            // hasn't returned a new query response, and shouldn't be retried yet.
            mc_fog_types::view::MultiViewStoreQueryResponseStatus::NotReady => (),
        }
    }

    Ok(ProcessedShardResponseData::new(
        shards_for_retry,
        view_store_uris_for_authentication,
        new_query_responses,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sharding_strategy::{EpochShardingStrategy, ShardingStrategy};
    use grpcio::ChannelBuilder;
    use mc_common::logger::{test_with_logger, Logger};
    use mc_fog_api::view_grpc::FogViewStoreApiClient;
    use mc_fog_types::common::BlockRange;
    use mc_fog_uri::FogViewStoreScheme;
    use mc_util_grpc::ConnectionUriGrpcioChannel;
    use mc_util_uri::UriScheme;
    use std::sync::Arc;

    fn create_successful_mvq_response(
        shard_index: usize,
        block_range: BlockRange,
    ) -> MultiViewStoreQueryResponse {
        let mut successful_response = mc_fog_api::view::MultiViewStoreQueryResponse::new();
        let client_auth_request = Vec::new();
        successful_response
            .mut_query_response()
            .set_data(client_auth_request);
        let view_uri_string = format!(
            "{}://node{}.test.mobilecoin.com:{}",
            FogViewStoreScheme::SCHEME_INSECURE,
            shard_index,
            FogViewStoreScheme::DEFAULT_INSECURE_PORT,
        );
        successful_response.set_store_uri(view_uri_string);
        successful_response.set_block_range(mc_fog_api::fog_common::BlockRange::from(&block_range));
        successful_response
            .set_status(mc_fog_api::view::MultiViewStoreQueryResponseStatus::SUCCESS);

        successful_response
            .try_into()
            .expect("Couldn't convert MultiViewStoreQueryResponse proto to internal struct")
    }

    fn create_failed_mvq_response(
        shard_index: usize,
        block_range: BlockRange,
        status: mc_fog_api::view::MultiViewStoreQueryResponseStatus,
    ) -> MultiViewStoreQueryResponse {
        let mut failed_response = mc_fog_api::view::MultiViewStoreQueryResponse::new();
        let view_uri_string = format!(
            "{}://node{}.test.mobilecoin.com:{}",
            FogViewStoreScheme::SCHEME_INSECURE,
            shard_index,
            FogViewStoreScheme::DEFAULT_INSECURE_PORT,
        );
        failed_response.set_store_uri(view_uri_string);
        failed_response.set_block_range(mc_fog_api::fog_common::BlockRange::from(&block_range));
        failed_response.set_status(status);

        failed_response
            .try_into()
            .expect("Couldn't convert MultiViewStoreQueryResponse proto to internal struct")
    }

    fn create_shard(i: usize, block_range: BlockRange, logger: Logger) -> Shard {
        let view_uri_string = format!(
            "{}://node{}.test.mobilecoin.com:{}",
            FogViewStoreScheme::SCHEME_INSECURE,
            i,
            FogViewStoreScheme::DEFAULT_INSECURE_PORT,
        );
        let uri = FogViewStoreUri::from_str(&view_uri_string).unwrap();
        let grpc_env = Arc::new(
            grpcio::EnvBuilder::new()
                .name_prefix("processor-test".to_string())
                .build(),
        );

        let grpc_client = FogViewStoreApiClient::new(
            ChannelBuilder::default_channel_builder(grpc_env)
                .keepalive_permit_without_calls(false)
                .connect_to_uri(&uri, &logger),
        );

        Shard::new(uri, Arc::new(grpc_client), block_range)
    }

    #[test_with_logger]
    fn one_successful_response_no_shards(logger: Logger) {
        let shard_index = 0;
        let sharding_strategy = EpochShardingStrategy::default();
        let block_range = sharding_strategy.get_block_range();
        let shard = create_shard(shard_index, block_range.clone(), logger.clone());
        let successful_mvq_response = create_successful_mvq_response(shard_index, block_range);
        let shards_and_responses = vec![(shard, successful_mvq_response)];

        let result = process_shard_responses(shards_and_responses, logger);

        assert!(result.is_ok());

        let shards_for_retry = result.unwrap().shards_for_retry;
        assert!(shards_for_retry.is_empty());
    }

    #[test_with_logger]
    fn one_successful_response_no_pending_authentications(logger: Logger) {
        let shard_index = 0;
        let sharding_strategy = EpochShardingStrategy::default();
        let block_range = sharding_strategy.get_block_range();
        let shard = create_shard(shard_index, block_range.clone(), logger.clone());
        let successful_mvq_response = create_successful_mvq_response(shard_index, block_range);
        let shards_and_responses = vec![(shard, successful_mvq_response)];

        let result = process_shard_responses(shards_and_responses, logger);

        assert!(result.is_ok());

        let view_store_uris_for_authentication = result.unwrap().view_store_uris_for_authentication;
        assert!(view_store_uris_for_authentication.is_empty());
    }

    #[test_with_logger]
    fn one_successful_response_one_new_query_response(logger: Logger) {
        let shard_index = 0;
        let sharding_strategy = EpochShardingStrategy::default();
        let block_range = sharding_strategy.get_block_range();
        let shard = create_shard(shard_index, block_range.clone(), logger.clone());
        let successful_mvq_response = create_successful_mvq_response(shard_index, block_range);
        let shards_and_responses = vec![(shard, successful_mvq_response)];

        let result = process_shard_responses(shards_and_responses, logger);

        assert!(result.is_ok());

        let new_query_response = result.unwrap().multi_view_store_query_responses;
        assert_eq!(new_query_response.len(), 1);
    }

    #[test_with_logger]
    fn one_auth_error_response_one_pending_shard(logger: Logger) {
        let shard_index = 0;
        let sharding_strategy = EpochShardingStrategy::default();
        let block_range = sharding_strategy.get_block_range();
        let shard = create_shard(shard_index, block_range.clone(), logger.clone());
        let failed_mvq_response = create_failed_mvq_response(
            shard_index,
            block_range,
            mc_fog_api::view::MultiViewStoreQueryResponseStatus::AUTHENTICATION_ERROR,
        );
        let shards_and_responses = vec![(shard, failed_mvq_response)];

        let result = process_shard_responses(shards_and_responses, logger);

        assert!(result.is_ok());

        let shards_for_retry = result.unwrap().shards_for_retry;
        assert_eq!(shards_for_retry.len(), 1);
    }

    #[test_with_logger]
    fn one_auth_error_response_one_pending_authentications(logger: Logger) {
        let shard_index: usize = 0;
        let sharding_strategy = EpochShardingStrategy::default();
        let block_range = sharding_strategy.get_block_range();
        let shard = create_shard(shard_index, block_range.clone(), logger.clone());
        let failed_mvq_response = create_failed_mvq_response(
            shard_index,
            block_range,
            mc_fog_api::view::MultiViewStoreQueryResponseStatus::AUTHENTICATION_ERROR,
        );
        let shards_and_responses = vec![(shard, failed_mvq_response)];

        let result = process_shard_responses(shards_and_responses, logger);

        assert!(result.is_ok());

        let view_store_uris_for_authentication = result.unwrap().view_store_uris_for_authentication;
        assert_eq!(view_store_uris_for_authentication.len(), 1);
    }

    #[test_with_logger]
    fn one_auth_error_response_zero_new_query_responses(logger: Logger) {
        let shard_index: usize = 0;
        let sharding_strategy = EpochShardingStrategy::default();
        let block_range = sharding_strategy.get_block_range();
        let shard = create_shard(shard_index, block_range.clone(), logger.clone());
        let failed_mvq_response = create_failed_mvq_response(
            shard_index,
            block_range,
            mc_fog_api::view::MultiViewStoreQueryResponseStatus::AUTHENTICATION_ERROR,
        );
        let shards_and_responses = vec![(shard, failed_mvq_response)];

        let result = process_shard_responses(shards_and_responses, logger);

        assert!(result.is_ok());

        let new_query_responses = result.unwrap().multi_view_store_query_responses;
        assert!(new_query_responses.is_empty());
    }

    #[test_with_logger]
    fn one_not_ready_response_zero_new_query_responses(logger: Logger) {
        let shard_index: usize = 0;
        let sharding_strategy = EpochShardingStrategy::default();
        let block_range = sharding_strategy.get_block_range();
        let shard = create_shard(shard_index, block_range.clone(), logger.clone());
        let failed_mvq_response = create_failed_mvq_response(
            shard_index,
            block_range,
            mc_fog_api::view::MultiViewStoreQueryResponseStatus::NOT_READY,
        );
        let shards_and_responses = vec![(shard, failed_mvq_response)];

        let result = process_shard_responses(shards_and_responses, logger);

        assert!(result.is_ok());

        let new_query_responses = result.unwrap().multi_view_store_query_responses;
        assert!(new_query_responses.is_empty());
    }

    #[test_with_logger]
    fn one_not_ready_response_zero_pending_authentications(logger: Logger) {
        let shard_index: usize = 0;
        let sharding_strategy = EpochShardingStrategy::default();
        let block_range = sharding_strategy.get_block_range();
        let shard = create_shard(shard_index, block_range.clone(), logger.clone());
        let failed_mvq_response = create_failed_mvq_response(
            shard_index,
            block_range,
            mc_fog_api::view::MultiViewStoreQueryResponseStatus::NOT_READY,
        );
        let shards_and_responses = vec![(shard, failed_mvq_response)];

        let result = process_shard_responses(shards_and_responses, logger);

        assert!(result.is_ok());

        let view_store_uris_for_authentication = result.unwrap().view_store_uris_for_authentication;
        assert_eq!(view_store_uris_for_authentication.len(), 0);
    }

    #[test_with_logger]
    fn one_not_ready_response_zero_pending_shard_clients(logger: Logger) {
        let shard_index: usize = 0;
        let sharding_strategy = EpochShardingStrategy::default();
        let block_range = sharding_strategy.get_block_range();
        let shard = create_shard(shard_index, block_range.clone(), logger.clone());
        let failed_mvq_response = create_failed_mvq_response(
            shard_index,
            block_range,
            mc_fog_api::view::MultiViewStoreQueryResponseStatus::NOT_READY,
        );
        let shards_and_responses = vec![(shard, failed_mvq_response)];
        let result = process_shard_responses(shards_and_responses, logger);

        assert!(result.is_ok());

        let shard_clients_for_retry = result.unwrap().shards_for_retry;
        assert_eq!(shard_clients_for_retry.len(), 0);
    }

    #[test_with_logger]
    fn mixed_auth_error_and_successful_responses_processes_correctly(logger: Logger) {
        const NUMBER_OF_FAILURES: usize = 11;
        const NUMBER_OF_SUCCESSES: usize = 8;

        let mut shards_and_clients = Vec::new();
        for i in 0..NUMBER_OF_FAILURES {
            let block_range = BlockRange::new_from_length(i as u64, 1);
            let shard = create_shard(i, block_range.clone(), logger.clone());
            let failed_mvq_response = create_failed_mvq_response(
                i,
                block_range,
                mc_fog_api::view::MultiViewStoreQueryResponseStatus::AUTHENTICATION_ERROR,
            );
            shards_and_clients.push((shard, failed_mvq_response));
        }
        for i in 0..NUMBER_OF_SUCCESSES {
            let shard_index = i + NUMBER_OF_FAILURES;
            let block_range = BlockRange::new_from_length(shard_index as u64, 1);
            let shard = create_shard(shard_index, block_range.clone(), logger.clone());
            let successful_mvq_response = create_successful_mvq_response(shard_index, block_range);
            shards_and_clients.push((shard, successful_mvq_response));
        }

        let result = process_shard_responses(shards_and_clients, logger);
        assert!(result.is_ok());
        let processed_shard_response_data = result.unwrap();

        assert_eq!(
            processed_shard_response_data.shards_for_retry.len(),
            NUMBER_OF_FAILURES
        );
        assert_eq!(
            processed_shard_response_data
                .view_store_uris_for_authentication
                .len(),
            NUMBER_OF_FAILURES
        );
        assert_eq!(
            processed_shard_response_data
                .multi_view_store_query_responses
                .len(),
            NUMBER_OF_SUCCESSES
        );
    }

    #[test_with_logger]
    fn shard_block_range_does_not_match_configured_block_range(logger: Logger) {
        let shard_index: usize = 0;
        let configured_block_range = BlockRange::new(0, 10);
        let shard = create_shard(shard_index, configured_block_range, logger.clone());

        let response_block_range = BlockRange::new(100, 110);
        let response = create_successful_mvq_response(shard_index, response_block_range);
        let shards_and_responses = vec![(shard, response)];

        let result = process_shard_responses(shards_and_responses, logger);

        assert!(result.is_err());
    }
}
