// Copyright (c) 2018-2022 The MobileCoin Foundation

use crate::{
    error::{router_server_err_to_rpc_status, RouterServerError},
    shard_responses_processor,
};
use futures::{future::try_join_all, SinkExt, TryStreamExt};
use grpcio::{ChannelBuilder, DuplexSink, RequestStream, RpcStatus, WriteFlags};
use mc_attest_api::attest;
use mc_attest_enclave_api::{ClientSession, EnclaveMessage};
use mc_common::{logger::Logger, ResponderId};
use mc_fog_api::{
    view::{
        FogViewRouterRequest, FogViewRouterResponse, MultiViewStoreQueryRequest,
        MultiViewStoreQueryResponse,
    },
    view_grpc::FogViewStoreApiClient,
};
use mc_fog_uri::FogViewStoreUri;
use mc_fog_view_enclave_api::ViewEnclaveProxy;
use mc_util_grpc::{rpc_invalid_arg_error, ConnectionUriGrpcioChannel};
use mc_util_uri::ConnectionUri;
use std::{collections::BTreeMap, sync::Arc};

const RETRY_COUNT: usize = 3;

/// Handles a series of requests sent by the Fog Router client.
pub async fn handle_requests<E>(
    shard_clients: Vec<Arc<FogViewStoreApiClient>>,
    enclave: E,
    mut requests: RequestStream<FogViewRouterRequest>,
    mut responses: DuplexSink<FogViewRouterResponse>,
    logger: Logger,
) -> Result<(), grpcio::Error>
where
    E: ViewEnclaveProxy,
{
    while let Some(request) = requests.try_next().await? {
        let result = handle_request(
            request,
            shard_clients.clone(),
            enclave.clone(),
            logger.clone(),
        )
        .await;
        match result {
            Ok(response) => responses.send((response, WriteFlags::default())).await?,
            Err(rpc_status) => return responses.fail(rpc_status).await,
        }
    }
    responses.close().await?;
    Ok(())
}

/// Handles a client's request by performing either an authentication or a
/// query.
pub async fn handle_request<E>(
    mut request: FogViewRouterRequest,
    shard_clients: Vec<Arc<FogViewStoreApiClient>>,
    enclave: E,
    logger: Logger,
) -> Result<FogViewRouterResponse, RpcStatus>
where
    E: ViewEnclaveProxy,
{
    if request.has_auth() {
        handle_auth_request(enclave, request.take_auth(), logger)
    } else if request.has_query() {
        handle_query_request(request.take_query(), enclave, shard_clients, logger).await
    } else {
        let rpc_status = rpc_invalid_arg_error(
            "Inavlid FogViewRouterRequest request",
            "Neither the query nor auth fields were set".to_string(),
            &logger,
        );
        Err(rpc_status)
    }
}

/// Handles a client's authentication request.
fn handle_auth_request<E>(
    enclave: E,
    auth_message: attest::AuthMessage,
    logger: Logger,
) -> Result<FogViewRouterResponse, RpcStatus>
where
    E: ViewEnclaveProxy,
{
    let (client_auth_response, _) = enclave.client_accept(auth_message.into()).map_err(|err| {
        router_server_err_to_rpc_status("Auth: e client accept", err.into(), logger)
    })?;

    let mut response = FogViewRouterResponse::new();
    response.mut_auth().set_data(client_auth_response.into());
    Ok(response)
}

/// Handles a client's query request.
async fn handle_query_request<E>(
    query: attest::Message,
    enclave: E,
    shard_clients: Vec<Arc<FogViewStoreApiClient>>,
    logger: Logger,
) -> Result<FogViewRouterResponse, RpcStatus>
where
    E: ViewEnclaveProxy,
{
    let mut query_responses: BTreeMap<ResponderId, EnclaveMessage<ClientSession>> = BTreeMap::new();
    let mut shard_clients = shard_clients.clone();
    // TODO: use retry crate?
    for _ in 0..RETRY_COUNT {
        let multi_view_store_query_request = enclave
            .create_multi_view_store_query_data(query.clone().into())
            .map_err(|err| {
                router_server_err_to_rpc_status(
                    "Query: internal encryption error",
                    err.into(),
                    logger.clone(),
                )
            })?
            .into();
        let clients_and_responses =
            route_query(&multi_view_store_query_request, shard_clients.clone())
                .await
                .map_err(|err| {
                    router_server_err_to_rpc_status(
                        "Query: internal query routing error",
                        err,
                        logger.clone(),
                    )
                })?;

        let processed_shard_response_data = shard_responses_processor::process_shard_responses(
            clients_and_responses,
        )
        .map_err(|err| {
            router_server_err_to_rpc_status(
                "Query: internal query response processing",
                err,
                logger.clone(),
            )
        })?;

        for (store_responder_id, new_query_response) in processed_shard_response_data
            .new_query_responses
            .into_iter()
        {
            query_responses.insert(store_responder_id, new_query_response.into());
        }

        shard_clients = processed_shard_response_data.shard_clients_for_retry;
        if shard_clients.is_empty() {
            break;
        }

        authenticate_view_stores(
            enclave.clone(),
            processed_shard_response_data.view_store_uris_for_authentication,
            logger.clone(),
        )
        .await?;
    }

    let query_response = enclave
        .collate_shard_query_responses(query.into(), query_responses)
        .map_err(|err| {
            router_server_err_to_rpc_status(
                "Query: shard response collation",
                RouterServerError::Enclave(err),
                logger.clone(),
            )
        })?;

    let mut response = FogViewRouterResponse::new();
    response.set_query(query_response.into());
    Ok(response)
}

/// Sends a client's query request to all of the Fog View shards.
async fn route_query(
    request: &MultiViewStoreQueryRequest,
    shard_clients: Vec<Arc<FogViewStoreApiClient>>,
) -> Result<Vec<(Arc<FogViewStoreApiClient>, MultiViewStoreQueryResponse)>, RouterServerError> {
    let responses = shard_clients
        .into_iter()
        .map(|shard_client| query_shard(request, shard_client));
    try_join_all(responses).await
}

/// Sends a client's query request to one of the Fog View shards.
async fn query_shard(
    request: &MultiViewStoreQueryRequest,
    shard_client: Arc<FogViewStoreApiClient>,
) -> Result<(Arc<FogViewStoreApiClient>, MultiViewStoreQueryResponse), RouterServerError> {
    let client_unary_receiver = shard_client.multi_view_store_query_async(request)?;
    let response = client_unary_receiver.await?;

    Ok((shard_client, response))
}

/// Authenticates Fog View Stores that have previously not been authenticated.
async fn authenticate_view_stores<E: ViewEnclaveProxy>(
    enclave: E,
    view_store_uris: Vec<FogViewStoreUri>,
    logger: Logger,
) -> Result<Vec<()>, RpcStatus> {
    let pending_auth_requests = view_store_uris
        .into_iter()
        .map(|store_uri| authenticate_view_store(enclave.clone(), store_uri, logger.clone()));

    try_join_all(pending_auth_requests).await.map_err(|err| {
        router_server_err_to_rpc_status(
            "Query: cannot authenticate with each Fog View Store:",
            err,
            logger.clone(),
        )
    })
}

/// Authenticates a Fog View Store that has previously not been authenticated.
async fn authenticate_view_store<E: ViewEnclaveProxy>(
    enclave: E,
    view_store_url: FogViewStoreUri,
    logger: Logger,
) -> Result<(), RouterServerError> {
    let view_store_id = view_store_url.responder_id()?;
    let client_auth_request = enclave.view_store_init(view_store_id.clone())?;
    let grpc_env = Arc::new(
        grpcio::EnvBuilder::new()
            .name_prefix("authenticate-view-store".to_string())
            .build(),
    );
    let view_store_client = FogViewStoreApiClient::new(
        ChannelBuilder::default_channel_builder(grpc_env).connect_to_uri(&view_store_url, &logger),
    );

    let auth_unary_receiver = view_store_client.auth_async(&client_auth_request.into())?;
    let auth_response = auth_unary_receiver.await?;

    let result = enclave.view_store_connect(view_store_id, auth_response.into())?;

    Ok(result)
}
