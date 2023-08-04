// Copyright (c) 2018-2022 The MobileCoin Foundation

use crate::{
    error::{router_server_err_to_rpc_status, RouterServerError},
    fog_view_router_server::Shard,
    shard_responses_processor, SVC_COUNTERS,
};
use futures::{future::try_join_all, SinkExt, TryStreamExt};
use grpcio::{ChannelBuilder, DuplexSink, RequestStream, RpcStatus, WriteFlags};
use lazy_static::lazy_static;
use mc_attest_api::attest;
use mc_attest_enclave_api::SealedClientMessage;
use mc_common::logger::{log, Logger};
use mc_fog_api::{
    view::{FogViewRouterRequest, FogViewRouterResponse, MultiViewStoreQueryRequest},
    view_grpc::FogViewStoreApiClient,
};
use mc_fog_types::view::MultiViewStoreQueryResponse;
use mc_fog_uri::FogViewStoreUri;
use mc_fog_view_enclave_api::ViewEnclaveProxy;
use mc_util_grpc::{rpc_invalid_arg_error, ConnectionUriGrpcioChannel, ResponseStatus};
use mc_util_metrics::GrpcMethodName;
use mc_util_telemetry::{create_context, tracer, BoxedTracer, FutureExt, Tracer};
use mc_util_uri::ConnectionUri;
use prometheus::{
    histogram_opts, register_histogram, register_histogram_vec, register_int_counter,
    register_int_gauge, Histogram, HistogramVec, IntCounter, IntGauge,
};
use std::{sync::Arc, time::Instant};
const RETRY_COUNT: usize = 3;
use regex::Regex;

/// Handles a series of requests sent by the Fog Router client.
pub async fn handle_requests<E>(
    method_name: GrpcMethodName,
    shards: Vec<Shard>,
    enclave: E,
    mut requests: RequestStream<FogViewRouterRequest>,
    mut responses: DuplexSink<FogViewRouterResponse>,
    logger: Logger,
) -> Result<(), grpcio::Error>
where
    E: ViewEnclaveProxy,
{
    while let Some(request) = requests.try_next().await? {
        let _timer = SVC_COUNTERS.req_impl(&method_name);
        CONNECTED_CLIENTS.inc();
        let result = handle_request(request, shards.clone(), enclave.clone(), logger.clone()).await;

        // Perform prometheus logic before the match statement to ensure that
        // this logic is executed.
        let response_status = ResponseStatus::from(&result);
        SVC_COUNTERS.resp_impl(&method_name, response_status.is_success);
        SVC_COUNTERS.status_code_impl(&method_name, response_status.code);

        match result {
            Ok(response) => responses.send((response, WriteFlags::default())).await?,
            Err(rpc_status) => {
                log::error!(logger, "error handling request: {}", &method_name);
                CONNECTED_CLIENTS.dec();
                return responses.fail(rpc_status).await;
            }
        }
    }
    match responses.close().await {
        Ok(value) => {
            CONNECTED_CLIENTS.dec();
            Ok(value)
        }
        Err(err) => {
            log::error!(logger, "error closing response");
            CONNECTED_CLIENTS.dec();
            Err(err)
        }
    }
}

/// Handles a client's request by performing either an authentication or a
/// query.
pub async fn handle_request<E>(
    mut request: FogViewRouterRequest,
    shards: Vec<Shard>,
    enclave: E,
    logger: Logger,
) -> Result<FogViewRouterResponse, RpcStatus>
where
    E: ViewEnclaveProxy,
{
    let tracer = tracer!();
    if request.has_auth() {
        tracer.in_span("router_auth", |_cx| {
            handle_auth_request(enclave, request.take_auth(), logger)
        })
    } else if request.has_query() {
        handle_query_request(request.take_query(), enclave, shards, logger, &tracer)
            .with_context(create_context(&tracer, "router_query"))
            .await
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
pub fn handle_auth_request<E>(
    enclave: E,
    auth_message: attest::AuthMessage,
    logger: Logger,
) -> Result<FogViewRouterResponse, RpcStatus>
where
    E: ViewEnclaveProxy,
{
    AUTH_CLIENT_REQUESTS.inc();
    let (client_auth_response, _) = enclave.client_accept(auth_message.into()).map_err(|err| {
        router_server_err_to_rpc_status("Auth: e client accept", err.into(), logger)
    })?;

    let mut response = FogViewRouterResponse::new();
    response.mut_auth().set_data(client_auth_response.into());
    Ok(response)
}

/// Handles a client's query request.
pub async fn handle_query_request<E>(
    query: attest::Message,
    enclave: E,
    shards: Vec<Shard>,
    logger: Logger,
    tracer: &BoxedTracer,
) -> Result<FogViewRouterResponse, RpcStatus>
where
    E: ViewEnclaveProxy,
{
    let sealed_query = enclave
        .decrypt_and_seal_query(query.into())
        .map_err(|err| {
            router_server_err_to_rpc_status(
                "Query: internal decrypt and seal error",
                err.into(),
                logger.clone(),
            )
        })?;

    let query_responses = get_query_responses(
        sealed_query.clone(),
        enclave.clone(),
        shards.clone(),
        logger.clone(),
    )
    .with_context(create_context(tracer, "router_get_query_responses"))
    .await?;

    let query_response = tracer.in_span("router_collate_query_responses", |_cx| {
        enclave
            .collate_shard_query_responses(sealed_query, query_responses)
            .map_err(|err| {
                router_server_err_to_rpc_status(
                    "Query: shard response collation",
                    RouterServerError::Enclave(err),
                    logger.clone(),
                )
            })
    })?;

    let mut response = FogViewRouterResponse::new();
    response.set_query(query_response.into());
    Ok(response)
}

async fn get_query_responses<E>(
    sealed_query: SealedClientMessage,
    enclave: E,
    mut shards: Vec<Shard>,
    logger: Logger,
) -> Result<Vec<MultiViewStoreQueryResponse>, RpcStatus>
where
    E: ViewEnclaveProxy,
{
    let mut query_responses: Vec<MultiViewStoreQueryResponse> = Vec::with_capacity(shards.len());
    let mut remaining_tries = RETRY_COUNT;
    let _timer = BULK_QUERY_REQUESTS.start_timer();
    while remaining_tries > 0 {
        if remaining_tries < RETRY_COUNT {
            QUERY_GROUP_RETRY.inc();
        }
        let multi_view_store_query_request = enclave
            .create_multi_view_store_query_data(sealed_query.clone())
            .map_err(|err| {
                router_server_err_to_rpc_status(
                    "Query: internal encryption error for MultiViewStoreQueryData",
                    err.into(),
                    logger.clone(),
                )
            })?
            .into();
        let clients_and_responses = route_query(&multi_view_store_query_request, shards.clone())
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
            logger.clone(),
        )
        .map_err(|err| {
            router_server_err_to_rpc_status(
                "Query: internal query response processing",
                err,
                logger.clone(),
            )
        })?;

        for multi_view_store_query_response in processed_shard_response_data
            .multi_view_store_query_responses
            .into_iter()
        {
            query_responses.push(multi_view_store_query_response);
        }

        shards = processed_shard_response_data.shards_for_retry;
        if shards.is_empty() {
            break;
        }

        let view_store_uris_for_authentication =
            processed_shard_response_data.view_store_uris_for_authentication;
        if !view_store_uris_for_authentication.is_empty() {
            authenticate_view_stores(
                enclave.clone(),
                view_store_uris_for_authentication,
                logger.clone(),
            )
            .await?;
        } else {
            remaining_tries -= 1;
        }
    }

    if remaining_tries == 0 {
        return Err(router_server_err_to_rpc_status(
            "Query: timed out connecting to view stores",
            RouterServerError::ViewStoreError(format!(
                "Received {RETRY_COUNT} responses which failed to advance the MultiViewStoreRequest"
            )),
            logger.clone(),
        ));
    }

    Ok(query_responses)
}

/// Sends a client's query request to all of the Fog View shards.
async fn route_query(
    request: &MultiViewStoreQueryRequest,
    shards: Vec<Shard>,
) -> Result<Vec<(Shard, MultiViewStoreQueryResponse)>, RouterServerError> {
    let responses = shards
        .into_iter()
        .map(|shard_client| query_shard(request, shard_client));
    try_join_all(responses).await
}

fn extract_subdomain(input: &str) -> &str {
    let re = Regex::new(r"^(.*?)\..*").unwrap();
    let captures = re.captures(input);
    captures
        .and_then(|caps| caps.get(1).map(|m| m.as_str()))
        .unwrap_or("")
}

/// Sends a client's query request to one of the Fog View shards.
async fn query_shard(
    request: &MultiViewStoreQueryRequest,
    shard: Shard,
) -> Result<(Shard, MultiViewStoreQueryResponse), RouterServerError> {
    let start_time = Instant::now();
    let subdomain = extract_subdomain(shard.uri.host.as_str());
    let client_unary_receiver = shard
        .grpc_client
        .multi_view_store_query_async(request)
        .or_else(|err| {
            let histogram = QUERY_REQUESTS.with_label_values(&[&subdomain, &err.to_string()]);
            histogram.observe(start_time.elapsed().as_secs_f64());
            Err(err)
        })?;
    let response = client_unary_receiver.await.or_else(|err| {
        let histogram = QUERY_REQUESTS.with_label_values(&[&subdomain, &err.to_string()]);
        histogram.observe(start_time.elapsed().as_secs_f64());
        Err(err)
    })?;
    let histogram = QUERY_REQUESTS.with_label_values(&[&subdomain, "ok"]);
    histogram.observe(start_time.elapsed().as_secs_f64());
    Ok((shard, response.try_into()?))
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
    let view_store_id = view_store_url.host_and_port_responder_id()?;
    let nonce_auth_request = enclave.view_store_init(view_store_id.clone())?;
    let grpc_env = Arc::new(
        grpcio::EnvBuilder::new()
            .name_prefix("authenticate-view-store".to_string())
            .build(),
    );
    let view_store_client = FogViewStoreApiClient::new(
        ChannelBuilder::default_channel_builder(grpc_env)
            .keepalive_permit_without_calls(false)
            .connect_to_uri(&view_store_url, &logger),
    );

    let auth_unary_receiver = view_store_client.auth_async(&nonce_auth_request.into())?;
    let nonce_auth_response = auth_unary_receiver.await?;

    enclave.view_store_connect(view_store_id, nonce_auth_response.into())?;
    Ok(())
}

// Initialize global metrics
lazy_static! {
    pub static ref QUERY_REQUESTS: HistogramVec = register_histogram_vec!(
        histogram_opts!(
            "fog_view_router_query_requests",
            "Queries to individual stores"
        ),
        &["store_uri", "status"]
    )
    .expect("metric cannot be created");
    pub static ref QUERY_GROUP_RETRY: IntCounter = register_int_counter!(
        "fog_view_router_bulk_query_retry",
        "Query retries per client request"
    )
    .expect("metric cannot be created");
    pub static ref BULK_QUERY_REQUESTS: Histogram = register_histogram!(histogram_opts!(
        "fog_view_router_bulk_query_requests",
        "Queries to router"
    ))
    .expect("metric cannot be created");
    pub static ref AUTH_CLIENT_REQUESTS: IntCounter =
        register_int_counter!("fog_view_auth_client_requests", "Auth requests to stores")
            .expect("metric cannot be created");
    pub static ref CONNECTED_CLIENTS: IntGauge =
        register_int_gauge!("fog_view_connected_clients", "Connected Clients")
            .expect("metric cannot be created");
}
