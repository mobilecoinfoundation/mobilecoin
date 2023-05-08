// Copyright (c) 2018-2022 The MobileCoin Foundation

use crate::{
    error::{router_server_err_to_rpc_status, RouterServerError},
    SVC_COUNTERS,
};
use futures::{future::try_join_all, SinkExt, TryStreamExt};
use grpcio::{ChannelBuilder, DuplexSink, RequestStream, RpcStatus, WriteFlags};
use mc_attest_api::attest;
use mc_attest_enclave_api::{EnclaveMessage, NonceSession};
use mc_common::{
    logger::{log, Logger},
    ResponderId,
};
use mc_fog_api::{
    ledger::{
        LedgerRequest, LedgerRequest_oneof_request_data, LedgerResponse, MultiKeyImageStoreRequest,
        MultiKeyImageStoreResponse, MultiKeyImageStoreResponseStatus,
    },
    ledger_grpc::KeyImageStoreApiClient,
};
use mc_fog_ledger_enclave::LedgerEnclaveProxy;
use mc_fog_uri::{ConnectionUri, KeyImageStoreUri};
use mc_util_grpc::{rpc_invalid_arg_error, ConnectionUriGrpcioChannel, ResponseStatus};
use mc_util_metrics::GrpcMethodName;
use mc_util_telemetry::{create_context, tracer, BoxedTracer, FutureExt, Tracer};
use std::{collections::BTreeMap, str::FromStr, sync::Arc};

/// Handles a series of requests sent by the Fog Ledger Router client,
/// routing them out to shards.
pub async fn handle_requests<E>(
    method_name: GrpcMethodName,
    shard_clients: Vec<Arc<KeyImageStoreApiClient>>,
    enclave: E,
    mut requests: RequestStream<LedgerRequest>,
    mut responses: DuplexSink<LedgerResponse>,
    query_retries: usize,
    logger: Logger,
) -> Result<(), grpcio::Error>
where
    E: LedgerEnclaveProxy,
{
    while let Some(request) = requests.try_next().await? {
        // Per the comment thread on pull request #2976, this should be
        // req_impl() and not req().
        // This is so that one call of the original request() method is
        // reported per each actual request the client sends.
        let _timer = SVC_COUNTERS.req_impl(&method_name);

        let result = handle_request(
            request,
            shard_clients.clone(),
            enclave.clone(),
            query_retries,
            logger.clone(),
        )
        .await;

        let response_status = ResponseStatus::from(&result);
        SVC_COUNTERS.resp_impl(&method_name, response_status.is_success);
        SVC_COUNTERS.status_code_impl(&method_name, response_status.code);

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
    request: LedgerRequest,
    shard_clients: Vec<Arc<KeyImageStoreApiClient>>,
    enclave: E,
    query_retries: usize,
    logger: Logger,
) -> Result<LedgerResponse, RpcStatus>
where
    E: LedgerEnclaveProxy,
{
    let tracer = tracer!();
    match request.request_data {
        Some(LedgerRequest_oneof_request_data::auth(request)) => {
            tracer.in_span("auth", |_cx| handle_auth_request(enclave, request, logger))
        }
        Some(LedgerRequest_oneof_request_data::check_key_images(request)) => {
            handle_query_request(
                request,
                enclave,
                shard_clients,
                query_retries,
                logger,
                &tracer,
            )
            .with_context(create_context(&tracer, "check_key_images"))
            .await
        }
        None => {
            let rpc_status = rpc_invalid_arg_error(
                "Inavlid LedgerRequest request",
                "Neither the check_key_images nor auth fields were set".to_string(),
                &logger,
            );
            Err(rpc_status)
        }
    }
}

/// The result of processing the MultiLedgerStoreQueryResponse from each Fog
/// Ledger Shard.
pub struct ProcessedShardResponseData {
    /// gRPC clients for Shards that need to be retried for a successful
    /// response.
    pub shard_clients_for_retry: Vec<Arc<KeyImageStoreApiClient>>,

    /// Uris for individual Fog Ledger Stores that need to be authenticated with
    /// by the Fog Router. It should only have entries if
    /// `shard_clients_for_retry` has entries.
    pub store_uris_for_authentication: Vec<KeyImageStoreUri>,

    /// New, successfully processed query responses.
    pub new_query_responses: Vec<(ResponderId, attest::NonceMessage)>,
}

impl ProcessedShardResponseData {
    pub fn new(
        shard_clients_for_retry: Vec<Arc<KeyImageStoreApiClient>>,
        store_uris_for_authentication: Vec<KeyImageStoreUri>,
        new_query_responses: Vec<(ResponderId, attest::NonceMessage)>,
    ) -> Self {
        ProcessedShardResponseData {
            shard_clients_for_retry,
            store_uris_for_authentication,
            new_query_responses,
        }
    }
}

/// Processes the MultiKeyImageStoreResponses returned by each Ledger Shard.
pub fn process_shard_responses(
    clients_and_responses: Vec<(Arc<KeyImageStoreApiClient>, MultiKeyImageStoreResponse)>,
    logger: Logger,
) -> Result<ProcessedShardResponseData, RouterServerError> {
    let mut shard_clients_for_retry = Vec::new();
    let mut store_uris_for_authentication = Vec::new();
    let mut new_query_responses = Vec::new();

    for (shard_client, mut response) in clients_and_responses {
        let store_uri = KeyImageStoreUri::from_str(response.get_store_uri())?;
        match response.get_status() {
            MultiKeyImageStoreResponseStatus::SUCCESS => {
                let store_responder_id = store_uri.host_and_port_responder_id()?;
                new_query_responses.push((store_responder_id, response.take_query_response()));
            }
            MultiKeyImageStoreResponseStatus::AUTHENTICATION_ERROR => {
                // We did not receive a query response for this shard.Therefore, we need to:
                //  (a) retry the query
                //  (b) authenticate with the Ledger Store that returned the decryption_error
                shard_clients_for_retry.push(shard_client);
                store_uris_for_authentication.push(store_uri);
            }
            // This call will be retried as part of the larger retry logic
            MultiKeyImageStoreResponseStatus::NOT_READY => (),
            // This is a Protobuf decode error - we should never see this
            MultiKeyImageStoreResponseStatus::INVALID_ARGUMENT => {
                log::error!(
                    logger,
                    "Received a response with status 'INVALID_ARGUMENT' from store {}",
                    KeyImageStoreUri::from_str(&response.store_uri)?
                );
            }
            // This is an unexpected error - we should never see this
            MultiKeyImageStoreResponseStatus::UNKNOWN => {
                log::error!(
                    logger,
                    "Received a response with status 'UNKNOWN' from store {}",
                    KeyImageStoreUri::from_str(&response.store_uri)?
                );
            }
        }
    }

    Ok(ProcessedShardResponseData::new(
        shard_clients_for_retry,
        store_uris_for_authentication,
        new_query_responses,
    ))
}

/// Handles a client's authentication request.
pub(crate) fn handle_auth_request<E>(
    enclave: E,
    auth_message: attest::AuthMessage,
    logger: Logger,
) -> Result<LedgerResponse, RpcStatus>
where
    E: LedgerEnclaveProxy,
{
    let (client_auth_response, _) = enclave.client_accept(auth_message.into()).map_err(|err| {
        router_server_err_to_rpc_status("Auth: e client accept", err.into(), logger)
    })?;

    let mut response = LedgerResponse::new();
    response.mut_auth().set_data(client_auth_response.into());
    Ok(response)
}

/// Handles a client's query request.
pub(crate) async fn handle_query_request<E>(
    query: attest::Message,
    enclave: E,
    shard_clients: Vec<Arc<KeyImageStoreApiClient>>,
    query_retries: usize,
    logger: Logger,
    tracer: &BoxedTracer,
) -> Result<LedgerResponse, RpcStatus>
where
    E: LedgerEnclaveProxy,
{
    let mut query_responses: BTreeMap<ResponderId, EnclaveMessage<NonceSession>> = BTreeMap::new();
    let mut shards_to_query = shard_clients.clone();
    let sealed_query = enclave
        .decrypt_and_seal_query(query.into())
        .map_err(|err| {
            router_server_err_to_rpc_status(
                "Key Images Query: internal encryption error",
                err.into(),
                logger.clone(),
            )
        })?;

    // The retry logic here is:
    // Set retries remaining to query_retries
    // Send query and process responses
    // If there's a response from every shard, we're done
    // If there's a new store, repeat
    // If there's no new store and we don't have enough responses, decrement
    // remaining_retries and loop
    let mut remaining_retries = query_retries;
    while remaining_retries > 0 {
        let multi_ledger_store_query_request = tracer
            .in_span("create_multi_key_image_query", |_cx| {
                enclave
                    .create_multi_key_image_store_query_data(sealed_query.clone())
                    .map_err(|err| {
                        router_server_err_to_rpc_status(
                            "Key Images Query: internal encryption error",
                            err.into(),
                            logger.clone(),
                        )
                    })
            })?
            .into();
        let clients_and_responses =
            route_query(&multi_ledger_store_query_request, shards_to_query.clone())
                .with_context(create_context(
                    tracer,
                    "send_multi_key_image_request_to_shards",
                ))
                .await
                .map_err(|err| {
                    router_server_err_to_rpc_status(
                        "Key Images Query: internal query routing error",
                        err,
                        logger.clone(),
                    )
                })?;

        let processed_shard_response_data =
            tracer.in_span("process_key_image_shard_responses", |_cx| {
                process_shard_responses(clients_and_responses, logger.clone()).map_err(|err| {
                    router_server_err_to_rpc_status(
                        "Key Images Query: internal query response processing",
                        err,
                        logger.clone(),
                    )
                })
            })?;

        for (store_responder_id, new_query_response) in processed_shard_response_data
            .new_query_responses
            .into_iter()
        {
            query_responses.insert(store_responder_id, new_query_response.into());
        }

        if query_responses.len() >= shard_clients.len() {
            break;
        }

        shards_to_query = processed_shard_response_data.shard_clients_for_retry;
        if !shards_to_query.is_empty() {
            authenticate_ledger_stores(
                enclave.clone(),
                processed_shard_response_data.store_uris_for_authentication,
                logger.clone(),
            )
            .with_context(create_context(tracer, "authn_key_image_stores"))
            .await?;
        } else {
            remaining_retries -= 1;
        }
    }

    if remaining_retries == 0 {
        return Err(router_server_err_to_rpc_status(
            "Key Images Query: timed out connecting to key image stores",
            RouterServerError::LedgerStoreError(format!(
                "Received {query_retries} responses which failed to advance the MultiKeyImageStoreRequest"
            )),
            logger.clone(),
        ));
    }

    let query_response = tracer.in_span("collate_key_image_responses", |_cx| {
        enclave
            .collate_shard_query_responses(sealed_query, query_responses)
            .map_err(|err| {
                router_server_err_to_rpc_status(
                    "Key Images Query: shard response collation error",
                    RouterServerError::Enclave(err),
                    logger.clone(),
                )
            })
    })?;

    let mut response = LedgerResponse::new();
    response.set_check_key_image_response(query_response.into());
    Ok(response)
}

/// Sends a client's query request to all of the Fog Ledger shards.
async fn route_query(
    request: &MultiKeyImageStoreRequest,
    shard_clients: Vec<Arc<KeyImageStoreApiClient>>,
) -> Result<Vec<(Arc<KeyImageStoreApiClient>, MultiKeyImageStoreResponse)>, RouterServerError> {
    let responses = shard_clients
        .into_iter()
        .map(|shard_client| query_shard(request, shard_client));
    try_join_all(responses).await
}

/// Sends a client's query request to one of the Fog Ledger shards.
async fn query_shard(
    request: &MultiKeyImageStoreRequest,
    shard_client: Arc<KeyImageStoreApiClient>,
) -> Result<(Arc<KeyImageStoreApiClient>, MultiKeyImageStoreResponse), RouterServerError> {
    let client_unary_receiver = shard_client.multi_key_image_store_query_async(request)?;
    let response = client_unary_receiver.await?;

    Ok((shard_client, response))
}

// Authenticates Fog Ledger Stores that have previously not been authenticated.
async fn authenticate_ledger_stores<E: LedgerEnclaveProxy>(
    enclave: E,
    ledger_store_uris: Vec<KeyImageStoreUri>,
    logger: Logger,
) -> Result<Vec<()>, RpcStatus> {
    let pending_auth_requests = ledger_store_uris
        .into_iter()
        .map(|store_uri| authenticate_ledger_store(enclave.clone(), store_uri, logger.clone()));

    try_join_all(pending_auth_requests).await.map_err(|err| {
        router_server_err_to_rpc_status(
            "Key Images Query: cannot authenticate with each Fog Ledger Store:",
            err,
            logger.clone(),
        )
    })
}

// Authenticates a Fog Ledger Store that has previously not been authenticated.
async fn authenticate_ledger_store<E: LedgerEnclaveProxy>(
    enclave: E,
    ledger_store_url: KeyImageStoreUri,
    logger: Logger,
) -> Result<(), RouterServerError> {
    let ledger_store_id = ledger_store_url.responder_id()?;
    let client_auth_request = enclave.ledger_store_init(ledger_store_id.clone())?;
    let grpc_env = Arc::new(
        grpcio::EnvBuilder::new()
            .name_prefix("authenticate-ledger-store".to_string())
            .build(),
    );
    let ledger_store_client = KeyImageStoreApiClient::new(
        ChannelBuilder::default_channel_builder(grpc_env)
            .keepalive_permit_without_calls(false)
            .connect_to_uri(&ledger_store_url, &logger),
    );

    let auth_unary_receiver = ledger_store_client.auth_async(&client_auth_request.into())?;
    let auth_response = auth_unary_receiver.await?;

    enclave
        .ledger_store_connect(ledger_store_id, auth_response.into())
        .map_err(|e| e.into())
}
