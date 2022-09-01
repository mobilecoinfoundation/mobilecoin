// Copyright (c) 2018-2022 The MobileCoin Foundation

use crate::{
    error::{router_server_err_to_rpc_status, RouterServerError},
};
use futures::{future::try_join_all, TryStreamExt, SinkExt};
use grpcio::{DuplexSink, RequestStream, RpcStatus, WriteFlags};
use mc_attest_api::attest;
use mc_common::{logger::Logger};
use mc_fog_api::{
    ledger::{LedgerRequest, LedgerResponse, MultiKeyImageStoreRequest, MultiKeyImageStoreResponse}, ledger_grpc::KeyImageStoreApiClient,
};
use mc_fog_ledger_enclave::LedgerEnclaveProxy;
use mc_fog_uri::KeyImageStoreUri;
//use mc_fog_ledger_enclave_api::LedgerEnclaveProxy;
use mc_util_grpc::{rpc_invalid_arg_error};
use std::{str::FromStr, sync::Arc};

#[allow(dead_code)] //FIXME
const RETRY_COUNT: usize = 3;

/// Handles a series of requests sent by the Fog Ledger Router client,
/// routing them out to shards.
#[allow(dead_code)] //FIXME
pub async fn handle_requests<E>(
    shard_clients: Vec<Arc<KeyImageStoreApiClient>>,
    enclave: E,
    mut requests: RequestStream<LedgerRequest>,
    mut responses: DuplexSink<LedgerResponse>,
    logger: Logger,
) -> Result<(), grpcio::Error>
where
    E: LedgerEnclaveProxy,
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
    mut request: LedgerRequest,
    shard_clients: Vec<Arc<KeyImageStoreApiClient>>,
    enclave: E,
    logger: Logger,
) -> Result<LedgerResponse, RpcStatus>
where
    E: LedgerEnclaveProxy,
{
    if request.has_auth() {
        handle_auth_request(enclave, request.take_auth(), logger)
    } else if request.has_check_key_images() {
        handle_query_request(request.take_check_key_images(), enclave, shard_clients, logger).await
        // TODO: Handle other cases here as they are added, such as the merkele proof service.
    } else {
        let rpc_status = rpc_invalid_arg_error(
            "Inavlid LedgerRequest request",
            "Neither the query nor auth fields were set".to_string(),
            &logger,
        );
        Err(rpc_status)
    }
}

/// The result of processing the MultiLedgerStoreQueryResponse from each Fog Ledger Shard.
pub struct ProcessedShardResponseData {
    /// gRPC clients for Shards that need to be retried for a successful
    /// response.
    pub shard_clients_for_retry: Vec<Arc<KeyImageStoreApiClient>>,

    /// Uris for individual Fog Ledger Stores that need to be authenticated with
    /// by the Fog Router. It should only have entries if
    /// `shard_clients_for_retry` has entries.
    pub store_uris_for_authentication: Vec<KeyImageStoreUri>,

    /// New, successfully processed query responses.
    pub new_query_responses: Vec<attest::Message>,
}

impl ProcessedShardResponseData {
    pub fn new(
        shard_clients_for_retry: Vec<Arc<KeyImageStoreApiClient>>,
        store_uris_for_authentication: Vec<KeyImageStoreUri>,
        new_query_responses: Vec<attest::Message>,
    ) -> Self {
        ProcessedShardResponseData {
            shard_clients_for_retry,
            store_uris_for_authentication,
            new_query_responses,
        }
    }
}

/// Processes the MultiLedgerStoreQueryResponses returned by each Ledger Shard.
pub fn process_shard_responses(
    clients_and_responses: Vec<(Arc<KeyImageStoreApiClient>, MultiKeyImageStoreResponse)>,
) -> Result<ProcessedShardResponseData, RouterServerError> {
    let mut shard_clients_for_retry = Vec::new();
    let mut store_uris_for_authentication = Vec::new();
    let mut new_query_responses = Vec::new();

    for (shard_client, mut response) in clients_and_responses {
        // We did not receive a query_response for this shard.Therefore, we need to:
        //  (a) retry the query
        //  (b) authenticate with the Ledger Store that returned the decryption_error
        if response.has_decryption_error() {
            shard_clients_for_retry.push(shard_client);
            let store_uri =
            KeyImageStoreUri::from_str(&response.get_decryption_error().store_uri)?;
            store_uris_for_authentication.push(store_uri);
        } else {
            new_query_responses.push(response.take_query_response());
        }
    }

    Ok(ProcessedShardResponseData::new(
        shard_clients_for_retry,
        store_uris_for_authentication,
        new_query_responses,
    ))
}

/// Handles a client's authentication request.
fn handle_auth_request<E>(
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

#[allow(unused_variables)] // FIXME when enclave code is set up. 
/// Handles a client's query request.
async fn handle_query_request<E>(
    query: attest::Message,
    enclave: E,
    shard_clients: Vec<Arc<KeyImageStoreApiClient>>,
    logger: Logger,
) -> Result<LedgerResponse, RpcStatus>
where
    E: LedgerEnclaveProxy,
{
    let mut query_responses: Vec<attest::Message> = Vec::with_capacity(shard_clients.len());
    let mut shard_clients = shard_clients.clone();
    // TODO: use retry crate?
    for _ in 0..RETRY_COUNT {
        /*
        let multi_ledger_store_query_request = enclave
            .create_multi_key_image_store_query_data(query.clone().into())
            .map_err(|err| {
                router_server_err_to_rpc_status(
                    "Query: internal encryption error",
                    err.into(),
                    logger.clone(),
                )
            })?
            .into();*/
        let test_request = MultiKeyImageStoreRequest::default();
        let clients_and_responses =
            route_query(&test_request, shard_clients.clone())
                .await
                .map_err(|err| {
                    router_server_err_to_rpc_status(
                        "Query: internal query routing error",
                        err,
                        logger.clone(),
                    )
                })?;

        let mut processed_shard_response_data = process_shard_responses(
            clients_and_responses,
        )
        .map_err(|err| {
            router_server_err_to_rpc_status(
                "Query: internal query response processing",
                err,
                logger.clone(),
            )
        })?;

        query_responses.append(&mut processed_shard_response_data.new_query_responses);
        shard_clients = processed_shard_response_data.shard_clients_for_retry;
        if shard_clients.is_empty() {
            break;
        }

        /* TODO pending ledger router code enclave-side. 
        
        authenticate_ledger_stores(
            enclave.clone(),
            processed_shard_response_data.store_uris_for_authentication,
            logger.clone(),
        )
        .await?;*/
    }

    // TODO: Collate the query_responses into one response for the client. Make an
    // enclave  method for this.
    let response = LedgerResponse::new();
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



/* TODO pending ledger router code enclave-side. 

// Authenticates Fog Ledger Stores that have previously not been authenticated.
async fn authenticate_ledger_stores<E: LedgerEnclaveProxy>(
    enclave: E,
    ledger_store_uris: Vec<LedgerStoreUri>,
    logger: Logger,
) -> Result<(), RpcStatus> {
    let pending_auth_requests = ledger_store_uris
        .into_iter()
        .map(|store_uri| authenticate_ledger_store(enclave.clone(), store_uri, logger.clone()));

    try_join_all(pending_auth_requests).await.map_err(|err| {
        router_server_err_to_rpc_status(
            "Query: cannot authenticate with each Fog Ledger Store:",
            err,
            logger.clone(),
        )
    })
    Ok(())
}

// Authenticates a Fog Ledger Store that has previously not been authenticated.
async fn authenticate_ledger_store<E: LedgerEnclaveProxy>(
    enclave: E,
    ledger_store_url: LedgerStoreUri,
    logger: Logger,
) -> Result<(), RouterServerError> {
    let ledger_store_id = ResponderId::from_str(&ledger_store_url.to_string())?;
    let client_auth_request = enclave.ledger_store_init(ledger_store_id.clone())?;
    let grpc_env = Arc::new(
        grpcio::EnvBuilder::new()
            .name_prefix("authenticate-ledger-store".to_string())
            .build(),
    );
    let ledger_store_client = KeyImageStoreApiClient::new(
        ChannelBuilder::default_channel_builder(grpc_env).connect_to_uri(&ledger_store_url, &logger),
    );

    let auth_unary_receiver = ledger_store_client.auth_async(&client_auth_request.into())?;
    let auth_response = auth_unary_receiver.await?;

    let result = enclave.ledger_store_connect(ledger_store_id, auth_response.into())?;

    Ok(result)
}
*/ 