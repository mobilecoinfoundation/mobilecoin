// Copyright (c) 2018-2022 The MobileCoin Foundation

use crate::error::{router_server_err_to_rpc_status, RouterServerError};
use futures::{future::try_join_all, FutureExt, SinkExt, TryFutureExt, TryStreamExt};
use grpcio::{ChannelBuilder, DuplexSink, RequestStream, RpcContext, RpcStatus, WriteFlags};
use mc_attest_api::attest;
use mc_common::{
    logger::{log, Logger},
    ResponderId,
};
use mc_fog_api::{
    view::{
        FogViewRouterRequest, FogViewRouterResponse, MultiViewStoreQueryRequest,
        MultiViewStoreQueryResponse,
    },
    view_grpc::{FogViewApiClient, FogViewRouterApi},
};
use mc_fog_uri::FogViewUri;
use mc_fog_view_enclave_api::ViewEnclaveProxy;
use mc_util_grpc::{rpc_invalid_arg_error, rpc_logger, ConnectionUriGrpcioChannel};
use mc_util_metrics::SVC_COUNTERS;
use std::{future::Future, str::FromStr, sync::Arc};

const RETRY_COUNT: usize = 3;

#[derive(Clone)]
pub struct FogViewRouterService<E: ViewEnclaveProxy> {
    enclave: E,
    shard_clients: Vec<Arc<FogViewApiClient>>,
    logger: Logger,
}

impl<E: ViewEnclaveProxy> FogViewRouterService<E> {
    /// Creates a new FogViewRouterService that can be used by a gRPC server to
    /// fulfill gRPC requests.
    ///
    /// TODO: Add a `view_store_clients` parameter of type FogApiClient, and
    /// perform view store authentication on each one.
    pub fn new(enclave: E, shard_clients: Vec<FogViewApiClient>, logger: Logger) -> Self {
        let shard_clients = shard_clients.into_iter().map(Arc::new).collect();
        Self {
            enclave,
            shard_clients,
            logger,
        }
    }
}

impl<E: ViewEnclaveProxy> FogViewRouterApi for FogViewRouterService<E> {
    fn request(
        &mut self,
        ctx: RpcContext,
        requests: RequestStream<FogViewRouterRequest>,
        responses: DuplexSink<FogViewRouterResponse>,
    ) {
        log::info!(self.logger, "Request received in request fn");
        let _timer = SVC_COUNTERS.req(&ctx);
        mc_common::logger::scoped_global_logger(&rpc_logger(&ctx, &self.logger), |logger| {
            let logger = logger.clone();
            // TODO: Confirm that we don't need to perform the authenticator logic. I think
            // we don't  because of streaming...
            let future = handle_requests(
                self.shard_clients.clone(),
                self.enclave.clone(),
                requests,
                responses,
                logger.clone(),
            )
            .map_err(move |err: grpcio::Error| log::error!(&logger, "failed to reply: {}", err))
            // TODO: Do stuff with the error
            .map(|_| ());

            ctx.spawn(future)
        });
    }
}

/// Handles a series of requests sent by the Fog Router client.
async fn handle_requests<E: ViewEnclaveProxy>(
    shard_clients: Vec<Arc<FogViewApiClient>>,
    enclave: E,
    mut requests: RequestStream<FogViewRouterRequest>,
    mut responses: DuplexSink<FogViewRouterResponse>,
    logger: Logger,
) -> Result<(), grpcio::Error> {
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
async fn handle_request<E: ViewEnclaveProxy>(
    mut request: FogViewRouterRequest,
    shard_clients: Vec<Arc<FogViewApiClient>>,
    enclave: E,
    logger: Logger,
) -> Result<FogViewRouterResponse, RpcStatus> {
    if request.has_auth() {
        return handle_auth_request(enclave, request.take_auth(), logger).await;
    } else if request.has_query() {
        return handle_query_request(request.take_query(), enclave, shard_clients, logger).await;
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
async fn handle_auth_request<E: ViewEnclaveProxy>(
    enclave: E,
    auth_message: attest::AuthMessage,
    logger: Logger,
) -> Result<FogViewRouterResponse, RpcStatus> {
    let (client_auth_response, _) = enclave.client_accept(auth_message.into()).map_err(|err| {
        router_server_err_to_rpc_status("Auth: e client accept", err.into(), logger)
    })?;

    let mut response = FogViewRouterResponse::new();
    response.mut_auth().set_data(client_auth_response.into());
    Ok(response)
}

/// Handles a client's query request.
async fn handle_query_request<E: ViewEnclaveProxy>(
    query: attest::Message,
    enclave: E,
    shard_clients: Vec<Arc<FogViewApiClient>>,
    logger: Logger,
) -> Result<FogViewRouterResponse, RpcStatus> {
    let mut query_responses: Vec<attest::Message> = Vec::with_capacity(shard_clients.len());
    let shard_clients = shard_clients.clone();
    // TODO: use retry crate?
    for _ in 0..RETRY_COUNT {
        let multi_view_store_query_request: MultiViewStoreQueryRequest = enclave
            .create_multi_view_store_query_data(query.clone().into())
            .map_err(|err| {
                router_server_err_to_rpc_status(
                    "Query: internal encryption error",
                    err.into(),
                    logger.clone(),
                )
            })?
            .into();
        let clients_and_responses: Vec<(Arc<FogViewApiClient>, MultiViewStoreQueryResponse)> =
            route_query(&multi_view_store_query_request, shard_clients.clone())
                .await
                .map_err(|err| {
                    router_server_err_to_rpc_status(
                        "Query: internal query routing error",
                        err,
                        logger.clone(),
                    )
                })?;

        let (shard_clients, pending_auth_requests, mut new_query_responses) =
            process_shard_responses(clients_and_responses, enclave.clone(), logger.clone())
                .map_err(|err| {
                    router_server_err_to_rpc_status(
                        "Query: internal query response processing",
                        err,
                        logger.clone(),
                    )
                })?;
        query_responses.append(&mut new_query_responses);

        try_join_all(pending_auth_requests).await.map_err(|err| {
            router_server_err_to_rpc_status(
                "Query: cannot authenticate with each Fog View Store:",
                err,
                logger.clone(),
            )
        })?;

        // We've successfully retrieved responses from each shard so we can break.
        if shard_clients.is_empty() {
            break;
        }
    }

    // TODO: Collate the query_responses into one response for the client. Make an
    // enclave  method for this.
    let response = FogViewRouterResponse::new();
    Ok(response)
}

fn process_shard_responses<E: ViewEnclaveProxy>(
    clients_and_responses: Vec<(Arc<FogViewApiClient>, MultiViewStoreQueryResponse)>,
    enclave: E,
    logger: Logger,
) -> Result<
    (
        Vec<Arc<FogViewApiClient>>,
        Vec<impl Future<Output = Result<(), RouterServerError>>>,
        Vec<attest::Message>,
    ),
    RouterServerError,
> {
    let mut shard_clients_for_retry = Vec::new();
    let mut pending_auth_requests = Vec::new();
    let mut new_query_responses = Vec::new();
    for (shard_client, mut response) in clients_and_responses {
        // We did not receive a query_response for this shard.Therefore, we need to:
        //  (a) retry the query
        //  (b) authenticate with the Fog View Store that returned the decryption_error
        if response.has_decryption_error() {
            shard_clients_for_retry.push(shard_client);
            let store_uri =
                FogViewUri::from_str(&response.get_decryption_error().fog_view_store_uri)?;
            let auth_future = authenticate_view_store(enclave.clone(), store_uri, logger.clone());
            pending_auth_requests.push(auth_future);
        } else {
            new_query_responses.push(response.take_query_response());
        }
    }

    Ok((
        shard_clients_for_retry,
        pending_auth_requests,
        new_query_responses,
    ))
}

/// Sends a client's query request to all of the Fog View shards.
async fn route_query(
    request: &MultiViewStoreQueryRequest,
    shard_clients: Vec<Arc<FogViewApiClient>>,
) -> Result<Vec<(Arc<FogViewApiClient>, MultiViewStoreQueryResponse)>, RouterServerError> {
    let mut responses = Vec::with_capacity(shard_clients.len());
    for shard_client in shard_clients {
        let response = query_shard(request, shard_client.clone());
        responses.push(response);
    }
    try_join_all(responses).await
}

/// Sends a client's query request to one of the Fog View shards.
async fn query_shard(
    request: &MultiViewStoreQueryRequest,
    shard_client: Arc<FogViewApiClient>,
) -> Result<(Arc<FogViewApiClient>, MultiViewStoreQueryResponse), RouterServerError> {
    let client_unary_receiver = shard_client.multi_view_store_query_async(request)?;
    let response = client_unary_receiver.await?;

    Ok((shard_client, response))
}

/// Authenticates a Fog View Store that has previously not been authenticated.
async fn authenticate_view_store<E: ViewEnclaveProxy>(
    enclave: E,
    view_store_url: FogViewUri,
    logger: Logger,
) -> Result<(), RouterServerError> {
    let view_store_id = ResponderId::from_str(&view_store_url.to_string())?;
    let client_auth_request = enclave.view_store_init(view_store_id.clone())?;
    let grpc_env = Arc::new(
        grpcio::EnvBuilder::new()
            .name_prefix("Main-RPC".to_string())
            .build(),
    );
    let view_store_client = FogViewApiClient::new(
        ChannelBuilder::default_channel_builder(grpc_env).connect_to_uri(&view_store_url, &logger),
    );

    let auth_unary_receiver = view_store_client.auth_async(&client_auth_request.into())?;
    let auth_response = auth_unary_receiver.await?;

    let result = enclave.view_store_connect(view_store_id, auth_response.into())?;

    Ok(result)
}
