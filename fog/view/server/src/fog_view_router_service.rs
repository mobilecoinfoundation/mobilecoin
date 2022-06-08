// Copyright (c) 2018-2022 The MobileCoin Foundation

use futures::{future::try_join_all, FutureExt, SinkExt, TryFutureExt, TryStreamExt};
use grpcio::{DuplexSink, RequestStream, RpcContext, WriteFlags};
use mc_common::logger::{log, Logger};
use mc_fog_api::{
    view::{FogViewRouterRequest, FogViewRouterResponse},
    view_grpc::FogViewRouterApi,
};
use mc_fog_uri::FogViewStoreUri;
use mc_fog_view_enclave_api::ViewEnclaveProxy;
use mc_util_grpc::{rpc_logger, rpc_permissions_error};
use mc_util_metrics::SVC_COUNTERS;
use std::sync::Arc;

#[derive(Clone)]
pub struct FogViewRouterService<E: ViewEnclaveProxy> {
    enclave: E,
    shards: Vec<Arc<FogViewStoreUri>>,
    logger: Logger,
}

impl<E: ViewEnclaveProxy> FogViewRouterService<E> {
    /// Creates a new FogViewRouterService that can be used by a gRPC server to
    /// fulfill gRPC requests.
    pub fn new(enclave: E, shards: Vec<FogViewStoreUri>, logger: Logger) -> Self {
        let shards = shards.into_iter().map(Arc::new).collect();
        Self {
            enclave,
            shards,
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
            let future = handle_request(
                self.shards.clone(),
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

/// Receives a client's request and performs either authentication or a query.
async fn handle_request<E: ViewEnclaveProxy>(
    shards: Vec<Arc<FogViewStoreUri>>,
    enclave: E,
    mut requests: RequestStream<FogViewRouterRequest>,
    mut responses: DuplexSink<FogViewRouterResponse>,
    logger: Logger,
) -> Result<(), grpcio::Error> {
    while let Some(mut request) = requests.try_next().await? {
        if request.has_auth() {
            match enclave.client_accept(request.take_auth().into()) {
                Ok((enclave_response, _)) => {
                    let mut response = FogViewRouterResponse::new();
                    response.mut_auth().set_data(enclave_response.into());
                    responses
                        .send((response.clone(), WriteFlags::default()))
                        .await?;
                }
                Err(client_error) => {
                    log::debug!(
                        &logger,
                        "ViewEnclaveApi::client_accept failed: {}",
                        client_error
                    );
                    let rpc_permissions_error = rpc_permissions_error(
                        "client_auth",
                        format!("Permission denied: {:?}", client_error),
                        &logger,
                    );
                    return responses.fail(rpc_permissions_error).await;
                }
            }
        } else if request.has_query() {
            log::info!(logger, "Request has query");
            let _result = route_query(shards.clone(), logger.clone()).await;

            let response = FogViewRouterResponse::new();
            responses
                .send((response.clone(), WriteFlags::default()))
                .await?;
        } else {
            // TODO: Throw some sort of error though not sure
            //  that's necessary.
        }
    }

    responses.close().await?;
    Ok(())
}

// TODO: This method will be responsible for contacting each shard, passing
// along a  MultiViewStoreQuery message. It will eventually return a Vec of
// encrypted QueryResponses that  the caller of this method will transform into
// one FogViewRouterResponse to return to the client.
async fn route_query(
    shards: Vec<Arc<FogViewStoreUri>>,
    logger: Logger,
) -> Result<Vec<i32>, String> {
    let mut futures = Vec::new();
    for (i, shard) in shards.iter().enumerate() {
        let future = contact_shard(i, shard.clone(), logger.clone());
        futures.push(future);
    }

    try_join_all(futures).await
}

// TODO: Pass along the MultiViewStoreQuery to the individual shard.
//  This method will eventually return an encrypted QueryResponse that the
//  router will decrypt and collate with all of the other shards' responses.
async fn contact_shard(
    index: usize,
    shard: Arc<FogViewStoreUri>,
    logger: Logger,
) -> Result<i32, String> {
    log::info!(logger, "Contacting shard {} at index {}", shard, index);

    Ok(0)
}
