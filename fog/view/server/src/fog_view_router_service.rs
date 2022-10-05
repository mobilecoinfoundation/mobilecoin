// Copyright (c) 2018-2022 The MobileCoin Foundation

use crate::router_request_handler;
use futures::{FutureExt, TryFutureExt};
use grpcio::{DuplexSink, RequestStream, RpcContext};
use mc_common::logger::{log, Logger};
use mc_fog_api::{
    view::{FogViewRouterRequest, FogViewRouterResponse},
    view_grpc::{FogViewRouterApi, FogViewStoreApiClient},
};
use mc_fog_uri::FogViewStoreUri;
use mc_fog_view_enclave_api::ViewEnclaveProxy;
use mc_util_grpc::rpc_logger;
use mc_util_metrics::SVC_COUNTERS;
use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

#[derive(Clone)]
pub struct FogViewRouterService<E>
where
    E: ViewEnclaveProxy,
{
    enclave: E,
    shard_clients: Arc<RwLock<HashMap<FogViewStoreUri, Arc<FogViewStoreApiClient>>>>,
    logger: Logger,
}

impl<E: ViewEnclaveProxy> FogViewRouterService<E> {
    /// Creates a new FogViewRouterService that can be used by a gRPC server to
    /// fulfill gRPC requests.
    ///
    /// TODO: Add a `view_store_clients` parameter of type FogApiClient, and
    /// perform view store authentication on each one.
    pub fn new(
        enclave: E,
        shard_clients: Arc<RwLock<HashMap<FogViewStoreUri, Arc<FogViewStoreApiClient>>>>,
        logger: Logger,
    ) -> Self {
        Self {
            enclave,
            shard_clients,
            logger,
        }
    }
}

impl<E> FogViewRouterApi for FogViewRouterService<E>
where
    E: ViewEnclaveProxy,
{
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
            let shard_clients = self.shard_clients.read().expect("RwLock poisoned");
            let future = router_request_handler::handle_requests(
                shard_clients.values().cloned().collect(),
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
