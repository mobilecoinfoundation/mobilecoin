// Copyright (c) 2018-2022 The MobileCoin Foundation

use crate::router_request_handler;
use futures::{executor::block_on, FutureExt, TryFutureExt};
use grpcio::{DuplexSink, RequestStream, RpcContext, UnarySink};
use mc_attest_api::attest;
use mc_common::logger::{log, Logger};
use mc_fog_api::{
    view::{FogViewRouterRequest, FogViewRouterResponse},
    view_grpc::{FogViewApi, FogViewRouterApi, FogViewStoreApiClient},
};
use mc_fog_uri::FogViewStoreUri;
use mc_fog_view_enclave_api::ViewEnclaveProxy;
use mc_util_grpc::{
    check_request_chain_id, rpc_internal_error, rpc_logger, send_result, Authenticator,
};
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
    unary_api_data: Option<UnaryApiData>,
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
        unary_api_data: Option<UnaryApiData>,
        logger: Logger,
    ) -> Self {
        Self {
            enclave,
            shard_clients,
            unary_api_data,
            logger,
        }
    }
}

#[derive(Clone)]
pub(crate) struct UnaryApiData {
    ///
    pub(crate) chain_id: String,
    /// GRPC request authenticator.
    pub(crate) authenticator: Arc<dyn Authenticator + Send + Sync>,
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

impl<E> FogViewApi for FogViewRouterService<E>
where
    E: ViewEnclaveProxy,
{
    fn auth(
        &mut self,
        ctx: RpcContext,
        request: attest::AuthMessage,
        sink: UnarySink<attest::AuthMessage>,
    ) {
        let _timer = SVC_COUNTERS.req(&ctx);
        mc_common::logger::scoped_global_logger(&rpc_logger(&ctx, &self.logger), |logger| {
            match &self.unary_api_data {
                None => {
                    let rpc_internal_error = rpc_internal_error(
                         "unary fog view router",
                         "Internal error: this fog view router instance is not configured to accept unary requests"
                             .to_string(),
                         logger,
                     );
                    send_result(ctx, sink, Err(rpc_internal_error), logger)
                }
                Some(unary_api_data) => {
                    if let Err(err) = check_request_chain_id(&unary_api_data.chain_id, &ctx) {
                        return send_result(ctx, sink, Err(err), logger);
                    }

                    if let Err(err) = unary_api_data.authenticator.authenticate_rpc(&ctx) {
                        return send_result(ctx, sink, err.into(), logger);
                    }
                    let result = router_request_handler::handle_auth_request(
                        self.enclave.clone(),
                        request,
                        self.logger.clone(),
                    )
                    .map(|mut response| response.take_auth());

                    send_result(ctx, sink, result, logger);
                }
            }
        });
    }

    fn query(
        &mut self,
        ctx: RpcContext,
        request: attest::Message,
        sink: UnarySink<attest::Message>,
    ) {
        mc_common::logger::scoped_global_logger(&rpc_logger(&ctx, &self.logger), |logger| {
            match &self.unary_api_data {
                None => {
                    let rpc_internal_error= rpc_internal_error("unary query", "Internal error: this Fog View Router instance is not configured to serve unary requests.", &logger);
                    return send_result(ctx, sink, Err(rpc_internal_error), logger);
                }
                Some(unary_api_data) => {
                    if let Err(err) = check_request_chain_id(&unary_api_data.chain_id, &ctx) {
                        return send_result(ctx, sink, Err(err), logger);
                    }
                    if let Err(err) = unary_api_data.authenticator.authenticate_rpc(&ctx) {
                        return send_result(ctx, sink, err.into(), logger);
                    }
                    let shard_clients = self.shard_clients.read().expect("RwLock poisoned");
                    let result = block_on(router_request_handler::handle_query_request(
                        request,
                        self.enclave.clone(),
                        shard_clients.values().cloned().collect(),
                        self.logger.clone(),
                    ))
                    .map(|mut response| response.take_query());

                    send_result(ctx, sink, result, logger)
                }
            };
        })
    }
}
