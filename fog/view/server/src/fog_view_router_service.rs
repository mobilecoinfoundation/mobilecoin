// Copyright (c) 2018-2022 The MobileCoin Foundation

use crate::{fog_view_router_server::Shard, router_request_handler};
use futures::{executor::block_on, FutureExt, TryFutureExt};
use grpcio::{DuplexSink, RequestStream, RpcContext, UnarySink};
use mc_attest_api::attest;
use mc_common::logger::{log, Logger};
use mc_fog_api::{
    view::{FogViewRouterRequest, FogViewRouterResponse},
    view_grpc::{FogViewApi, FogViewRouterApi},
};
use mc_fog_view_enclave_api::ViewEnclaveProxy;
use mc_util_grpc::{check_request_chain_id, rpc_logger, send_result, Authenticator};
use mc_util_metrics::{ServiceMetrics, SVC_COUNTERS};
use mc_util_telemetry::tracer;
use std::sync::{Arc, RwLock};

#[derive(Clone)]
pub struct FogViewRouterService<E>
where
    E: ViewEnclaveProxy,
{
    enclave: E,
    shards: Arc<RwLock<Vec<Shard>>>,
    chain_id: String,
    /// GRPC request authenticator.
    authenticator: Arc<dyn Authenticator + Send + Sync>,
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
        shards: Arc<RwLock<Vec<Shard>>>,
        chain_id: String,
        authenticator: Arc<dyn Authenticator + Send + Sync>,
        logger: Logger,
    ) -> Self {
        Self {
            enclave,
            shards,
            chain_id,
            authenticator,
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
        mc_common::logger::scoped_global_logger(&rpc_logger(&ctx, &self.logger), |logger| {
            let logger = logger.clone();
            // TODO: Confirm that we don't need to perform the authenticator logic. I think
            // we don't  because of streaming...
            let shards = self.shards.read().expect("RwLock poisoned");
            let method_name = ServiceMetrics::get_method_name(&ctx);
            let future = router_request_handler::handle_requests(
                method_name,
                shards.clone(),
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
            if let Err(err) = check_request_chain_id(&self.chain_id, &ctx) {
                return send_result(ctx, sink, Err(err), logger);
            }

            if let Err(err) = self.authenticator.authenticate_rpc(&ctx) {
                return send_result(ctx, sink, err.into(), logger);
            }
            let result = router_request_handler::handle_auth_request(
                self.enclave.clone(),
                request,
                self.logger.clone(),
            )
            .map(|mut response| response.take_auth());

            send_result(ctx, sink, result, logger);
        })
    }

    fn query(
        &mut self,
        ctx: RpcContext,
        request: attest::Message,
        sink: UnarySink<attest::Message>,
    ) {
        mc_common::logger::scoped_global_logger(&rpc_logger(&ctx, &self.logger), |logger| {
            if let Err(err) = check_request_chain_id(&self.chain_id, &ctx) {
                return send_result(ctx, sink, Err(err), logger);
            }

            if let Err(err) = self.authenticator.authenticate_rpc(&ctx) {
                return send_result(ctx, sink, err.into(), logger);
            }

            // This will block the async API. We should use some sort of differentiator...
            let shards = self.shards.read().expect("RwLock poisoned");
            let tracer = tracer!();
            let result = block_on(router_request_handler::handle_query_request(
                request,
                self.enclave.clone(),
                shards.clone(),
                self.logger.clone(),
                &tracer,
            ))
            .map(|mut response| response.take_query());

            send_result(ctx, sink, result, logger)
        })
    }
}
