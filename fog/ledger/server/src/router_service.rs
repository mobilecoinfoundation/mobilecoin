// Copyright (c) 2018-2022 The MobileCoin Foundation

use crate::{
    router_handlers::{self, handle_auth_request, handle_query_request},
    SVC_COUNTERS,
};
use futures::{FutureExt, TryFutureExt};
use grpcio::{DuplexSink, RequestStream, RpcContext, UnarySink};
use mc_attest_api::attest::{AuthMessage, Message};
use mc_common::logger::{log, Logger};
use mc_fog_api::fog_ledger::{
    self, ledger_response, FogKeyImageApi, KeyImageStoreApiClient, LedgerApi, LedgerRequest,
    LedgerResponse,
};
use mc_fog_ledger_enclave::LedgerEnclaveProxy;
use mc_fog_uri::KeyImageStoreUri;
use mc_util_grpc::{rpc_internal_error, rpc_logger};
use mc_util_metrics::ServiceMetrics;
use mc_util_telemetry::tracer;

use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

#[derive(Clone)]
pub struct LedgerRouterService<E>
where
    E: LedgerEnclaveProxy,
{
    enclave: E,
    shards: Arc<RwLock<HashMap<KeyImageStoreUri, Arc<fog_ledger::KeyImageStoreApiClient>>>>,
    query_retries: usize,
    logger: Logger,
}

impl<E: LedgerEnclaveProxy> LedgerRouterService<E> {
    /// Creates a new LedgerRouterService that can be used by a gRPC server to
    /// fulfill gRPC requests.
    pub fn new(
        enclave: E,
        shards: Arc<RwLock<HashMap<KeyImageStoreUri, Arc<fog_ledger::KeyImageStoreApiClient>>>>,
        query_retries: usize,
        logger: Logger,
    ) -> Self {
        Self {
            enclave,
            shards,
            query_retries,
            logger,
        }
    }
}

impl<E> LedgerApi for LedgerRouterService<E>
where
    E: LedgerEnclaveProxy,
{
    fn request(
        &mut self,
        ctx: RpcContext,
        requests: RequestStream<LedgerRequest>,
        responses: DuplexSink<LedgerResponse>,
    ) {
        let _timer = SVC_COUNTERS.req(&ctx);
        mc_common::logger::scoped_global_logger(&rpc_logger(&ctx, &self.logger), |logger| {
            log::warn!(
                self.logger,
                "Streaming GRPC Ledger API only partially implemented."
            );
            let logger = logger.clone();

            let shards = self.shards.read().expect("RwLock poisoned");
            let method_name = ServiceMetrics::get_method_name(&ctx);

            let future = router_handlers::handle_requests(
                method_name,
                shards.values().cloned().collect(),
                self.enclave.clone(),
                requests,
                responses,
                self.query_retries,
                logger.clone(),
            )
            .map_err(move |err| log::error!(&logger, "failed to reply: {}", err))
            // TODO: Do more with the error than just push it to the log.
            .map(|_| ());

            ctx.spawn(future)
        });
    }
}

/// Used for the implementation of FogKeyImageApi::check_key_images(),
/// the legacy unary key-image API, for LedgerRouterService.
async fn unary_check_key_image_impl<E>(
    request: Message,
    query_retries: usize,
    enclave: E,
    sink: UnarySink<Message>,
    shard_clients: Vec<Arc<KeyImageStoreApiClient>>,
    scope_logger: Logger,
) -> Result<(), grpcio::Error>
where
    E: LedgerEnclaveProxy,
{
    let tracer = tracer!();
    let result = handle_query_request(
        request,
        enclave,
        shard_clients,
        query_retries,
        scope_logger.clone(),
        &tracer,
    )
    .await;

    match result {
        Ok(response) => match response.response_data {
            Some(ledger_response::ResponseData::CheckKeyImageResponse(key_images)) => {
                sink.success(key_images).await
            }
            _ => {
                let error = rpc_internal_error(
                    "Invalid LedgerRequest response",
                    "Cannot provide a check key image response to the client's key image request."
                        .to_string(),
                    &scope_logger,
                );
                sink.fail(error).await
            }
        },
        Err(rpc_status) => sink.fail(rpc_status).await,
    }
}

// This API is the unary key-image-specific equivalent of LedgerApi.
impl<E: LedgerEnclaveProxy> FogKeyImageApi for LedgerRouterService<E> {
    fn check_key_images(&mut self, ctx: RpcContext, request: Message, sink: UnarySink<Message>) {
        let _timer = SVC_COUNTERS.req(&ctx);
        mc_common::logger::scoped_global_logger(&rpc_logger(&ctx, &self.logger), |logger| {
            let logger = logger.clone();
            let shards = self.shards.read().expect("RwLock poisoned");

            let future = unary_check_key_image_impl(
                request,
                self.query_retries,
                self.enclave.clone(),
                sink,
                shards.values().cloned().collect(),
                logger.clone(),
            )
            .map_err(move |err| log::error!(&logger, "failed to reply: {}", err))
            // TODO: Do more with the error than just push it to the log.
            .map(|_| ());

            ctx.spawn(future);
        })
    }

    fn auth(&mut self, ctx: RpcContext, request: AuthMessage, sink: UnarySink<AuthMessage>) {
        let _timer = SVC_COUNTERS.req(&ctx);
        mc_common::logger::scoped_global_logger(&rpc_logger(&ctx, &self.logger), |logger| {
            let logger = logger.clone();
            let result = handle_auth_request(self.enclave.clone(), request, logger.clone());
            let future = match result {
                Ok(response) => match response.response_data {
                    Some(ledger_response::ResponseData::Auth(auth)) => sink.success(auth),
                    _ => {
                        let error = rpc_internal_error(
                            "Invalid LedgerRequest response",
                            "Response to client's auth request did not contain an auth response."
                                .to_string(),
                            &logger,
                        );
                        sink.fail(error)
                    }
                },
                Err(rpc_status) => sink.fail(rpc_status),
            }
            .map_err(move |err| log::error!(&logger, "failed to reply: {}", err))
            .map(|_| ());
            ctx.spawn(future);
        });
    }
}
