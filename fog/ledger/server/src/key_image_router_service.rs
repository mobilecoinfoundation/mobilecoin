// Copyright (c) 2018-2022 The MobileCoin Foundation

use std::sync::Arc;

use futures::{FutureExt, TryFutureExt};
use grpcio::{DuplexSink, RequestStream, RpcContext};
use mc_common::logger::{log, Logger};
use mc_fog_api::{
    ledger::{LedgerRequest, LedgerResponse},
    ledger_grpc::{self, LedgerApi},
};
use mc_fog_ledger_enclave::LedgerEnclaveProxy;
use mc_util_grpc::rpc_logger;
use mc_util_metrics::SVC_COUNTERS;

use crate::router_handlers;

#[allow(dead_code)] // FIXME
#[derive(Clone)]
pub struct KeyImageRouterService<E>
where
    E: LedgerEnclaveProxy,
{
    enclave: E,
    shards: Vec<Arc<ledger_grpc::KeyImageStoreApiClient>>,
    logger: Logger,
}

impl<E: LedgerEnclaveProxy> KeyImageRouterService<E> {
    /// Creates a new LedgerRouterService that can be used by a gRPC server to
    /// fulfill gRPC requests.
    #[allow(dead_code)] // FIXME
    pub fn new(
        enclave: E,
        shards: Vec<ledger_grpc::KeyImageStoreApiClient>,
        logger: Logger,
    ) -> Self {
        let shards = shards.into_iter().map(Arc::new).collect();
        Self {
            enclave,
            shards,
            logger,
        }
    }
}

impl<E> LedgerApi for KeyImageRouterService<E>
where
    E: LedgerEnclaveProxy,
{
    #[allow(unused_variables)] // FIXME
    fn request(
        &mut self,
        ctx: RpcContext,
        requests: RequestStream<LedgerRequest>,
        responses: DuplexSink<LedgerResponse>,
    ) {
        log::info!(self.logger, "Request received in request fn");
        let _timer = SVC_COUNTERS.req(&ctx);
        mc_common::logger::scoped_global_logger(&rpc_logger(&ctx, &self.logger), |logger| {
            log::warn!(
                self.logger,
                "Streaming GRPC Ledger API only partially implemented."
            );

            let logger = logger.clone();

            let future = router_handlers::handle_requests(
                self.shards.clone(),
                self.enclave.clone(),
                requests,
                responses,
                logger.clone(),
            )
            .map_err(move |err: grpcio::Error| log::error!(&logger, "failed to reply: {}", err))
            // TODO: Do more with the error than just push it to the log.
            .map(|_| ());

            ctx.spawn(future)
        });
    }
}
