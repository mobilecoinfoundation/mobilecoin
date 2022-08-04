use grpcio::{DuplexSink, RequestStream, RpcContext};
use mc_common::logger::{log, Logger};
use mc_fog_api::{
    ledger_grpc::{LedgerApi, self},
    ledger::{LedgerRequest, LedgerResponse}, 
};
use mc_fog_ledger_enclave::LedgerEnclaveProxy;
use mc_util_grpc::rpc_logger;
use mc_util_metrics::SVC_COUNTERS;

#[allow(dead_code)] // FIXME
#[derive(Clone)]
pub struct LedgerRouterService<E>
where
    E: LedgerEnclaveProxy,
{
    enclave: E,
    shards: Vec<ledger_grpc::LedgerStoreApiClient>,
    logger: Logger,
}

impl<E: LedgerEnclaveProxy> LedgerRouterService<E> {
    /// Creates a new LedgerRouterService that can be used by a gRPC server to
    /// fulfill gRPC requests.
    #[allow(dead_code)] // FIXME
    pub fn new(enclave: E, shards: Vec<ledger_grpc::LedgerStoreApiClient>, logger: Logger) -> Self {
        Self {
            enclave,
            shards,
            logger,
        }
    }
}

impl<E> LedgerApi for LedgerRouterService<E>
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
        mc_common::logger::scoped_global_logger(&rpc_logger(&ctx, &self.logger), |_logger| {
            todo!("Streaming GRPC Ledger API not yet implemented.");
        });
    }
}

/* 
        log::info!(self.logger, "Request received in request fn");
        let _timer = SVC_COUNTERS.req(&ctx);
        mc_common::logger::scoped_global_logger(&rpc_logger(&ctx, &self.logger), |logger| {
            let logger = logger.clone();
            // TODO: Confirm that we don't need to perform the authenticator logic. I think
            // we don't  because of streaming...
            let future = router_request_handler::handle_requests(
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
        }); */