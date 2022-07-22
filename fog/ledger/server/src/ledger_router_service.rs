use grpcio::{DuplexSink, RequestStream, RpcContext};
use mc_common::logger::{log, Logger};
use mc_fog_api::{
    ledger_grpc::LedgerApi,
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
    // Will need some kind of shard_clients vec of handles to stores. 
    logger: Logger,
}

impl<E: LedgerEnclaveProxy> LedgerRouterService<E> {
    /// Creates a new LedgerRouterService that can be used by a gRPC server to
    /// fulfill gRPC requests.
    /// TODO: Shards / router functionality. 
    #[allow(dead_code)] // FIXME
    pub fn new(enclave: E, logger: Logger) -> Self {
        Self {
            enclave,
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