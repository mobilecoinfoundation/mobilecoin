// Copyright (c) 2018-2022 The MobileCoin Foundation

use crate::{router_handlers, SVC_COUNTERS};
use futures::{FutureExt, TryFutureExt};
use grpcio::{DuplexSink, RequestStream, RpcContext};
use mc_common::logger::{log, Logger};
use mc_fog_api::{
    ledger::{LedgerRequest, LedgerResponse},
    ledger_grpc::{self, LedgerApi},
};
use mc_fog_ledger_enclave::LedgerEnclaveProxy;
use mc_fog_uri::KeyImageStoreUri;
use mc_util_grpc::rpc_logger;
use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

#[derive(Clone)]
pub struct KeyImageRouterService<E>
where
    E: LedgerEnclaveProxy,
{
    enclave: E,
    shards: Arc<RwLock<HashMap<KeyImageStoreUri, Arc<ledger_grpc::KeyImageStoreApiClient>>>>,
    query_retries: usize,
    logger: Logger,
}

impl<E: LedgerEnclaveProxy> KeyImageRouterService<E> {
    /// Creates a new LedgerRouterService that can be used by a gRPC server to
    /// fulfill gRPC requests.
    pub fn new(
        enclave: E,
        shards: Arc<RwLock<HashMap<KeyImageStoreUri, Arc<ledger_grpc::KeyImageStoreApiClient>>>>,
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

impl<E> LedgerApi for KeyImageRouterService<E>
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
            let future = router_handlers::handle_requests(
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
