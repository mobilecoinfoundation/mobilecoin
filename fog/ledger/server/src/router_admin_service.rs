// Copyright (c) 2018-2022 The MobileCoin Foundation

use crate::SVC_COUNTERS;
use grpcio::{ChannelBuilder, RpcContext, RpcStatus, UnarySink};
use itertools::Itertools;
use mc_common::logger::{log, Logger};
use mc_fog_api::{
    fog_common::AddShardRequest,
    ledger_grpc::{KeyImageStoreApiClient, LedgerRouterAdminApi},
};
use mc_fog_uri::KeyImageStoreUri;
use mc_util_grpc::{
    rpc_invalid_arg_error, rpc_logger, rpc_precondition_error, send_result,
    ConnectionUriGrpcioChannel, Empty,
};
use std::{
    collections::HashMap,
    str::FromStr,
    sync::{Arc, RwLock},
};

#[derive(Clone)]
pub struct LedgerRouterAdminService {
    shard_clients: Arc<RwLock<HashMap<KeyImageStoreUri, Arc<KeyImageStoreApiClient>>>>,
    logger: Logger,
}

impl LedgerRouterAdminService {
    #[allow(dead_code)]
    pub fn new(
        shard_clients: Arc<RwLock<HashMap<KeyImageStoreUri, Arc<KeyImageStoreApiClient>>>>,
        logger: Logger,
    ) -> Self {
        Self {
            shard_clients,
            logger,
        }
    }

    fn add_shard_impl(&mut self, shard_uri: &str, logger: &Logger) -> Result<Empty, RpcStatus> {
        let key_image_store_uri = KeyImageStoreUri::from_str(shard_uri).map_err(|_| {
            rpc_invalid_arg_error(
                "add_shard",
                format!("Shard uri string {shard_uri} is invalid"),
                logger,
            )
        })?;
        let mut shard_clients = self.shard_clients.write().expect("RwLock Poisoned");
        if shard_clients.keys().contains(&key_image_store_uri) {
            let error = rpc_precondition_error(
                "add_shard",
                format!("Shard uri {shard_uri} already exists in the shard list"),
                logger,
            );
            return Err(error);
        }
        let grpc_env = Arc::new(
            grpcio::EnvBuilder::new()
                .name_prefix("add-shard".to_string())
                .build(),
        );
        let key_image_store_client = KeyImageStoreApiClient::new(
            ChannelBuilder::default_channel_builder(grpc_env)
                .keepalive_permit_without_calls(false)
                .connect_to_uri(&key_image_store_uri, logger),
        );
        shard_clients.insert(key_image_store_uri, Arc::new(key_image_store_client));

        Ok(Empty::new())
    }
}

impl LedgerRouterAdminApi for LedgerRouterAdminService {
    fn add_shard(&mut self, ctx: RpcContext, request: AddShardRequest, sink: UnarySink<Empty>) {
        log::info!(self.logger, "Request received in add_shard fn");
        let _timer = SVC_COUNTERS.req(&ctx);
        mc_common::logger::scoped_global_logger(&rpc_logger(&ctx, &self.logger), |logger| {
            send_result(
                ctx,
                sink,
                self.add_shard_impl(request.get_shard_uri(), logger),
                logger,
            );
        });
    }
}
