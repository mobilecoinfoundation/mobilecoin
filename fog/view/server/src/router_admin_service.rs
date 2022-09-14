// Copyright (c) 2018-2022 The MobileCoin Foundation

use grpcio::{ChannelBuilder, RpcContext, RpcStatus, UnarySink};
use itertools::Itertools;
use mc_common::logger::{log, Logger};
use mc_fog_api::{
    view::AddShardRequest,
    view_grpc::{FogViewRouterAdminApi, FogViewStoreApiClient},
};
use mc_fog_uri::FogViewStoreUri;
use mc_util_grpc::{
    rpc_invalid_arg_error, rpc_logger, rpc_precondition_error, send_result,
    ConnectionUriGrpcioChannel, Empty,
};
use mc_util_metrics::SVC_COUNTERS;
use std::{
    collections::HashMap,
    str::FromStr,
    sync::{Arc, RwLock},
};

#[derive(Clone)]
pub struct FogViewRouterAdminService {
    shard_clients: Arc<RwLock<HashMap<FogViewStoreUri, Arc<FogViewStoreApiClient>>>>,
    logger: Logger,
}

impl FogViewRouterAdminService {
    pub fn new(
        shard_clients: Arc<RwLock<HashMap<FogViewStoreUri, Arc<FogViewStoreApiClient>>>>,
        logger: Logger,
    ) -> Self {
        Self {
            shard_clients,
            logger,
        }
    }

    fn add_shard_impl(&mut self, shard_uri: &str, logger: &Logger) -> Result<Empty, RpcStatus> {
        let view_store_uri = FogViewStoreUri::from_str(shard_uri).map_err(|_| {
            rpc_invalid_arg_error(
                "add_shard",
                format!("Shard uri string {} is invalid", shard_uri),
                logger,
            )
        })?;
        let mut shard_clients = self.shard_clients.write().expect("RwLock Poisoned");
        if shard_clients.keys().contains(&view_store_uri) {
            let error = rpc_precondition_error(
                "add_shard",
                format!("Shard uri {} already exists in the shard list", shard_uri),
                logger,
            );
            return Err(error);
        }
        let grpc_env = Arc::new(
            grpcio::EnvBuilder::new()
                .name_prefix("add-shard".to_string())
                .build(),
        );
        let view_store_client = FogViewStoreApiClient::new(
            ChannelBuilder::default_channel_builder(grpc_env)
                .connect_to_uri(&view_store_uri, logger),
        );
        shard_clients.insert(view_store_uri, Arc::new(view_store_client));

        Ok(Empty::new())
    }
}

impl FogViewRouterAdminApi for FogViewRouterAdminService {
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
