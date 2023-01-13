// Copyright (c) 2018-2022 The MobileCoin Foundation

use crate::{
    fog_view_router_server::Shard,
    sharding_strategy::{EpochShardingStrategy, ShardingStrategy},
    SVC_COUNTERS,
};
use grpcio::{ChannelBuilder, RpcContext, RpcStatus, UnarySink};
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
use std::{
    str::FromStr,
    sync::{Arc, RwLock},
};

#[derive(Clone)]
pub struct FogViewRouterAdminService {
    shards: Arc<RwLock<Vec<Shard>>>,
    logger: Logger,
}

impl FogViewRouterAdminService {
    pub fn new(shards: Arc<RwLock<Vec<Shard>>>, logger: Logger) -> Self {
        Self { shards, logger }
    }

    fn add_shard_impl(&mut self, shard_uri: &str, logger: &Logger) -> Result<Empty, RpcStatus> {
        let view_store_uri = FogViewStoreUri::from_str(shard_uri).map_err(|_| {
            rpc_invalid_arg_error(
                "add_shard",
                format!("Shard uri string {} is invalid", shard_uri),
                logger,
            )
        })?;
        let mut shards = self.shards.write().expect("RwLock Poisoned");
        if shards
            .iter()
            .any(|shard| shard.uri.clone() == view_store_uri)
        {
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
        let block_range = EpochShardingStrategy::default().get_block_range();
        let shard = Shard::new(view_store_uri, Arc::new(view_store_client), block_range);
        shards.push(shard);

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
