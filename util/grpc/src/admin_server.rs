//! A standardized admin GRPC server

use crate::{
    AdminService, BuildInfoService, ConnectionUriGrpcioServer, GetConfigJsonFn, HealthService,
};
use grpcio::{Environment, ShutdownFuture};
use mc_common::logger::{log, Logger};
use mc_util_uri::{AdminUri, ConnectionUri};
use std::sync::Arc;

pub struct AdminServer {
    server: grpcio::Server,
}

impl AdminServer {
    pub fn start(
        env: Option<Arc<Environment>>,
        admin_listen_uri: &AdminUri,
        name: String,
        id: String,
        get_config_json: Option<GetConfigJsonFn>,
        logger: Logger,
    ) -> Result<Self, grpcio::Error> {
        log::info!(
            logger,
            "Starting admin rpc server on {}...",
            admin_listen_uri.addr(),
        );

        // Create env if needed, otherwise use supplied env.
        let env = env.unwrap_or_else(|| {
            Arc::new(
                grpcio::EnvBuilder::new()
                    .name_prefix("Admin-RPC".to_string())
                    .build(),
            )
        });

        // Initialize services.
        let admin_service =
            AdminService::new(name, id, get_config_json, logger.clone()).into_service();
        let health_service = HealthService::new(None, logger.clone()).into_service();
        let build_info_service = BuildInfoService::new(logger.clone()).into_service();

        let server_builder = grpcio::ServerBuilder::new(env)
            .register_service(admin_service)
            .register_service(health_service)
            .register_service(build_info_service)
            .bind_using_uri(admin_listen_uri, logger.clone());

        let mut server = server_builder.build()?;
        server.start();

        for (host, port) in server.bind_addrs() {
            log::info!(logger, "Admin GRPC API listening on {}:{}", host, port);
        }

        Ok(Self { server })
    }

    pub fn shutdown(&mut self) -> ShutdownFuture {
        self.server.shutdown()
    }
}
