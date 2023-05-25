//! A standardized admin GRPC server

use crate::{
    AdminService, BuildInfoService, ConnectionUriGrpcioServer, GetConfigJsonFn, HealthService,
};
use futures::executor::block_on;
use grpcio::{Environment, Service, ShutdownFuture};
use mc_common::logger::{log, Logger};
use mc_util_uri::{AdminUri, ConnectionUri};
use std::sync::Arc;

/// The admin server is a grpc server that serves the admin endpoint
pub struct AdminServer {
    server: grpcio::Server,
}

impl AdminServer {
    /// Initilaizes and starts the admin server
    pub fn start(
        env: Option<Arc<Environment>>,
        admin_listen_uri: &AdminUri,
        name: String,
        id: String,
        get_config_json: Option<GetConfigJsonFn>,
        extra_services: Vec<Service>,
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

        let mut server_builder = grpcio::ServerBuilder::new(env)
            .register_service(admin_service)
            .register_service(health_service)
            .register_service(build_info_service);
        for extra_service in extra_services {
            server_builder = server_builder.register_service(extra_service);
        }

        let mut server = server_builder.build_using_uri(admin_listen_uri, logger.clone())?;
        server.start();

        log::info!(
            logger,
            "Admin GRPC API listening on {}",
            admin_listen_uri.addr()
        );

        Ok(Self { server })
    }

    /// Shuts down the admin server
    pub fn shutdown(&mut self) -> ShutdownFuture {
        self.server.shutdown()
    }
}

impl Drop for AdminServer {
    fn drop(&mut self) {
        block_on(self.shutdown()).expect("Could not shutdown admin server")
    }
}
