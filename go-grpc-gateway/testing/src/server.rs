use crate::service::Service;
use futures::executor::block_on;
use grpcio::{Server as GrpcioServer, ServerBuilder};
use mc_common::logger::{log, Logger};
use mc_fog_report_api::report_grpc;
use mc_util_grpc::{ConnectionUriGrpcioServer, HealthService};
use mc_util_uri::{ConnectionUri, FogUri};
use std::sync::Arc;

/// The application server
pub struct Server {
    server: GrpcioServer,
    logger: Logger,
}

impl Server {
    /// Instantiate a server, ready to listen at the given URI
    pub fn new(client_listen_uri: &FogUri, chain_id: String, logger: Logger) -> Self {
        let env = Arc::new(
            grpcio::EnvBuilder::new()
                .name_prefix("StubServer-RPC".to_string())
                .build(),
        );

        let service = Service::new(chain_id, logger.clone());

        let report_service = report_grpc::create_report_api(service);
        log::debug!(logger, "Constructed Report GRPC Service");

        // Health check service
        let health_service = HealthService::new(None, logger.clone()).into_service();

        // Package service into grpc server
        log::info!(
            logger,
            "Starting stub server on {}",
            client_listen_uri.addr(),
        );
        let server_builder = ServerBuilder::new(env)
            .register_service(report_service)
            .register_service(health_service)
            .bind_using_uri(client_listen_uri, logger.clone());

        let server = server_builder.build().unwrap();

        Self { server, logger }
    }

    /// Start the server.
    pub fn start(&mut self) {
        self.server.start();
        for (host, port) in self.server.bind_addrs() {
            log::info!(self.logger, "API listening on {}:{}", host, port);
        }
    }

    /// Stop the server.
    pub fn stop(&mut self) {
        block_on(self.server.shutdown()).expect("Could not stop grpc server");
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop();
    }
}
