// Copyright 2018-2021 MobileCoin, Inc.

//! Server for ingest reports.

use crate::{config::Materials, service::Service};
use futures::executor::block_on;
use grpcio::{Server as GrpcioServer, ServerBuilder};
use mc_common::logger::{log, Logger};
use mc_fog_api::report_grpc;
use mc_fog_recovery_db_iface::ReportDb;
use mc_util_grpc::{ConnectionUriGrpcioServer, HealthService};
use mc_util_uri::{ConnectionUri, FogUri};
use std::sync::Arc;

/// The application server structure, contains the gRPC server and logger.
pub struct Server {
    server: GrpcioServer,
    logger: Logger,
}

impl Server {
    /// Construct a new server object.
    pub fn new(
        db: impl ReportDb + Clone + Send + Sync + 'static,
        client_listen_uri: &FogUri,
        materials: Materials,
        logger: Logger,
    ) -> Self {
        let env = Arc::new(
            grpcio::EnvBuilder::new()
                .name_prefix("ReportServer-RPC".to_string())
                .build(),
        );

        let report_service =
            report_grpc::create_report_api(Service::new(db, materials, logger.clone()));
        log::debug!(logger, "Constructed Report GRPC Service");

        // Health check service
        let health_service = HealthService::new(None, logger.clone()).into_service();

        // Package service into grpc server
        log::info!(
            logger,
            "Starting Report server on {}",
            client_listen_uri.addr(),
        );
        let server_builder = ServerBuilder::new(env)
            .register_service(report_service)
            .register_service(health_service)
            .bind_using_uri(client_listen_uri, logger.clone());

        let server = server_builder.build().unwrap();

        Self { server, logger }
    }

    pub fn start(&mut self) {
        self.server.start();
        for (host, port) in self.server.bind_addrs() {
            log::info!(self.logger, "API listening on {}:{}", host, port);
        }
    }

    pub fn stop(&mut self) {
        block_on(self.server.shutdown()).expect("Could not stop grpc server");
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop();
    }
}
