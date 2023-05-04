// Copyright (c) 2018-2023 The MobileCoin Foundation

use crate::{Error, VerifierService};
use futures::executor::block_on;
use light_client_api::LightClientUri;
use mc_common::logger::{log, Logger};
use mc_util_grpc::ConnectionUriGrpcioServer;
use mc_util_uri::ConnectionUri;
use std::sync::Arc;

/// Light Client Verifier server
pub struct VerifierServer {
    /// Client listen URI.
    client_listen_uri: LightClientUri,

    /// Logger.
    logger: Logger,

    /// Client GRPC server.
    server: Option<grpcio::Server>,
}

impl VerifierServer {
    pub fn new(client_listen_uri: LightClientUri, logger: Logger) -> Self {
        Self {
            client_listen_uri,
            logger,
            server: None,
        }
    }

    /// Start all the grpc services and threads in the server
    pub fn start(&mut self) -> Result<(), Error> {
        let ret = self.start_helper();
        if let Err(ref err) = ret {
            log::error!(self.logger, "Server failed to start: {}", err);
            self.stop();
        }
        ret
    }

    /// Helper which gathers errors when starting server
    fn start_helper(&mut self) -> Result<(), Error> {
        self.start_client_rpc_server()?;
        Ok(())
    }

    /// Start the client RPC server
    fn start_client_rpc_server(&mut self) -> Result<(), Error> {
        log::info!(
            self.logger,
            "Starting Verifier RPC server on {}",
            self.client_listen_uri
        );

        let health_service =
            mc_util_grpc::HealthService::new(None, self.logger.clone()).into_service();

        let verifier_service = VerifierService::new(self.logger.clone()).into_service();

        let grpc_env = Arc::new(
            grpcio::EnvBuilder::new()
                .name_prefix("Verifier-RPC".to_string())
                .build(),
        );

        let server_builder = grpcio::ServerBuilder::new(grpc_env)
            .register_service(health_service)
            .register_service(verifier_service);

        let mut server =
            server_builder.build_using_uri(&self.client_listen_uri, self.logger.clone())?;
        server.start();

        log::info!(
            self.logger,
            "Verifier GRPC API listening on {}",
            self.client_listen_uri.addr(),
        );

        self.server = Some(server);
        Ok(())
    }

    /// Stop the servers and threads
    /// They cannot be restarted, so this should normally be done only just
    /// before tearing down the whole server.
    pub fn stop(&mut self) {
        if let Some(mut server) = self.server.take() {
            block_on(server.shutdown()).expect("Could not stop verifier_service grpc server");
        }
    }
}

impl Drop for VerifierServer {
    fn drop(&mut self) {
        self.stop();
    }
}
