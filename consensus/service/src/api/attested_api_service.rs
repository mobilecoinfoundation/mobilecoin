// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Serves node-to-node attested gRPC requests.

use crate::SVC_COUNTERS;
use grpcio::{RpcContext, UnarySink};
use mc_attest_api::{attest::AuthMessage, attest_grpc::AttestedApi};
use mc_attest_enclave_api::{ClientSession, PeerSession, Session};
use mc_common::{
    logger::{log, Logger},
    HashSet,
};
use mc_consensus_enclave::ConsensusEnclave;
use mc_util_grpc::{
    check_request_chain_id, rpc_logger, rpc_permissions_error, send_result, Authenticator,
};
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct AttestedApiService<S: Session> {
    chain_id: String,
    enclave: Arc<dyn ConsensusEnclave + Send + Sync>,
    authenticator: Arc<dyn Authenticator + Send + Sync>,
    logger: Logger,
    sessions: Arc<Mutex<HashSet<S>>>,
}

impl<S: Session> AttestedApiService<S> {
    pub fn new(
        chain_id: String,
        enclave: Arc<dyn ConsensusEnclave + Send + Sync>,
        authenticator: Arc<dyn Authenticator + Send + Sync>,
        logger: Logger,
    ) -> Self {
        Self {
            chain_id,
            enclave,
            authenticator,
            logger,
            sessions: Arc::new(Mutex::new(HashSet::default())),
        }
    }
}

impl AttestedApi for AttestedApiService<PeerSession> {
    fn auth(&mut self, ctx: RpcContext, request: AuthMessage, sink: UnarySink<AuthMessage>) {
        let _timer = SVC_COUNTERS.req(&ctx);
        mc_common::logger::scoped_global_logger(&rpc_logger(&ctx, &self.logger), |logger| {
            if let Err(err) = check_request_chain_id(&self.chain_id, &ctx) {
                return send_result(ctx, sink, Err(err), logger);
            }

            if let Err(err) = self.authenticator.authenticate_rpc(&ctx) {
                return send_result(ctx, sink, err.into(), logger);
            }

            // TODO: Use the prost message directly, once available
            match self.enclave.peer_accept(request.into()) {
                Ok((response, session_id)) => {
                    {
                        self.sessions
                            .lock()
                            .expect("Thread crashed while inserting new session ID")
                            .insert(session_id);
                    }
                    send_result(ctx, sink, Ok(response.into()), logger);
                }
                Err(peer_error) => {
                    // This is debug because there's no requirement on the remote party to trigger
                    // it.
                    log::debug!(
                        logger,
                        "ConsensusEnclave::peer_accept failed: {}",
                        peer_error
                    );
                    send_result(
                        ctx,
                        sink,
                        Err(rpc_permissions_error(
                            "peer_auth",
                            "Permission denied",
                            logger,
                        )),
                        logger,
                    );
                }
            }
        });
    }
}

impl AttestedApi for AttestedApiService<ClientSession> {
    fn auth(&mut self, ctx: RpcContext, request: AuthMessage, sink: UnarySink<AuthMessage>) {
        let _timer = SVC_COUNTERS.req(&ctx);
        mc_common::logger::scoped_global_logger(&rpc_logger(&ctx, &self.logger), |logger| {
            if let Err(err) = check_request_chain_id(&self.chain_id, &ctx) {
                return send_result(ctx, sink, Err(err), logger);
            }

            if let Err(err) = self.authenticator.authenticate_rpc(&ctx) {
                return send_result(ctx, sink, err.into(), logger);
            }

            // TODO: Use the prost message directly, once available
            match self.enclave.client_accept(request.into()) {
                Ok((response, session_id)) => {
                    {
                        self.sessions
                            .lock()
                            .expect("Thread crashed while inserting client sesssion ID")
                            .insert(session_id);
                    }
                    send_result(ctx, sink, Ok(response.into()), logger);
                }
                Err(client_error) => {
                    // This is debug because there's no requirement on the remote party to trigger
                    // it.
                    log::debug!(
                        logger,
                        "ConsensusEnclave::client_accept failed: {}",
                        client_error
                    );
                    send_result(
                        ctx,
                        sink,
                        Err(rpc_permissions_error(
                            "client_auth",
                            "Permission denied",
                            logger,
                        )),
                        logger,
                    );
                }
            }
        });
    }
}

#[cfg(test)]
mod peer_tests {
    use super::*;
    use grpcio::{
        ChannelBuilder, Environment, Error as GrpcError, RpcStatusCode, Server, ServerBuilder,
        ServerCredentials,
    };
    use mc_attest_api::attest_grpc::{self, AttestedApiClient};
    use mc_common::{logger::test_with_logger, time::SystemTimeProvider};
    use mc_consensus_enclave_mock::MockConsensusEnclave;
    use mc_util_grpc::TokenAuthenticator;
    use std::time::Duration;

    /// Starts the service on localhost and connects a client to it.
    fn get_client_server(instance: AttestedApiService<PeerSession>) -> (AttestedApiClient, Server) {
        let service = attest_grpc::create_attested_api(instance);
        let env = Arc::new(Environment::new(1));
        let mut server = ServerBuilder::new(env.clone())
            .register_service(service)
            .build()
            .expect("Could not create GRPC server");
        let port = server
            .add_listening_port("127.0.0.1:0", ServerCredentials::insecure())
            .expect("Could not create anonymous bind");
        server.start();
        let ch = ChannelBuilder::new(env).connect(&format!("127.0.0.1:{port}"));
        let client = AttestedApiClient::new(ch);
        (client, server)
    }

    #[test_with_logger]
    // `auth` should reject unauthenticated responses when configured with an
    // authenticator.
    fn test_peer_auth_unauthenticated(logger: Logger) {
        let authenticator = Arc::new(TokenAuthenticator::new(
            [1; 32],
            Duration::from_secs(60),
            SystemTimeProvider,
        ));
        let enclave = Arc::new(MockConsensusEnclave::new());

        let attested_api_service = AttestedApiService::<PeerSession>::new(
            "local".to_string(),
            enclave,
            authenticator,
            logger,
        );

        let (client, _server) = get_client_server(attested_api_service);

        match client.auth(&AuthMessage::default()) {
            Ok(response) => {
                panic!("Unexpected response {response:?}");
            }
            Err(GrpcError::RpcFailure(rpc_status)) => {
                assert_eq!(rpc_status.code(), RpcStatusCode::UNAUTHENTICATED);
            }
            Err(err) => {
                panic!("Unexpected error {err:?}");
            }
        }
    }
}

#[cfg(test)]
mod client_tests {
    use super::*;
    use grpcio::{
        ChannelBuilder, Environment, Error as GrpcError, RpcStatusCode, Server, ServerBuilder,
        ServerCredentials,
    };
    use mc_attest_api::attest_grpc::{self, AttestedApiClient};
    use mc_common::{logger::test_with_logger, time::SystemTimeProvider};
    use mc_consensus_enclave_mock::MockConsensusEnclave;
    use mc_util_grpc::TokenAuthenticator;
    use std::time::Duration;

    /// Starts the service on localhost and connects a client to it.
    fn get_client_server(
        instance: AttestedApiService<ClientSession>,
    ) -> (AttestedApiClient, Server) {
        let service = attest_grpc::create_attested_api(instance);
        let env = Arc::new(Environment::new(1));
        let mut server = ServerBuilder::new(env.clone())
            .register_service(service)
            .build()
            .expect("Could not create GRPC server");
        let port = server
            .add_listening_port("127.0.0.1:0", ServerCredentials::insecure())
            .expect("Could not create anonymous bind");
        server.start();
        let ch = ChannelBuilder::new(env).connect(&format!("127.0.0.1:{port}"));
        let client = AttestedApiClient::new(ch);
        (client, server)
    }

    #[test_with_logger]
    // `auth` should reject unauthenticated responses when configured with an
    // authenticator.
    fn test_client_auth_unauthenticated(logger: Logger) {
        let authenticator = Arc::new(TokenAuthenticator::new(
            [1; 32],
            Duration::from_secs(60),
            SystemTimeProvider,
        ));
        let enclave = Arc::new(MockConsensusEnclave::new());

        let attested_api_service = AttestedApiService::<ClientSession>::new(
            "local".to_string(),
            enclave,
            authenticator,
            logger,
        );

        let (client, _server) = get_client_server(attested_api_service);

        match client.auth(&AuthMessage::default()) {
            Ok(response) => {
                panic!("Unexpected response {response:?}");
            }
            Err(GrpcError::RpcFailure(rpc_status)) => {
                assert_eq!(rpc_status.code(), RpcStatusCode::UNAUTHENTICATED);
            }
            Err(err) => {
                panic!("Unexpected error {err:?}");
            }
        }
    }
}
