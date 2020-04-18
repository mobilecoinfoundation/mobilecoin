// Copyright (c) 2018-2020 MobileCoin Inc.

//! Serves node-to-node attested gRPC requests.

use grpcio::{RpcContext, UnarySink};
use mc_attest_api::{attest::AuthMessage, attest_grpc::AttestedApi};
use mc_attest_enclave_api::{ClientSession, PeerSession, Session};
use mc_common::{
    logger::{log, Logger},
    HashSet,
};
use mc_consensus_enclave::ConsensusEnclaveProxy;
use mc_util_grpc::{rpc_logger, rpc_permissions_error, send_result};
use mc_util_metrics::SVC_COUNTERS;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct AttestedApiService<E: ConsensusEnclaveProxy, S: Session> {
    enclave: E,
    logger: Logger,
    sessions: Arc<Mutex<HashSet<S>>>,
}

impl<E: ConsensusEnclaveProxy, S: Session> AttestedApiService<E, S> {
    pub fn new(enclave: E, logger: Logger) -> Self {
        Self {
            enclave,
            logger,
            sessions: Arc::new(Mutex::new(HashSet::default())),
        }
    }
}

impl<E: ConsensusEnclaveProxy> AttestedApi for AttestedApiService<E, PeerSession> {
    fn auth(&mut self, ctx: RpcContext, request: AuthMessage, sink: UnarySink<AuthMessage>) {
        let _timer = SVC_COUNTERS.req(&ctx);
        mc_common::logger::scoped_global_logger(&rpc_logger(&ctx, &self.logger), |logger| {
            // TODO: Use the prost message directly, once available
            match self.enclave.peer_accept(request.into()) {
                Ok((response, session_id)) => {
                    {
                        self.sessions
                            .lock()
                            .expect("Thread crashed while inserting new session ID")
                            .insert(session_id);
                    }
                    send_result(ctx, sink, Ok(response.into()), &logger);
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
                            &logger,
                        )),
                        &logger,
                    );
                }
            }
        });
    }
}

impl<E: ConsensusEnclaveProxy> AttestedApi for AttestedApiService<E, ClientSession> {
    fn auth(&mut self, ctx: RpcContext, request: AuthMessage, sink: UnarySink<AuthMessage>) {
        let _timer = SVC_COUNTERS.req(&ctx);
        mc_common::logger::scoped_global_logger(&rpc_logger(&ctx, &self.logger), |logger| {
            // TODO: Use the prost message directly, once available
            match self.enclave.client_accept(request.into()) {
                Ok((response, session_id)) => {
                    {
                        self.sessions
                            .lock()
                            .expect("Thread crashed while inserting client sesssion ID")
                            .insert(session_id);
                    }
                    send_result(ctx, sink, Ok(response.into()), &logger);
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
                            &logger,
                        )),
                        &logger,
                    );
                }
            }
        });
    }
}
