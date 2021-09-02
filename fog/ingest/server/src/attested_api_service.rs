// Copyright (c) 2018-2021 MobileCoin Inc.

//! Serves node-to-node attested gRPC requests.

use crate::{controller::IngestController, error::IngestServiceError};
use grpcio::{RpcContext, UnarySink};
use mc_attest_api::{attest::AuthMessage, attest_grpc::AttestedApi};
use mc_attest_net::RaClient;
use mc_common::logger::{log, Logger};
use mc_fog_recovery_db_iface::{RecoveryDb, ReportDb};
use mc_util_grpc::{rpc_logger, rpc_permissions_error, send_result};
use mc_util_metrics::SVC_COUNTERS;
use std::sync::Arc;

#[derive(Clone)]
pub struct AttestedApiService<
    R: RaClient + Send + Sync + 'static,
    DB: RecoveryDb + ReportDb + Clone + Send + Sync + 'static,
> where
    IngestServiceError: From<<DB as RecoveryDb>::Error>,
{
    controller: Arc<IngestController<R, DB>>,
    logger: Logger,
}

impl<
        R: RaClient + Send + Sync + 'static,
        DB: RecoveryDb + ReportDb + Clone + Send + Sync + 'static,
    > AttestedApiService<R, DB>
where
    IngestServiceError: From<<DB as RecoveryDb>::Error>,
{
    pub fn new(controller: Arc<IngestController<R, DB>>, logger: Logger) -> Self {
        Self { controller, logger }
    }
}

impl<
        R: RaClient + Send + Sync + 'static,
        DB: RecoveryDb + ReportDb + Clone + Send + Sync + 'static,
    > AttestedApi for AttestedApiService<R, DB>
where
    IngestServiceError: From<<DB as RecoveryDb>::Error>,
{
    fn auth(&mut self, ctx: RpcContext, request: AuthMessage, sink: UnarySink<AuthMessage>) {
        let _timer = SVC_COUNTERS.req(&ctx);
        mc_common::logger::scoped_global_logger(&rpc_logger(&ctx, &self.logger), |logger| {
            // TODO: Use the prost message directly, once available
            match self.controller.peer_accept(request.into()) {
                Ok((response, _session_id)) => {
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
