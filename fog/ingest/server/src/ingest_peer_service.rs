// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Implement the ingest grpc API

use crate::{controller::IngestController, error::IngestServiceError};
use grpcio::{RpcContext, RpcStatus, UnarySink};
use mc_attest_api::attest::Message;
use mc_attest_enclave_api::PeerSession;
use mc_attest_net::RaClient;
use mc_common::logger::{log, Logger};
use mc_fog_api::{
    ingest_common::{IngestSummary, SetPeersRequest},
    ingest_peer::*,
    Empty,
};
use mc_fog_recovery_db_iface::{RecoveryDb, ReportDb};
use mc_fog_uri::IngestPeerUri;
use mc_util_grpc::{rpc_enclave_err, rpc_invalid_arg_error, rpc_logger, send_result};
use mc_util_metrics::SVC_COUNTERS;
use std::{str::FromStr, sync::Arc};

/// Implements the Ingest Peer grpc api
#[derive(Clone)]
pub struct IngestPeerService<
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
    > IngestPeerService<R, DB>
where
    IngestServiceError: From<<DB as RecoveryDb>::Error>,
{
    /// Creates a new ingest node (but does not create sockets and start it
    /// etc.)
    pub fn new(controller: Arc<IngestController<R, DB>>, logger: Logger) -> Self {
        Self { controller, logger }
    }

    /// Logic of proto api
    pub fn get_status_impl(&mut self) -> Result<IngestSummary, RpcStatus> {
        Ok(self.controller.get_ingest_summary())
    }

    /// Logic of proto api
    pub fn set_peers_impl(
        &mut self,
        request: SetPeersRequest,
        logger: &Logger,
    ) -> Result<IngestSummary, RpcStatus> {
        let peers = request
            .ingest_peer_uris
            .iter()
            .map(|x| IngestPeerUri::from_str(x))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|err| rpc_invalid_arg_error("invalid peer uri", err, logger))?;

        self.controller
            .set_peers(peers)
            .map_err(|err| rpc_invalid_arg_error(err, "invalid peer uri", logger))?;

        Ok(self.controller.get_ingest_summary())
    }

    /// Logic of proto api (this actually matches part of the peer API)
    pub fn get_ingress_private_key_impl(
        &mut self,
        request: GetPrivateKeyRequest,
        logger: &Logger,
    ) -> Result<Message, RpcStatus> {
        log::debug!(&self.logger, "Now getting private key",);

        let peer_session = PeerSession::from(request.get_channel_id());

        let (private_key, _) = self
            .controller
            .get_ingress_private_key(peer_session)
            .map_err(|err| rpc_enclave_err(err, logger))?;

        Ok(private_key.into())
    }

    /// Set the private key of this enclave
    pub fn set_ingress_private_key_impl(
        &mut self,
        msg: Message,
        logger: &Logger,
    ) -> Result<IngestSummary, RpcStatus> {
        log::debug!(&self.logger, "Now getting private key",);

        self.controller
            .set_ingress_private_key(msg.into())
            .map_err(|err| rpc_enclave_err(err, logger))?;

        Ok(self.controller.get_ingest_summary())
    }
}

impl<
        R: RaClient + Send + Sync + 'static,
        DB: RecoveryDb + ReportDb + Clone + Send + Sync + 'static,
    > mc_fog_api::ingest_peer_grpc::AccountIngestPeerApi for IngestPeerService<R, DB>
where
    IngestServiceError: From<<DB as RecoveryDb>::Error>,
{
    fn get_status(&mut self, ctx: RpcContext, _request: Empty, sink: UnarySink<IngestSummary>) {
        let _timer = SVC_COUNTERS.req(&ctx);
        mc_common::logger::scoped_global_logger(&rpc_logger(&ctx, &self.logger), |logger| {
            send_result(ctx, sink, self.get_status_impl(), &logger)
        })
    }

    fn set_peers(
        &mut self,
        ctx: RpcContext,
        request: SetPeersRequest,
        sink: UnarySink<IngestSummary>,
    ) {
        let _timer = SVC_COUNTERS.req(&ctx);
        mc_common::logger::scoped_global_logger(&rpc_logger(&ctx, &self.logger), |logger| {
            send_result(ctx, sink, self.set_peers_impl(request, &logger), &logger)
        })
    }

    fn get_ingress_private_key(
        &mut self,
        ctx: RpcContext,
        request: GetPrivateKeyRequest,
        sink: UnarySink<Message>,
    ) {
        let _timer = SVC_COUNTERS.req(&ctx);
        mc_common::logger::scoped_global_logger(&rpc_logger(&ctx, &self.logger), |logger| {
            send_result(
                ctx,
                sink,
                self.get_ingress_private_key_impl(request, &logger),
                &logger,
            )
        })
    }
    fn set_ingress_private_key(
        &mut self,
        ctx: RpcContext,
        request: Message,
        sink: UnarySink<IngestSummary>,
    ) {
        let _timer = SVC_COUNTERS.req(&ctx);
        mc_common::logger::scoped_global_logger(&rpc_logger(&ctx, &self.logger), |logger| {
            send_result(
                ctx,
                sink,
                self.set_ingress_private_key_impl(request, &logger),
                &logger,
            )
        })
    }
}
