// Copyright (c) 2018-2020 MobileCoin Inc.

//! Serves administrative gRPC requests.

use crate::{config::Config, grpc_error::ConsensusGrpcError};
use grpcio::{RpcContext, UnarySink};
use mc_common::logger::{log, Logger};
use mc_consensus_api::{
    consensus_admin::{GetInfoResponse, GetPrometheusMetricsResponse, UpdateRustLogRequest},
    consensus_admin_grpc::ConsensusAdminApi,
    empty::Empty,
};
use mc_util_grpc::{rpc_logger, send_result};
use mc_util_metrics::SVC_COUNTERS;
use prometheus::{self, Encoder};
use serde_json::json;
use std::env;

/// Admin api service implementation.
#[derive(Clone)]
pub struct AdminApiService {
    /// Consensus service global configuration.
    config: Config,

    /// Logger.
    logger: Logger,
}

impl AdminApiService {
    pub fn new(config: Config, logger: Logger) -> Self {
        Self { config, logger }
    }

    fn get_prometheus_metrics_impl(
        &mut self,
        _request: Empty,
        logger: &Logger,
    ) -> Result<GetPrometheusMetricsResponse, ConsensusGrpcError> {
        log::trace!(logger, "get_prometheus_metrics_impl");

        let metric_families = prometheus::gather();
        let encoder = prometheus::TextEncoder::new();
        let mut buffer = vec![];
        encoder.encode(&metric_families, &mut buffer).unwrap();

        let mut response = GetPrometheusMetricsResponse::new();
        response.set_metrics(
            String::from_utf8(buffer)
                .map_err(|err| ConsensusGrpcError::Other(format!("from_utf8 failed: {}", err)))?,
        );
        Ok(response)
    }

    fn get_info_impl(
        &mut self,
        _request: Empty,
        logger: &Logger,
    ) -> Result<GetInfoResponse, ConsensusGrpcError> {
        log::trace!(logger, "get_info_impl");

        let mut build_info_json = String::new();
        mc_util_build_info::write_report(&mut build_info_json)
            .map_err(|err| ConsensusGrpcError::Other(format!("write_report failed: {}", err)))?;

        let config = &self.config;
        let config_json = json!({
            "public_key": config.node_id().public_key,
            "peer_responder_id": config.peer_responder_id,
            "client_responder_id": config.client_responder_id,
            "message_pubkey": config.msg_signer_key.public_key(),
            "network": config.network_path,
            "ias_api_key": config.ias_api_key,
            "ias_spid": config.ias_spid,
            "peer_listen_uri": config.peer_listen_uri,
            "client_listen_uri": config.client_listen_uri,
            "management_listen_addr": config.management_listen_addr,
            "ledger_path": config.ledger_path,
            "scp_debug_dump": config.scp_debug_dump,
        })
        .to_string();

        let network_json = serde_json::to_string(&config.network()).map_err(|err| {
            ConsensusGrpcError::Other(format!("failed encoding network json: {}", err))
        })?;

        let rust_log = env::var("RUST_LOG").unwrap_or_else(|_| "".to_string());

        let mut response = GetInfoResponse::new();
        response.set_build_info_json(build_info_json);
        response.set_config_json(config_json);
        response.set_network_json(network_json);
        response.set_rust_log(rust_log);
        Ok(response)
    }

    fn update_rust_log_impl(
        &mut self,
        request: UpdateRustLogRequest,
        logger: &Logger,
    ) -> Result<Empty, ConsensusGrpcError> {
        log::info!(logger, "Updating RUST_LOG to '{}'", request.rust_log);
        env::set_var("RUST_LOG", request.rust_log);
        mc_common::logger::recreate_app_logger();

        Ok(Empty::new())
    }

    fn test_log_error_impl(
        &mut self,
        _request: Empty,
        logger: &Logger,
    ) -> Result<Empty, ConsensusGrpcError> {
        log::error!(logger, "Test log message admin admin interface");

        Ok(Empty::new())
    }
}

impl ConsensusAdminApi for AdminApiService {
    fn get_prometheus_metrics(
        &mut self,
        ctx: RpcContext,
        request: Empty,
        sink: UnarySink<GetPrometheusMetricsResponse>,
    ) {
        let _timer = SVC_COUNTERS.req(&ctx);
        mc_common::logger::scoped_global_logger(&rpc_logger(&ctx, &self.logger), |logger| {
            send_result(
                ctx,
                sink,
                self.get_prometheus_metrics_impl(request, &logger)
                    .map_err(ConsensusGrpcError::into),
                &logger,
            )
        });
    }

    fn get_info(&mut self, ctx: RpcContext, request: Empty, sink: UnarySink<GetInfoResponse>) {
        let _timer = SVC_COUNTERS.req(&ctx);
        mc_common::logger::scoped_global_logger(&rpc_logger(&ctx, &self.logger), |logger| {
            send_result(
                ctx,
                sink,
                self.get_info_impl(request, &logger)
                    .map_err(ConsensusGrpcError::into),
                &logger,
            )
        });
    }

    fn update_rust_log(
        &mut self,
        ctx: RpcContext,
        request: UpdateRustLogRequest,
        sink: UnarySink<Empty>,
    ) {
        let _timer = SVC_COUNTERS.req(&ctx);
        mc_common::logger::scoped_global_logger(&rpc_logger(&ctx, &self.logger), |logger| {
            send_result(
                ctx,
                sink,
                self.update_rust_log_impl(request, &logger)
                    .map_err(ConsensusGrpcError::into),
                &logger,
            )
        });
    }

    fn test_log_error(&mut self, ctx: RpcContext, request: Empty, sink: UnarySink<Empty>) {
        let _timer = SVC_COUNTERS.req(&ctx);
        mc_common::logger::scoped_global_logger(&rpc_logger(&ctx, &self.logger), |logger| {
            send_result(
                ctx,
                sink,
                self.test_log_error_impl(request, &logger)
                    .map_err(ConsensusGrpcError::into),
                &logger,
            )
        });
    }
}
