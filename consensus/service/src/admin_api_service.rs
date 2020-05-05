// Copyright (c) 2018-2020 MobileCoin Inc.

//! Serves administrative gRPC requests.

use crate::grpc_error::ConsensusGrpcError;
use grpcio::{RpcContext, UnarySink};
use mc_common::logger::Logger;
use mc_consensus_api::{
    consensus_admin::{GetInfoResponse, GetPrometheusMetricsResponse, UpdateRustLogRequest},
    consensus_admin_grpc::ConsensusAdminApi,
    empty::Empty,
};
use mc_util_grpc::{rpc_logger, send_result};
use mc_util_metrics::SVC_COUNTERS;

#[derive(Clone)]
pub struct AdminApiService {
    logger: Logger,
}

impl AdminApiService {
    pub fn new(logger: Logger) -> Self {
        Self { logger }
    }

    fn get_prometheus_metrics_impl(
        &mut self,
        _request: Empty,
        logger: &Logger,
    ) -> Result<GetPrometheusMetricsResponse, ConsensusGrpcError> {
        todo!();
    }

    fn get_info_impl(
        &mut self,
        _request: Empty,
        logger: &Logger,
    ) -> Result<GetInfoResponse, ConsensusGrpcError> {
        todo!();
    }

    fn update_rust_log_impl(
        &mut self,
        request: UpdateRustLogRequest,
        logger: &Logger,
    ) -> Result<Empty, ConsensusGrpcError> {
        todo!();
    }

    fn test_log_error_impl(
        &mut self,
        _request: Empty,
        logger: &Logger,
    ) -> Result<Empty, ConsensusGrpcError> {
        todo!();
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
