// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Customizable implementation of the AdminApi service.

use crate::{
    admin::{GetInfoResponse, GetPrometheusMetricsResponse, SetRustLogRequest},
    admin_grpc::{create_admin_api, AdminApi},
    build_info_service::get_build_info,
    empty::Empty,
    rpc_logger, send_result,
};
use grpcio::{RpcContext, RpcStatus, RpcStatusCode, Service, UnarySink};
use mc_common::logger::{log, Logger};
use mc_util_metrics::SVC_COUNTERS;
use prometheus::{self, Encoder};
use std::{env, sync::Arc};

/// A callback for getting service-specific configuration data.
pub type GetConfigJsonFn = Arc<dyn Fn() -> Result<String, RpcStatus> + Sync + Send>;

/// Admin GRPC service.
#[derive(Clone)]
pub struct AdminService {
    /// User-friendly service name (e.g. "Consensus Service").
    name: String,

    /// Unique identifier for the service (e.g. the hostname it is running on).
    id: String,

    /// Optional callback for returning service-specific configuration JSON blob
    get_config_json: Option<GetConfigJsonFn>,

    /// Logger.
    logger: Logger,
}

impl AdminService {
    pub fn new(
        name: String,
        id: String,
        get_config_json: Option<GetConfigJsonFn>,
        logger: Logger,
    ) -> Self {
        Self {
            name,
            id,
            get_config_json,
            logger,
        }
    }

    pub fn into_service(self) -> Service {
        create_admin_api(self)
    }

    fn get_prometheus_metrics_impl(
        &mut self,
        _request: Empty,
        logger: &Logger,
    ) -> Result<GetPrometheusMetricsResponse, RpcStatus> {
        log::trace!(logger, "get_prometheus_metrics_impl");

        let metric_families = prometheus::gather();
        let encoder = prometheus::TextEncoder::new();
        let mut buffer = vec![];
        encoder.encode(&metric_families, &mut buffer).unwrap();

        let mut response = GetPrometheusMetricsResponse::new();
        response.set_metrics(String::from_utf8(buffer).map_err(|err| {
            RpcStatus::with_message(
                RpcStatusCode::INTERNAL,
                format!("from_utf8 failed: {}", err),
            )
        })?);
        Ok(response)
    }

    fn get_info_impl(
        &mut self,
        _request: Empty,
        logger: &Logger,
    ) -> Result<GetInfoResponse, RpcStatus> {
        log::trace!(logger, "get_info_impl");

        let mut build_info_json = String::new();
        mc_util_build_info::write_report(&mut build_info_json).map_err(|err| {
            RpcStatus::with_message(
                RpcStatusCode::INTERNAL,
                format!("write_report failed: {}", err),
            )
        })?;

        let build_info = get_build_info();

        let config_json = if let Some(get_config_json) = self.get_config_json.as_ref() {
            get_config_json()?
        } else {
            String::from("")
        };

        let rust_log = env::var("RUST_LOG").unwrap_or_else(|_| "".to_string());

        let mut response = GetInfoResponse::new();
        response.set_name(self.name.clone());
        response.set_id(self.id.clone());
        response.set_build_info_json(build_info_json);
        response.set_build_info(build_info);
        response.set_config_json(config_json);
        response.set_rust_log(rust_log);
        Ok(response)
    }

    fn set_rust_log_impl(
        &mut self,
        request: SetRustLogRequest,
        logger: &Logger,
    ) -> Result<Empty, RpcStatus> {
        log::info!(logger, "Updating RUST_LOG to '{}'", request.rust_log);
        env::set_var("RUST_LOG", request.rust_log);
        mc_common::logger::recreate_app_logger();

        Ok(Empty::new())
    }

    fn test_log_error_impl(
        &mut self,
        _request: Empty,
        logger: &Logger,
    ) -> Result<Empty, RpcStatus> {
        log::error!(logger, "Test log message admin admin interface");

        Ok(Empty::new())
    }
}

impl AdminApi for AdminService {
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
                self.get_prometheus_metrics_impl(request, &logger),
                &logger,
            )
        });
    }

    fn get_info(&mut self, ctx: RpcContext, request: Empty, sink: UnarySink<GetInfoResponse>) {
        let _timer = SVC_COUNTERS.req(&ctx);
        mc_common::logger::scoped_global_logger(&rpc_logger(&ctx, &self.logger), |logger| {
            send_result(ctx, sink, self.get_info_impl(request, &logger), &logger)
        });
    }

    fn set_rust_log(
        &mut self,
        ctx: RpcContext,
        request: SetRustLogRequest,
        sink: UnarySink<Empty>,
    ) {
        let _timer = SVC_COUNTERS.req(&ctx);
        mc_common::logger::scoped_global_logger(&rpc_logger(&ctx, &self.logger), |logger| {
            send_result(ctx, sink, self.set_rust_log_impl(request, &logger), &logger)
        });
    }

    fn test_log_error(&mut self, ctx: RpcContext, request: Empty, sink: UnarySink<Empty>) {
        let _timer = SVC_COUNTERS.req(&ctx);
        mc_common::logger::scoped_global_logger(&rpc_logger(&ctx, &self.logger), |logger| {
            send_result(
                ctx,
                sink,
                self.test_log_error_impl(request, &logger),
                &logger,
            )
        });
    }
}
