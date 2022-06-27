// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Customizable implementation of the AdminApi service.

use crate::{
    admin::{
        create_admin_api, AdminApi, GetInfoResponse, GetPrometheusMetricsResponse,
        SetRustLogRequest,
    },
    build_info_service::get_build_info,
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
    /// Create a new instance of the admin service
    ///
    /// Arguments:
    /// * name: A name for the server
    /// * id: An id for the server
    /// * get_config_json: An optional callback that describes the current
    ///   configuration of the server as a json object
    /// * logger
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

    /// Convert into a grpcio::Service
    pub fn into_service(self) -> Service {
        create_admin_api(self)
    }

    fn get_prometheus_metrics_impl(
        &mut self,
        logger: &Logger,
    ) -> Result<GetPrometheusMetricsResponse, RpcStatus> {
        log::trace!(logger, "get_prometheus_metrics_impl");

        let metric_families = prometheus::gather();
        let encoder = prometheus::TextEncoder::new();
        let mut buffer = vec![];
        encoder.encode(&metric_families, &mut buffer).unwrap();

        Ok(GetPrometheusMetricsResponse {
            metrics: String::from_utf8(buffer).map_err(|err| {
                RpcStatus::with_message(
                    RpcStatusCode::INTERNAL,
                    format!("from_utf8 failed: {}", err),
                )
            })?,
        })
    }

    fn get_info_impl(&mut self, logger: &Logger) -> Result<GetInfoResponse, RpcStatus> {
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

        Ok(GetInfoResponse {
            name: self.name.clone(),
            id: self.id.clone(),
            build_info_json,
            build_info: Some(build_info),
            config_json,
            rust_log,
        })
    }

    fn set_rust_log_impl(
        &mut self,
        request: SetRustLogRequest,
        logger: &Logger,
    ) -> Result<(), RpcStatus> {
        log::info!(logger, "Updating RUST_LOG to '{}'", request.rust_log);
        env::set_var("RUST_LOG", request.rust_log);
        mc_common::logger::recreate_app_logger();

        Ok(())
    }

    fn test_log_error_impl(&mut self, logger: &Logger) -> Result<(), RpcStatus> {
        log::error!(logger, "Test log message admin admin interface");

        Ok(())
    }
}

impl AdminApi for AdminService {
    fn get_prometheus_metrics(
        &mut self,
        ctx: RpcContext,
        _request: (),
        sink: UnarySink<GetPrometheusMetricsResponse>,
    ) {
        let _timer = SVC_COUNTERS.req(&ctx);
        mc_common::logger::scoped_global_logger(&rpc_logger(&ctx, &self.logger), |logger| {
            send_result(ctx, sink, self.get_prometheus_metrics_impl(logger), logger)
        });
    }

    fn get_info(&mut self, ctx: RpcContext, _request: (), sink: UnarySink<GetInfoResponse>) {
        let _timer = SVC_COUNTERS.req(&ctx);
        mc_common::logger::scoped_global_logger(&rpc_logger(&ctx, &self.logger), |logger| {
            send_result(ctx, sink, self.get_info_impl(logger), logger)
        });
    }

    fn set_rust_log(&mut self, ctx: RpcContext, request: SetRustLogRequest, sink: UnarySink<()>) {
        let _timer = SVC_COUNTERS.req(&ctx);
        mc_common::logger::scoped_global_logger(&rpc_logger(&ctx, &self.logger), |logger| {
            send_result(ctx, sink, self.set_rust_log_impl(request, logger), logger)
        });
    }

    fn test_log_error(&mut self, ctx: RpcContext, _request: (), sink: UnarySink<()>) {
        let _timer = SVC_COUNTERS.req(&ctx);
        mc_common::logger::scoped_global_logger(&rpc_logger(&ctx, &self.logger), |logger| {
            send_result(ctx, sink, self.test_log_error_impl(logger), logger)
        });
    }
}
