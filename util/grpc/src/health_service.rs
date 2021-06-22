// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Implementation of the [GRPC Health Checking
//! Protocol](https://github.com/grpc/grpc/blob/master/doc/health-checking.md) with some added
//! MobileCoin-specific (Ping) extensions.

use crate::{
    health_api::{
        HealthCheckRequest, HealthCheckResponse, HealthCheckResponse_ServingStatus, PingRequest,
        PingResponse,
    },
    health_api_grpc::{create_health, Health},
    rpc_logger, send_result,
};
use futures::prelude::*;
use grpcio::{RpcContext, RpcStatus, RpcStatusCode, ServerStreamingSink, Service, UnarySink};
use mc_common::logger::{log, Logger};
use mc_util_metrics::SVC_COUNTERS;
use std::sync::Arc;

// Re-export the health check status enum for convenience.
pub use crate::health_api::HealthCheckResponse_ServingStatus as HealthCheckStatus;

// A prototype of a callback function that receives a service name and returns
// it's health status. By defauult, `HealthService` would respond SERVING to all
// health check requests, but passing a callback to it allows customization of
// this behavior.
pub type ServiceHealthCheckCallback = Arc<dyn Fn(&str) -> HealthCheckStatus + Sync + Send>;

#[derive(Clone)]
pub struct HealthService {
    service_health_check_callback: Option<ServiceHealthCheckCallback>,
    logger: Logger,
}

impl HealthService {
    pub fn new(
        service_health_check_callback: Option<ServiceHealthCheckCallback>,
        logger: Logger,
    ) -> Self {
        Self {
            service_health_check_callback,
            logger,
        }
    }

    pub fn into_service(self) -> Service {
        create_health(self)
    }
}

impl Health for HealthService {
    fn check(
        &mut self,
        ctx: RpcContext,
        req: HealthCheckRequest,
        sink: UnarySink<HealthCheckResponse>,
    ) {
        let _timer = SVC_COUNTERS.req(&ctx);
        let logger = rpc_logger(&ctx, &self.logger);

        let status = match &self.service_health_check_callback {
            None => HealthCheckResponse_ServingStatus::SERVING,
            Some(callback) => callback(req.get_service()),
        };

        let mut resp = HealthCheckResponse::new();
        resp.set_status(status);
        send_result(ctx, sink, Ok(resp), &logger);
    }

    fn ping(&mut self, ctx: RpcContext, req: PingRequest, sink: UnarySink<PingResponse>) {
        let _timer = SVC_COUNTERS.req(&ctx);
        let logger = rpc_logger(&ctx, &self.logger);

        let mut resp = PingResponse::new();
        resp.set_data(req.get_data().to_vec());
        send_result(ctx, sink, Ok(resp), &logger);
    }

    fn watch(
        &mut self,
        ctx: RpcContext,
        _req: HealthCheckRequest,
        sink: ServerStreamingSink<HealthCheckResponse>,
    ) {
        let logger = self.logger.clone();

        let resp = sink
            .fail(RpcStatus::with_message(
                RpcStatusCode::UNIMPLEMENTED,
                "Unimplemented".into(),
            ))
            .map_err(move |err| log::error!(logger, "failed to reply: {:?}", err))
            .map(|_| ());

        ctx.spawn(resp);
    }
}
