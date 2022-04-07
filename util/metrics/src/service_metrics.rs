// Copyright (c) The Libra Core Contributors
// SPDX-License-Identifier: Apache-2.0
//
// Contains modifications by MobileCoin.

/*!
`ServiceMetrics` is a metric [`Collector`](prometheus::core::Collector) to capture key
metrics about a gRPC server.

For each method, the counters that are captured are:
- num_req: number of requests
- num_error: number of errors (can be used to calculate error rate)
- num_status_code: number of GRPC status code (for more fine grained error rates/diagnostics)
- duration: duration (in units determined by the exporter) the request took, bucketed

Example use:
call `req` when entering service method, and call `resp` on
exit, with a boolean flag to specify whether the request was
a success or a failure, to bump the counter for failures.
The call to `req` will provide a timer that handle time logging, as long
as it's in scope.

fn sample_service_method(ctx: RpcContext, params: Params) {
  let _timer = metrics.req(&ctx);
  // do business logic
  metrics.resp(&ctx, success_flag);
}
*/

use grpcio::{RpcContext, RpcStatusCode};
use mc_common::logger::global_log;
use prometheus::{
    core::{Collector, Desc},
    exponential_buckets,
    proto::MetricFamily,
    HistogramOpts, HistogramTimer, HistogramVec, IntCounterVec, Opts, Result,
};
use protobuf::Message;
use std::str;


/// Helper that encapsulates boilerplate for tracking
/// prometheus metrics about GRPC services. This struct
/// defines several common metrics (with a distinct
/// MetricFamily per method) with the method path as a
/// primary dimension/label. Method paths are derived
/// from GRPC context.
/// e.g., calc_service.req{method = "add"} = +1
/// e.g., calc_service.duration_sum{method="add"} = 6
#[derive(Clone)]
pub struct ServiceMetrics {

    /// Number of requests made by methods
    num_req: IntCounterVec,

    /// Number of error responses for methods
    num_error: IntCounterVec,

    /// Number of GRPC status codes for methods
    num_status_code: IntCounterVec,

    /// Duration of method call
    duration: HistogramVec,

    /// Histogram of message sizes
    message_size: HistogramVec,
}

impl ServiceMetrics {
    /// Create a default constructor that initializes all metrics
    pub fn default() -> ServiceMetrics {
        let message_size_buckets = exponential_buckets(2.0, 2.0, 22)
            .expect("Could not create buckets for message-size histogram");

        ServiceMetrics {

            num_req: IntCounterVec::new(Opts::new("num_req", "Number of requests"), &["method"])
                .unwrap(),
            num_error: IntCounterVec::new(Opts::new("num_error", "Number of errors"), &["method"])
                .unwrap(),
            num_status_code: IntCounterVec::new(Opts::new("num_status_code", "Number of grpc status codes"), &["method", "status_code"])
                .unwrap(),
            duration: HistogramVec::new(
                //TODO: frumious: how to ensure units?
                HistogramOpts::new("duration", "Duration for a request, in units of time"),
                &["method"],
            )
            .unwrap(),
            message_size: HistogramVec::new(
                HistogramOpts::new("message_size", "gRPC message size, in bytes (or close to)")
                    .buckets(message_size_buckets),
                &["message"],
            )
            .unwrap(),
        }
    }

    /// Register service
    pub fn new_and_registered() -> ServiceMetrics {
        let svc = ServiceMetrics::default();
        let _res = prometheus::register(Box::new(svc.clone()));
        svc
    }

    /// Track number of requests and durations
    pub fn req(&self, ctx: &RpcContext) -> Option<HistogramTimer> {
        let mut method_name = "unknown_method".to_string();
        if let Some(name) = path_from_ctx(ctx) {
            method_name = name;
        }

        self.num_req
            .with_label_values(&[method_name.as_str()])
            .inc();
        Some(
            self.duration
                .with_label_values(&[method_name.as_str()])
                .start_timer(),
        )
    }

    /// Count number of errors by method
    pub fn resp(&self, ctx: &RpcContext, success: bool) {
        if let Some(name) = path_from_ctx(ctx) {
            self.num_error
                .with_label_values(&[name.as_str()])
                .inc_by(if success { 0 } else { 1 });
        }
    }

    /// Count number of response codes by method
    pub fn status_code(&self, ctx: &RpcContext, response_code: RpcStatusCode) {
        if let Some(name) = path_from_ctx(ctx) {
            self.num_status_code
                .with_label_values(&[name.as_str(), response_code.to_string().as_str()])
                .inc();
        }
    }

    /// Track GRPC message size
    pub fn message<M: Message>(&self, message: &M) {
        let computed_size = message.compute_size();
        let message_fullname = message.descriptor().full_name();
        self.message_size
            .with_label_values(&[message_fullname])
            .observe(f64::from(computed_size));
    }

    pub fn register_default(&self) -> Result<()> {
        prometheus::register(Box::new(self.clone()))
    }
}

impl Collector for ServiceMetrics {
    /// Collect metric descriptions for Prometheus
    fn desc(&self) -> Vec<&Desc> {
        // order: num_req, num_error, duration
        vec![
            self.num_req.desc(),
            self.num_error.desc(),
            self.num_status_code.desc(),
            self.duration.desc(),
            self.message_size.desc(),
        ]
        .into_iter()
        .map(|m| m[0])
        .collect()
    }

    /// Collect Prometheus metrics
    fn collect(&self) -> Vec<MetricFamily> {
        // families
        let vs = vec![
            self.num_req.collect(),
            self.num_error.collect(),
            self.num_status_code.collect(),
            self.duration.collect(),
            self.message_size.collect(),
        ];

        vs.into_iter().fold(vec![], |mut l, v| {
            l.extend(v);
            l
        })
    }
}

/// This method reads the full URI from gRpcContext (looks like:
/// `/{package}.{service_name}/{method}`
/// and converts it into a dot-delimited string, dropping the 1st `/`
fn path_from_ctx(ctx: &RpcContext) -> Option<String> {
    let method = ctx.method();
    path_from_byte_slice(method)
}

/// This method reads the full URI from gRpcContext (looks like:
/// `/{package}.{service_name}/{method}`
/// and converts it into a dot-delimited string, dropping the 1st `/`
fn path_from_byte_slice(bytes: &[u8]) -> Option<String> {
    if bytes.len() < 5 || bytes[0] != 47u8 {
        // Incorrect structure: too short, or first char is not '/'
        global_log::info!("malformed request path: {:?}", bytes);
        return None;
    }

    let mut method_raw = vec![0u8; bytes.len() - 1];
    method_raw.copy_from_slice(&bytes[1..]);
    if let Ok(name) = str::from_utf8(&method_raw) {
        return Some(name.replace('/', "."));
    }
    global_log::info!("failed to convert byte slice to string: {:?}", &method_raw);
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_path_from_bytes() {
        let too_short = vec![47u8, 65u8, 47u8];
        assert_eq!(path_from_byte_slice(&too_short), None);

        // first char is not '/'
        let malformed = vec![65u8, 46u8, 65u8, 47u8, 66u8];
        assert_eq!(path_from_byte_slice(&malformed), None);

        // /package.service/method
        let full_name = vec![47u8, 65u8, 46u8, 65u8, 47u8, 66u8];
        assert_eq!(
            path_from_byte_slice(&full_name),
            Some(String::from("A.A.B"))
        );

        // /service/method
        let no_package = vec![47u8, 65u8, 98u8, 47u8, 99u8];
        assert_eq!(
            path_from_byte_slice(&no_package),
            Some(String::from("Ab.c"))
        );
    }
}
