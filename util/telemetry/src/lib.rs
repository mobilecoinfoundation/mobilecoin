// Copyright (c) 2018-2021 The MobileCoin Foundation

//! OpenTelemetry wrappers and helper utilities.

//     global,
//     global::BoxedTracer,
//     sdk,
//     trace::{TraceContextExt, Tracer},
// }

use opentelemetry::ContextGuard;
pub use opentelemetry::{
    global::tracer_with_version,
    trace::{SpanKind, TraceContextExt, TraceId, Tracer},
    Key,
};

#[macro_export]
macro_rules! tracer {
    () => {
        $crate::tracer_with_version(env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"))
    };
}

#[macro_export]
macro_rules! telemetry_static_key {
    ($key_name:tt) => {
        $crate::Key::from_static_str(concat!(
            "mobilecoin.com/",
            env!("CARGO_PKG_NAME"),
            "/",
            $key_name
        ))
    };
}

pub fn block_index_to_trace_id(block_index: u64) -> TraceId {
    TraceId::from_u128(0x7000000000000 + block_index as u128)
}

pub fn create_block_span<T: Tracer>(
    tracer: &T,
    span_name: &'static str,
    block_index: u64,
) -> ContextGuard {
    let span = tracer
        .span_builder(span_name)
        .with_kind(SpanKind::Server)
        .with_trace_id(block_index_to_trace_id(block_index))
        .start(tracer);
    opentelemetry::trace::mark_span_as_active(span)
}

cfg_if::cfg_if! {
    if #[cfg(feature = "jaeger")] {
        use displaydoc::Display;
        use opentelemetry::{trace::TraceError, KeyValue, sdk};
        use std::env;

        #[derive(Debug, Display)]
        pub enum Error {
            /// Trace error: {0}
            Trace(TraceError),

            /// Get hostname error: {0}
            GetHostname(std::io::Error),

            /// Failed converting hostname to string
            HostnameToString,
        }

        pub fn setup_default_tracer(service_name: &str) -> Result<sdk::trace::Tracer, Error> {
            let local_hostname = hostname::get().map_err(Error::GetHostname)?;

            let mut pipeline = opentelemetry_jaeger::new_pipeline().with_service_name(service_name);

            if let Ok(endpoint) = env::var("MC_JAEGER_AGENT") {
                pipeline = pipeline.with_agent_endpoint(endpoint);
            }

            pipeline
                .with_tags(vec![KeyValue::new(
                    "hostname",
                    local_hostname
                        .to_str()
                        .ok_or(Error::HostnameToString)?
                        .to_owned(),
                )])
                .install_simple()
                .map_err(Error::Trace)
        }
    }
}
