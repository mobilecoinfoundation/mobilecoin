// Copyright (c) 2025 The MobileCoin Foundation

//! Extractor for propagating trace context from gRPC metadata headers.
//!
//! # Example
//!
//! ```rust
//! use mc_util_telemetry::extract_context;
//! use opentelemetry::Context;
//!
//! // Extract context from incoming gRPC context
//! let parent_context = tracing_utils::extract_context(rpc_ctx);
//! ```

use grpcio::{Metadata, RpcContext};
use opentelemetry::{global, propagation::Extractor, Context};

struct GrpcExtractor<'a>(pub &'a Metadata);

impl Extractor for GrpcExtractor<'_> {
    fn get(&self, key: &str) -> Option<&str> {
        self.0.iter().find_map(|(k, v)| {
            if k == key {
                std::str::from_utf8(v).ok()
            } else {
                None
            }
        })
    }

    fn keys(&self) -> Vec<&str> {
        self.0.iter().map(|(k, _)| k).collect()
    }
}

/// Extract trace context from gRPC Context
pub fn extract_context(rpc_ctx: &RpcContext) -> Context {
    let metadata = rpc_ctx.request_headers();
    let extractor = GrpcExtractor(metadata);
    global::get_text_map_propagator(|prop| prop.extract(&extractor))
}
