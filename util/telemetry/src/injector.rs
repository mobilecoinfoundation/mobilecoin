// Copyright (c) 2025 The MobileCoin Foundation

//! Utilities for integrating OpenTelemetry distributed tracing with grpcio-rs.
//!
//! This module provides convenient extractor and injector implementations for
//! propagating trace context through gRPC metadata headers.
//!
//! # Example
//!
//! ```rust
//! use mc_util_telemetry::inject_context;
//! use opentelemetry::Context;
//!
//! // Inject context into outgoing gRPC request
//! let metadata = tracing_utils::inject_context(&current_context)?;
//! ```

use grpcio::MetadataBuilder;
use opentelemetry::{global, propagation::Injector, Context};
use std::collections::HashMap;

/// Injector for gRPC metadata that implements the OpenTelemetry Injector trait
struct GrpcInjector(pub HashMap<String, String>);

impl GrpcInjector {
    fn new() -> Self {
        Self(HashMap::new())
    }
}

impl Injector for GrpcInjector {
    fn set(&mut self, key: &str, value: String) {
        self.0.insert(key.to_string(), value);
    }
}

pub trait InjectContext {
    type Error;
    fn inject_context(&mut self, context: &Context) -> Result<&mut Self, Self::Error>;
}

impl InjectContext for MetadataBuilder {
    type Error = grpcio::Error;
    fn inject_context(&mut self, context: &Context) -> Result<&mut Self, Self::Error> {
        let mut injector = GrpcInjector::new();
        global::get_text_map_propagator(|prop| {
            prop.inject_context(context, &mut injector);
        });
        for (key, value) in injector.0 {
            self.add_str(&key, &value)?;
        }
        Ok(self)
    }
}
