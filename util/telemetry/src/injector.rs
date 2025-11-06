// Copyright (c) 2025 The MobileCoin Foundation

//! Utility for injecting trace context into a gRPC request

use grpcio::MetadataBuilder;
use opentelemetry::{global, propagation::Injector, Context};
use std::collections::HashMap;

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
    /// Injects the trace context info into the gRPC metadata
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
