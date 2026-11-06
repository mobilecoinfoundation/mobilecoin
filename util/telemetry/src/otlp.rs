use displaydoc::Display;
use opentelemetry::{global, global::BoxedTracer, KeyValue};
use opentelemetry_otlp::{ExporterBuildError, SpanExporter};
use opentelemetry_sdk::{propagation::TraceContextPropagator, trace::SdkTracerProvider, Resource};

#[derive(Debug, Display)]
pub enum Error {
    /// Failed building OTLP exporter: {0}
    Exporter(ExporterBuildError),

    /// Get hostname error: {0}
    GetHostname(std::io::Error),

    /// Failed converting hostname to string
    HostnameToString,
}

/// Set up a default tracer with no additional tags.
/// Telemetry is enabled iff env.MC_TELEMETRY is set to "1" or "true".
pub fn setup_default_tracer(service_name: &'static str) -> Result<Option<BoxedTracer>, Error> {
    setup_default_tracer_with_tags(service_name, &[])
}

pub fn telemetry_enabled() -> bool {
    std::env::var("MC_TELEMETRY")
        .map(|val| val == "1" || val.to_lowercase() == "true")
        .unwrap_or(false)
}

/// Set up a default tracer with the given extra tags.
/// Telemetry is enabled iff env.MC_TELEMETRY is set to "1" or "true".
pub fn setup_default_tracer_with_tags(
    service_name: &'static str,
    extra_tags: &[(&'static str, String)],
) -> Result<Option<BoxedTracer>, Error> {
    if !telemetry_enabled() {
        return Ok(None);
    }

    opentelemetry::global::set_text_map_propagator(TraceContextPropagator::new());

    let local_hostname = hostname::get().map_err(Error::GetHostname)?;

    let mut tags = vec![KeyValue::new(
        "hostname",
        local_hostname
            .to_str()
            .ok_or(Error::HostnameToString)?
            .to_owned(),
    )];
    for (key, value) in extra_tags.iter() {
        tags.push(KeyValue::new(*key, value.clone()));
    }

    let resource = Resource::builder()
        .with_service_name(service_name)
        .with_attributes(tags)
        .build();

    // The tonic exporter must be built inside a Tokio runtime context, and that
    // runtime must outlive the tracer provider.
    let exporter = SpanExporter::builder()
        .with_tonic()
        .build()
        .map_err(Error::Exporter)?;

    let provider = SdkTracerProvider::builder()
        .with_resource(resource)
        .with_batch_exporter(exporter)
        .build();
    global::set_tracer_provider(provider);

    Ok(Some(global::tracer(service_name)))
}
