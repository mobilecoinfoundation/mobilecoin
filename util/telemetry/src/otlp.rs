use displaydoc::Display;
use opentelemetry::{global, global::BoxedTracer, trace::TraceError, KeyValue};
use opentelemetry_sdk::{trace, Resource};

#[derive(Debug, Display)]
pub enum Error {
    /// Trace error: {0}
    Trace(TraceError),

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

/// Set up a default tracer with the given extra tags.
/// Telemetry is enabled iff env.MC_TELEMETRY is set to "1" or "true".
pub fn setup_default_tracer_with_tags(
    service_name: &'static str,
    extra_tags: &[(&'static str, String)],
) -> Result<Option<BoxedTracer>, Error> {
    let telemetry_enabled = std::env::var("MC_TELEMETRY")
        .map(|val| val == "1" || val.to_lowercase() == "true")
        .unwrap_or(false);
    if !telemetry_enabled {
        return Ok(None);
    }

    let local_hostname = hostname::get().map_err(Error::GetHostname)?;

    let mut tags = vec![
        KeyValue::new("service.name", service_name.to_owned()),
        KeyValue::new(
            "hostname",
            local_hostname
                .to_str()
                .ok_or(Error::HostnameToString)?
                .to_owned(),
        ),
    ];
    for (key, value) in extra_tags.iter() {
        tags.push(KeyValue::new(*key, value.clone()));
    }

    let provider = opentelemetry_otlp::new_pipeline()
        .tracing()
        .with_exporter(opentelemetry_otlp::new_exporter().tonic())
        .with_trace_config(trace::Config::default().with_resource(Resource::new(tags)))
        .install_batch(opentelemetry_sdk::runtime::Tokio)
        .map_err(Error::Trace)?;
    global::set_tracer_provider(provider);

    Ok(Some(global::tracer(service_name)))
}
