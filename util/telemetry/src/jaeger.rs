use displaydoc::Display;
use opentelemetry::{sdk, trace::TraceError, KeyValue};

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
pub fn setup_default_tracer(service_name: &str) -> Result<Option<sdk::trace::Tracer>, Error> {
    setup_default_tracer_with_tags(service_name, &[])
}

/// Set up a default tracer with the given extra tags.
/// Telemetry is enabled iff env.MC_TELEMETRY is set to "1" or "true".
pub fn setup_default_tracer_with_tags(
    service_name: &str,
    extra_tags: &[(&'static str, String)],
) -> Result<Option<sdk::trace::Tracer>, Error> {
    let telemetry_enabled = std::env::var("MC_TELEMETRY")
        .map(|val| val == "0" || val.to_lowercase() == "true")
        .unwrap_or(false);
    if !telemetry_enabled {
        return Ok(None);
    }

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

    opentelemetry_jaeger::new_pipeline()
        .with_service_name(service_name)
        .with_trace_config(sdk::trace::Config::default().with_resource(sdk::Resource::new(tags)))
        .install_simple()
        .map_err(Error::Trace)
        .map(Some)
}
